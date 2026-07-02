// Package service - PKI 业务层（v1.4.x 新增）。
//
// 在 Core 上扩展 PKI 方法：CreateCA / IssueCert / VerifyCert / RevokeCert / GetCRL。
// 复用 lifecycle.Manager（CA 密钥管理）+ lifecycle.CertManager（证书元数据）+ crypto（签发/验证）。
package service

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"yvonne/internal/auth"
	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/seal"
)

// === 结果类型 ===

type CreateCAResult struct {
	KeyID  string `json:"key_id"`
	CertID string `json:"cert_id"`
	PEM    []byte `json:"pem"`
	Serial string `json:"serial"`
}

type IssueCertResult struct {
	CertID   string    `json:"cert_id"`
	PEM      []byte    `json:"pem"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

type VerifyCertResult struct {
	Valid   bool     `json:"valid"`
	Revoked bool     `json:"revoked"`
	Expired bool     `json:"expired"`
	Chain   []string `json:"chain,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// === PKI 方法 ===

func (c *Core) CreateCA(ctx context.Context, keyID, algo, subject string, ttlYears int, policy *auth.Policy) (*CreateCAResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "CreateCA", keyID); err != nil {
		return nil, err
	}
	if c.certManager == nil {
		return nil, fmt.Errorf("service: PKI not configured")
	}

	// 1. 生成 CA 密钥对。
	var caMeta *lifecycle.KeyMetadata
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		var e error
		caMeta, e = c.manager.CreateAsymmetricKey(ctx, keyID, algo, kek)
		return e
	})
	if err != nil {
		c.recordAudit(ctx, "CreateCA", keyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: create CA key: %w", err)
	}

	// 2. 解密 CA 私钥 → SecureSigner。
	signer, err := c.extractSigner(ctx, caMeta, algo)
	if err != nil {
		c.recordAudit(ctx, "CreateCA", keyID, 0, "error", err.Error())
		return nil, err
	}
	defer signer.Dispose()

	// 3. 解析 CA 公钥。
	pubKey, err := crypto.ParsePublicKey(caMeta.PublicKey, algo)
	if err != nil {
		c.recordAudit(ctx, "CreateCA", keyID, 0, "error", err.Error())
		return nil, err
	}

	// 4. 构造自签根证书请求。
	ttl := time.Duration(ttlYears) * 365 * 24 * time.Hour
	if ttl <= 0 {
		ttl = crypto.DefaultRootTTL
	}
	req := crypto.CertRequest{
		Subject:   pkix.Name{CommonName: subject},
		PublicKey: pubKey,
		KeyType:   algo,
		CertType:  crypto.CertTypeCA,
		IsCA:      true,
		TTL:       ttl,
	}

	// 5. 自签根证书。
	certResult, err := crypto.IssueCertificate(req, nil, signer)
	if err != nil {
		c.recordAudit(ctx, "CreateCA", keyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: issue CA cert: %w", err)
	}

	// 6. 存储证书元数据。
	certID := fmt.Sprintf("ca-%s-%s", keyID, certResult.SerialNumber.Text(16))
	certMeta := &lifecycle.CertMetadata{
		CertID:       certID,
		CAKeyID:      keyID,
		SerialNumber: certResult.SerialNumber.String(),
		Subject:      subject,
		PEM:          certResult.PEM,
		DER:          certResult.DER,
		State:        lifecycle.CertStateActive,
		CertType:     string(crypto.CertTypeCA),
		IssuedAt:     certResult.NotBefore,
		ExpiresAt:    certResult.NotAfter,
	}
	if err := c.certManager.SaveCert(ctx, certMeta); err != nil {
		c.recordAudit(ctx, "CreateCA", keyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: save CA cert metadata: %w", err)
	}

	c.recordAudit(ctx, "CreateCA", keyID, 0, "success", "")
	return &CreateCAResult{
		KeyID:  keyID,
		CertID: certID,
		PEM:    certResult.PEM,
		Serial: certResult.SerialNumber.String(),
	}, nil
}

func (c *Core) IssueCert(ctx context.Context, caKeyID, subject, algo string, publicKeyPEM []byte, certType string, ttlDays int, policy *auth.Policy) (*IssueCertResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "IssueCert", caKeyID); err != nil {
		return nil, err
	}
	if c.certManager == nil {
		return nil, fmt.Errorf("service: PKI not configured")
	}

	caMeta, err := c.manager.GetActiveKey(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, err
	}

	signer, err := c.extractSigner(ctx, caMeta, caMeta.KeyType)
	if err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, err
	}
	defer signer.Dispose()

	pubKey, err := crypto.ParsePublicKey(publicKeyPEM, algo)
	if err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, err
	}

	ttl := time.Duration(ttlDays) * 24 * time.Hour
	if ttl <= 0 {
		ttl = crypto.DefaultCertTTL
	}
	req := crypto.CertRequest{
		Subject:   pkix.Name{CommonName: subject},
		PublicKey: pubKey,
		KeyType:   algo,
		CertType:  crypto.CertType(certType),
		TTL:       ttl,
	}

	caCert, err := c.getCACertificate(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: get CA certificate: %w", err)
	}

	certResult, err := crypto.IssueCertificate(req, caCert, signer)
	if err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: issue cert: %w", err)
	}

	certID := fmt.Sprintf("cert-%s-%s", caKeyID, certResult.SerialNumber.Text(16))
	certMeta := &lifecycle.CertMetadata{
		CertID:       certID,
		CAKeyID:      caKeyID,
		SerialNumber: certResult.SerialNumber.String(),
		Subject:      subject,
		PEM:          certResult.PEM,
		DER:          certResult.DER,
		State:        lifecycle.CertStateActive,
		CertType:     certType,
		IssuedAt:     certResult.NotBefore,
		ExpiresAt:    certResult.NotAfter,
	}
	if err := c.certManager.SaveCert(ctx, certMeta); err != nil {
		c.recordAudit(ctx, "IssueCert", caKeyID, 0, "error", err.Error())
		return nil, fmt.Errorf("service: save cert metadata: %w", err)
	}

	c.recordAudit(ctx, "IssueCert", caKeyID, 0, "success", "")
	return &IssueCertResult{
		CertID:   certID,
		PEM:      certResult.PEM,
		Serial:   certResult.SerialNumber.String(),
		NotAfter: certResult.NotAfter,
	}, nil
}

func (c *Core) VerifyCert(ctx context.Context, certPEM, caCertPEM []byte, policy *auth.Policy) (*VerifyCertResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if c.certManager == nil {
		return nil, fmt.Errorf("service: PKI not configured")
	}

	result, err := crypto.VerifyCertificate(certPEM, caCertPEM, nil)
	if err != nil {
		c.recordAudit(ctx, "VerifyCert", "", 0, "error", err.Error())
		return nil, err
	}

	c.recordAudit(ctx, "VerifyCert", "", 0, "success", "")
	return &VerifyCertResult{
		Valid:   result.Valid,
		Revoked: result.Revoked,
		Expired: result.Expired,
		Error:   result.Error,
	}, nil
}

func (c *Core) RevokeCert(ctx context.Context, caKeyID, certID, reason string, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "RevokeCert", caKeyID); err != nil {
		return err
	}
	if c.certManager == nil {
		return fmt.Errorf("service: PKI not configured")
	}

	if err := c.certManager.RevokeCert(ctx, certID, reason); err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return err
	}

	revokedCerts, err := c.certManager.ListByCA(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return fmt.Errorf("service: list certs for CRL: %w", err)
	}

	var revoked []crypto.RevokedCert
	for _, rc := range revokedCerts {
		if rc.State != lifecycle.CertStateRevoked {
			continue
		}
		serial := new(big.Int)
		_, ok := serial.SetString(rc.SerialNumber, 10)
		if !ok {
			continue
		}
		revoked = append(revoked, crypto.RevokedCert{
			SerialNumber: serial,
			RevokedAt:    rc.RevokedAt,
		})
	}

	caMeta, err := c.manager.GetActiveKey(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return err
	}
	signer, err := c.extractSigner(ctx, caMeta, caMeta.KeyType)
	if err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return err
	}
	defer signer.Dispose()

	caCert, err := c.getCACertificate(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return err
	}

	crlDER, err := crypto.CreateCRL(caCert, signer, revoked)
	if err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return fmt.Errorf("service: create CRL: %w", err)
	}

	if err := c.certManager.SaveCRL(ctx, caKeyID, crlDER); err != nil {
		c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "error", err.Error())
		return err
	}

	c.recordAudit(ctx, "RevokeCert", caKeyID, 0, "success", "")
	return nil
}

func (c *Core) GetCRL(ctx context.Context, caKeyID string, policy *auth.Policy) ([]byte, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if c.certManager == nil {
		return nil, fmt.Errorf("service: PKI not configured")
	}
	crl, err := c.certManager.GetCRL(ctx, caKeyID)
	if err != nil {
		c.recordAudit(ctx, "GetCRL", caKeyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "GetCRL", caKeyID, 0, "success", "")
	return crl, nil
}

func (c *Core) GetCert(ctx context.Context, certID string, policy *auth.Policy) (*lifecycle.CertMetadata, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if c.certManager == nil {
		return nil, fmt.Errorf("service: PKI not configured")
	}
	meta, err := c.certManager.GetCert(ctx, certID)
	if err != nil {
		c.recordAudit(ctx, "GetCert", certID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "GetCert", certID, 0, "success", "")
	return meta, nil
}

// === 内部辅助 ===

func (c *Core) extractSigner(ctx context.Context, meta *lifecycle.KeyMetadata, keyType string) (*crypto.SecureSigner, error) {
	var signer *crypto.SecureSigner
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		privSB, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return fmt.Errorf("service: unwrap key: %w", e)
		}
		defer privSB.Wipe()

		var privBytes []byte
		if err := privSB.WithKey(func(k []byte) error {
			privBytes = make([]byte, len(k))
			copy(privBytes, k)
			return nil
		}); err != nil {
			return err
		}
		defer func() {
			for i := range privBytes {
				privBytes[i] = 0
			}
		}()

		s, e := crypto.NewSecureSigner(privBytes, keyType)
		if e != nil {
			return e
		}
		signer = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func (c *Core) getCACertificate(ctx context.Context, caKeyID string) (*x509.Certificate, error) {
	certs, err := c.certManager.ListByCA(ctx, caKeyID)
	if err != nil {
		return nil, err
	}
	for _, cm := range certs {
		if cm.CertType == string(crypto.CertTypeCA) || cm.CertType == "ca" {
			return crypto.ParseCertificatePEM(cm.PEM)
		}
	}
	return nil, fmt.Errorf("service: CA certificate not found for key %s", caKeyID)
}
