//go:build gmsm

// SM2 X.509 证书签发（gmsm 构建标签，用 tjfoc/gmsm/x509）。
package crypto

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// issueSM2Certificate 用 tjfoc/gmsm/x509 签发 SM2 证书。
func issueSM2Certificate(req CertRequest, caCert *x509.Certificate, caSigner stdcrypto.Signer) (*CertResult, error) {
	// 提取 SM2 公钥。
	sm2Pub, ok := req.PublicKey.(*sm2.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto: SM2 cert requires *sm2.PublicKey, got %T", req.PublicKey)
	}

	// 从 SecureSigner 提取 SM2 私钥。
	// caSigner 是 *SecureSigner，但其 Sign 方法签名匹配 stdcrypto.Signer。
	// 直接用类型断言获取内部 SM2 私钥。
	secureSigner, ok := caSigner.(*SecureSigner)
	if !ok {
		// 如果不是 SecureSigner，尝试直接用 signer（外部传入的 crypto.Signer）。
		// 但 SM2 证书签发需要 *sm2.PrivateKey，所以必须从 SecureSigner 提取。
		return nil, errors.New("crypto: SM2 cert requires *SecureSigner to extract SM2 private key")
	}
	sm2Priv, ok := secureSigner.priv.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: SM2 cert signer must hold *sm2.PrivateKey, got %T", secureSigner.priv)
	}

	// 生成随机序列号。
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), SerialBits))
	if err != nil {
		return nil, fmt.Errorf("crypto: SM2 generate serial: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.Add(req.TTL)
	if req.IsCA && req.TTL > MaxRootCATTL {
		notAfter = now.Add(MaxRootCATTL)
	}
	if !req.IsCA && req.TTL > MaxEndCertTTL {
		notAfter = now.Add(MaxEndCertTTL)
	}

	// 确定签名算法：SM2WithSM3（国密合规首选）。
	sigAlg := gmx509.SM2WithSM3

	// 确定 KeyUsage（tjfoc 的 KeyUsage 类型与标准库不同，但底层都是 int）。
	var keyUsage gmx509.KeyUsage
	if req.KeyUsage == 0 {
		keyUsage = gmx509.KeyUsage(defaultKeyUsage(req.CertType, req.IsCA))
	} else {
		keyUsage = gmx509.KeyUsage(req.KeyUsage)
	}
	if req.IsCA {
		keyUsage = gmx509.KeyUsageCertSign | gmx509.KeyUsageCRLSign
	}

	// 构造 tjfoc x509.Certificate 模板。
	template := &gmx509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		SignatureAlgorithm:    sigAlg,
	}
	if req.IsCA {
		template.MaxPathLen = 1
	}

	// 自签根 CA：parent=template；签发终端证书：parent=caCert。
	var parent *gmx509.Certificate
	if caCert == nil && len(req.CACertPEM) == 0 {
		parent = template
	} else {
		// 优先用 CACertPEM（SM2 证书无法被标准库解析）。
		var caPEM []byte
		if len(req.CACertPEM) > 0 {
			caPEM = req.CACertPEM
		} else if len(caCert.Raw) > 0 {
			caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
		}
		if len(caPEM) > 0 {
			parsedParent, err := parseSM2CertPEM(caPEM)
			if err != nil {
				return nil, fmt.Errorf("crypto: parse CA cert for SM2 issue: %w", err)
			}
			parent = parsedParent
			if caCert != nil {
				template.Issuer = caCert.Subject
			}
		} else {
			parent = template
		}
	}

	// 调用 tjfoc CreateCertificateToPem（直接输出 PEM）。
	certPEM, err := gmx509.CreateCertificateToPem(template, parent, sm2Pub, sm2Priv)
	if err != nil {
		return nil, fmt.Errorf("crypto: SM2 create certificate: %w", err)
	}

	// 解析 DER（从 PEM 提取，供 CRL 用）。
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("crypto: SM2 cert PEM decode failed after issue")
	}

	return &CertResult{
		PEM:          certPEM,
		DER:          block.Bytes,
		SerialNumber: serial,
		NotBefore:    now,
		NotAfter:     notAfter,
	}, nil
}

// parseSM2CertPEM 用 tjfoc 解析 SM2 证书 PEM。
func parseSM2CertPEM(pemBytes []byte) (*gmx509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block in SM2 certificate")
	}
	cert, err := gmx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 certificate: %w", err)
	}
	return cert, nil
}
