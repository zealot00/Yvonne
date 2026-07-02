// Package crypto - CRL 吊销列表签发与解析。
//
// CRL（Certificate Revocation List）用于记录被吊销的证书序列号。
// 当证书被吊销时，CA 签发新的 CRL，验证方检查 CRL 判断证书是否有效。
//
// 安全红线：
//   - CRL 由 CA 私钥签名，篡改即验签失败
//   - CRL 有 nextUpdate 时间，过期后应重新获取
//   - 吊销列表覆盖存储（每次吊销重新签发完整 CRL）
package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	stdcrypto "crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RevokedCert 是被吊销的证书记录。
type RevokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	Reason       int // CRL reason code (0=unspecified, 1=keyCompromise, ...)
}

// CreateCRL 签发 CRL（RSA/ECDSA 路径）。
//
// 参数：
//   - caCert: CA 证书（标准库 *x509.Certificate）
//   - caSigner: CA 的 crypto.Signer
//   - revoked: 被吊销的证书列表
//
// 返回 CRL DER。
func CreateCRL(caCert *x509.Certificate, caSigner stdcrypto.Signer, revoked []RevokedCert) ([]byte, error) {
	if caCert == nil {
		return nil, errors.New("crypto: CA certificate is required for CRL")
	}
	if caSigner == nil {
		return nil, errors.New("crypto: CA signer is required for CRL")
	}

	// 构造 pkix.RevokedCertificate 列表。
	var revokedCerts []pkix.RevokedCertificate
	for _, rc := range revoked {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
		})
	}

	now := time.Now().UTC()
	nextUpdate := now.Add(24 * time.Hour) // CRL 有效期 24 小时

	template := &x509.RevocationList{
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedCerts,
	}

	// 标准库签发 CRL（返回 DER []byte）。
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caSigner)
	if err != nil {
		return nil, fmt.Errorf("crypto: create CRL: %w", err)
	}
	return crlDER, nil
}

// ParseCRL 解析 CRL DER。
func ParseCRL(crlDER []byte) (*x509.RevocationList, error) {
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CRL: %w", err)
	}
	return crl, nil
}

// IsRevoked 检查序列号是否在 CRL 中被吊销。
func IsRevoked(crl *x509.RevocationList, serial *big.Int) bool {
	if crl == nil || serial == nil {
		return false
	}
	for _, rc := range crl.RevokedCertificates {
		if rc.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// CRLToPEM 将 CRL DER 编码为 PEM。
func CRLToPEM(crlDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
}
