//go:build gmsm

// SM2 CRL 签发（gmsm 构建标签，用 tjfoc/gmsm/x509）。
package crypto

import (
	stdcrypto "crypto"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	gmx509 "github.com/tjfoc/gmsm/x509"
)

// CreateSM2CRL 用 tjfoc/gmsm 签发 SM2 CRL。
//
// caCertPEM: CA 证书 PEM（SM2 格式）
// caSigner: CA 的 crypto.Signer（*SecureSigner 实现 crypto.Signer）
// revoked: 被吊销的证书列表
func CreateSM2CRL(caCertPEM []byte, caSigner stdcrypto.Signer, revoked []RevokedCert) ([]byte, error) {
	// 解析 SM2 CA 证书。
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, errors.New("crypto: no PEM block in SM2 CA cert for CRL")
	}
	caCert, err := gmx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 CA cert for CRL: %w", err)
	}

	// 构造 pkix.RevokedCertificate 列表（tjfoc 用标准库 pkix 类型）。
	var revokedCerts []pkix.RevokedCertificate
	for _, rc := range revoked {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
		})
	}

	now := time.Now().UTC()
	nextUpdate := now.Add(24 * time.Hour)

	// tjfoc CreateCRL 接收 crypto.Signer 接口。
	// SecureSigner 实现了 crypto.Signer，但 tjfoc 内部会用它做 SM2 签名。
	// 需要传入 SecureSigner 本身（它持有 *sm2.PrivateKey）。
	crlDER, err := caCert.CreateCRL(nil, caSigner, revokedCerts, now, nextUpdate)
	if err != nil {
		return nil, fmt.Errorf("crypto: SM2 create CRL: %w", err)
	}

	return crlDER, nil
}
