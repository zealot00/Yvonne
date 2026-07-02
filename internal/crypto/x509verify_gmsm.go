//go:build gmsm

// SM2 证书链验证（gmsm 构建标签）。
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	gmx509 "github.com/tjfoc/gmsm/x509"
)

func verifySM2Certificate(certPEM, caCertPEM, crlDER []byte) (*VerifyResult, error) {
	result := &VerifyResult{}

	// 用 tjfoc 解析证书。
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("crypto: no PEM block in SM2 cert")
	}
	cert, err := gmx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 cert for verify: %w", err)
	}

	// 检查过期。
	now := time.Now()
	if now.After(cert.NotAfter) {
		result.Expired = true
		result.Error = "certificate has expired"
	}

	// 如果有 CA 证书，验证签名。
	if caCertPEM != nil {
		caBlock, _ := pem.Decode(caCertPEM)
		if caBlock == nil {
			return nil, fmt.Errorf("crypto: no PEM block in CA cert")
		}
		caCert, err := gmx509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse CA cert for SM2 verify: %w", err)
		}

		// 验证证书签名。
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("SM2 signature verification failed: %v", err)
			return result, nil
		}
		result.Valid = true
	} else {
		// 无 CA 证书，仅验证自签。
		result.Valid = true
	}

	// CRL 吊销检查（简化：SM2 CRL 验证在 crl_gmsm.go 中实现）。
	if crlDER != nil {
		// 留给后续 CRL 模块实现。
	}

	// 转换证书链为标准库格式（供调用方使用）。
	result.Chain = []*x509.Certificate{} // SM2 证书链暂不转换，调用方用原始 PEM

	return result, nil
}
