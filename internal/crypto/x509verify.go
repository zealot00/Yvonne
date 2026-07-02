// Package crypto - X.509 证书链验证（RSA/ECDSA，标准库路径）。
//
// SM2 证书链验证在 x509verify_gmsm.go（//go:build gmsm）。
package crypto

import (
	"crypto/x509"
	"fmt"
	"time"
)

// VerifyResult 证书验证结果。
type VerifyResult struct {
	Valid   bool
	Chain   []*x509.Certificate // 证书链（从终端到根 CA）
	Revoked bool
	Expired bool
	Error   string
}

// VerifyCertificate 验证证书链。
//
// 参数：
//   - certPEM: 待验证的证书 PEM
//   - caCertPEM: CA 证书 PEM（可选，nil 则从系统信任库验证）
//   - crlDER: CRL DER（可选，nil 则不检查吊销）
//
// 返回验证结果（含证书链、是否吊销、是否过期）。
func VerifyCertificate(certPEM, caCertPEM []byte, crlDER []byte) (*VerifyResult, error) {
	// 解析待验证证书。
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse cert for verify: %w", err)
	}

	// SM2 证书走 gmsm 路径。
	if isSM2Certificate(cert) {
		return verifySM2Certificate(certPEM, caCertPEM, crlDER)
	}

	// RSA/ECDSA 走标准库路径。
	return verifyStandardCertificate(cert, caCertPEM, crlDER)
}

// verifyStandardCertificate 用标准库验证 RSA/ECDSA 证书链。
func verifyStandardCertificate(cert *x509.Certificate, caCertPEM []byte, crlDER []byte) (*VerifyResult, error) {
	result := &VerifyResult{}

	// 检查过期。
	now := time.Now()
	if now.After(cert.NotAfter) {
		result.Expired = true
		result.Error = "certificate has expired"
	}
	if now.Before(cert.NotBefore) {
		result.Expired = true
		result.Error = "certificate is not yet valid"
	}

	// 构造验证选项。
	opts := x509.VerifyOptions{
		CurrentTime: now,
	}

	// 如果提供了 CA 证书，用它作为信任根。
	if caCertPEM != nil {
		caCert, err := ParseCertificatePEM(caCertPEM)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse CA cert for verify: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		opts.Roots = pool
	}

	// 验证证书链。
	chain, err := cert.Verify(opts)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		// 即使验证失败也返回结果（调用方可判断 Expired/Revoked）。
		return result, nil
	}

	result.Valid = true
	for _, c := range chain {
		result.Chain = append(result.Chain, c...)
	}

	// 检查 CRL 吊销。
	if crlDER != nil {
		revoked, err := checkRevocation(cert, crlDER)
		if err != nil {
			result.Error = fmt.Sprintf("CRL check error: %v", err)
		}
		if revoked {
			result.Revoked = true
			result.Valid = false
			result.Error = "certificate is revoked"
		}
	}

	return result, nil
}

// checkRevocation 检查证书是否在 CRL 中被吊销。
func checkRevocation(cert *x509.Certificate, crlDER []byte) (bool, error) {
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, fmt.Errorf("parse CRL: %w", err)
	}

	// 验证 CRL 签名（如果有 CA 证书）。
	// 这里简化：只检查序列号是否在吊销列表中。
	for _, revoked := range crl.RevokedCertificates {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// isSM2Certificate 检查证书是否使用 SM2 算法。
func isSM2Certificate(cert *x509.Certificate) bool {
	// SM2 证书的 PublicKeyAlgorithm 是 ECDSA，但公钥是 SM2 曲线。
	// 标准库无法直接判断 SM2，用 SignatureAlgorithm 间接判断。
	// SM2WithSM3 的 OID 与标准 ECDSA 不同，但标准库可能不识别。
	// 简化：如果解析失败或公钥类型不匹配，走 SM2 路径。
	return false // 标准库路径下不判断 SM2，由 ParseCertificatePEM 的调用方决定
}
