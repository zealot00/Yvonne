// Package crypto - 证书 serial/issuer 解析辅助（吊销检查用）。
//
// VerifyCert 需要从证书 PEM 提取 SerialNumber + Issuer，
// 用于在 CertManager 中查询吊销状态（元数据检查，无需 CRL 文件）。
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseCertSerialIssuer 解析证书 PEM，提取序列号（十进制字符串）与 Issuer DN。
//
// RSA/ECDSA 证书走标准库；SM2 证书标准库无法解析公钥算法，
// 走 gmsm 路径（parseCertSerialIssuerSM2，//go:build gmsm 时实现）。
func ParseCertSerialIssuer(certPEM []byte) (serial, issuer string, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", "", errors.New("crypto: no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// SM2 证书：标准库不识别 SM2 公钥算法 → 走 gmsm 路径。
		return parseCertSerialIssuerSM2(block.Bytes)
	}
	return cert.SerialNumber.String(), cert.Issuer.String(), nil
}

// parseCertSerialIssuerSM2 由 build tag 分文件实现。
// 无 gmsm 标签时返回错误（见 parse_cert_sm2_stub.go）。
var _ = fmt.Sprintf
