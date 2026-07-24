//go:build gmsm

// SM2 证书 serial/issuer 解析（gmsm 构建标签）。
package crypto

import (
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// parseCertSerialIssuerSM2 用 tjfoc 解析 SM2 证书 DER，提取序列号与 Issuer DN。
func parseCertSerialIssuerSM2(certDER []byte) (serial, issuer string, err error) {
	cert, err := gmx509.ParseCertificate(certDER)
	if err != nil {
		return "", "", err
	}
	return cert.SerialNumber.String(), cert.Issuer.String(), nil
}
