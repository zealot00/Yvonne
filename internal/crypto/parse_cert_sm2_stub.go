//go:build !gmsm

// SM2 证书解析 stub（无 gmsm 标签）。
package crypto

import "errors"

// parseCertSerialIssuerSM2 stub：无 gmsm 标签返回错误。
func parseCertSerialIssuerSM2(certDER []byte) (serial, issuer string, err error) {
	return "", "", errors.New("crypto: parse SM2 certificate requires -tags gmsm")
}
