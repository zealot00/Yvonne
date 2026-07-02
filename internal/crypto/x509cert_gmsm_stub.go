//go:build !gmsm

// SM2 证书签发 stub（无 gmsm 标签时返回错误）。
package crypto

import (
	stdcrypto "crypto"
	"crypto/x509"
	"errors"
)

// issueSM2Certificate stub。
func issueSM2Certificate(req CertRequest, caCert *x509.Certificate, caSigner stdcrypto.Signer) (*CertResult, error) {
	return nil, errors.New("crypto: SM2 certificate requires -tags gmsm")
}
