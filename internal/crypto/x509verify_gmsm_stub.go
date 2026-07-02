//go:build !gmsm

// SM2 证书链验证 stub。
package crypto

import "errors"

func verifySM2Certificate(certPEM, caCertPEM, crlDER []byte) (*VerifyResult, error) {
	return nil, errors.New("crypto: SM2 certificate verification requires -tags gmsm")
}
