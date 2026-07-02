//go:build !gmsm

// SM2 CRL stub。
package crypto

import (
	stdcrypto "crypto"
	"errors"
)

// CreateSM2CRL stub：无 gmsm 标签返回错误。
func CreateSM2CRL(caCertPEM []byte, caSigner stdcrypto.Signer, revoked []RevokedCert) ([]byte, error) {
	return nil, errors.New("crypto: SM2 CRL requires -tags gmsm")
}
