//go:build !gmsm

// SM2 SecureSigner stub（无 gmsm 构建标签时返回错误）。
package crypto

import (
	"crypto"
	"errors"
)

// sm2RequiresGmsm 是无 gmsm 标签时返回的错误。
var errSM2SignerRequiresGmsm = errors.New("crypto: SM2 signer requires -tags gmsm")

// newSM2SecureSigner stub：无 gmsm 标签时返回错误。
func newSM2SecureSigner(privPEM []byte) (*SecureSigner, error) {
	return nil, errSM2SignerRequiresGmsm
}

// sm2SignerPublic stub。
func sm2SignerPublic(priv interface{}) crypto.PublicKey { return nil }

// sm2SignerSign stub。
func sm2SignerSign(priv interface{}, digest []byte) ([]byte, error) {
	return nil, errSM2SignerRequiresGmsm
}
