//go:build !gmsm

package crypto

import "errors"

// ParseSM2PublicKey stub。
func ParseSM2PublicKey(pemBytes []byte) (interface{}, error) {
	return nil, errors.New("crypto: SM2 public key requires -tags gmsm")
}

// ParseSM2CACertPEM stub。
func ParseSM2CACertPEM(pemBytes []byte) (interface{}, error) {
	return nil, errors.New("crypto: SM2 certificate requires -tags gmsm")
}

// parseSM2CACert stub。
func parseSM2CACert(pemBytes []byte) (interface{}, error) {
	return nil, errors.New("crypto: SM2 certificate requires -tags gmsm")
}
