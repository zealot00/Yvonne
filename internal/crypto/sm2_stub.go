//go:build !gmsm

// Package crypto - SM2 stub（默认编译时不可用）。
package crypto

import "errors"

// SM2PublicKey SM2 公钥（stub）。
type SM2PublicKey struct{}

// SM2PrivateKey SM2 私钥（stub）。
type SM2PrivateKey struct{}

// GenerateSM2KeyPair 在默认编译时返回 error。
func GenerateSM2KeyPair() (*SM2PublicKey, *SM2PrivateKey, error) {
	return nil, nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2Encrypt stub。
func SM2Encrypt(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2Decrypt stub。
func SM2Decrypt(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2Sign stub。
func SM2Sign(priv *SM2PrivateKey, msg []byte) ([]byte, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2Verify stub。
func SM2Verify(pub *SM2PublicKey, msg, sig []byte) (bool, error) {
	return false, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2PrivateKeyToPEM stub。
func SM2PrivateKeyToPEM(priv *SM2PrivateKey) ([]byte, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2PrivateKeyFromPEM stub。
func SM2PrivateKeyFromPEM(pemData []byte) (*SM2PrivateKey, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}

// SM2PublicKeyFromPEM stub。
func SM2PublicKeyFromPEM(pemData []byte) (*SM2PublicKey, error) {
	return nil, errors.New("crypto: SM2 not compiled in (rebuild with -tags gmsm)")
}
