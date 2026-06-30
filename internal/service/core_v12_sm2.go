//go:build gmsm

// Package service - SM2 签名/验签实现（gmsm 构建标签）。
package service

import (
	"fmt"

	"yvonne/internal/crypto"
)

// signSM2 用 SM2 私钥签名（内部 SM3 摘要）。
// privKeyPEM: PEM 编码的 SM2 私钥。
// data: 原始数据（SM2Sign 内部做 SM3 哈希）。
func signSM2(privKeyPEM []byte, data []byte) ([]byte, error) {
	priv, err := crypto.SM2PrivateKeyFromPEM(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("service: parse SM2 private key: %w", err)
	}

	sig, err := crypto.SM2Sign(priv, data)
	if err != nil {
		return nil, fmt.Errorf("service: SM2 sign: %w", err)
	}
	return sig, nil
}

// verifySM2Key 用 SM2 公钥验签。
// pubKeyPEM: PEM 编码的 SM2 公钥。
// data: 原始数据。
// signature: SM2 签名。
func verifySM2Key(pubKeyPEM []byte, data, signature []byte) (bool, error) {
	pub, err := crypto.SM2PublicKeyFromPEM(pubKeyPEM)
	if err != nil {
		return false, fmt.Errorf("service: parse SM2 public key: %w", err)
	}

	valid, err := crypto.SM2Verify(pub, data, signature)
	if err != nil {
		return false, fmt.Errorf("service: SM2 verify: %w", err)
	}
	return valid, nil
}
