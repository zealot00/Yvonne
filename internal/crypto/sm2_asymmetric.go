//go:build gmsm

// Package crypto - SM2 非对称密钥 lifecycle 辅助（gmsm 构建标签）。
//
// 提供 SM2 密钥生成 + 私钥 PEM 序列化 + 公钥 PEM，
// 供 lifecycle.Manager.CreateAsymmetricKey 调用。
package crypto

import (
	"fmt"
	"runtime"

	"yvonne/internal/memguard"
)

// GenerateSM2AsymmetricKey 生成 SM2 密钥对，返回：
//   - 私钥 PEM（装入 SecureBuffer，供 KEK 加密存储）
//   - 公钥 PEM（明文存储）
func GenerateSM2AsymmetricKey() (privKeyPEM *memguard.SecureBuffer, pubKeyPEM []byte, err error) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		return nil, nil, err
	}

	// 私钥序列化为 PEM → 装入 SecureBuffer。
	privPEM, err := SM2PrivateKeyToPEM(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: sm2 private key to PEM: %w", err)
	}
	sb := memguard.NewSecureBuffer(privPEM)
	clear(privPEM)
	runtime.KeepAlive(privPEM)

	return sb, pub.PEM, nil
}
