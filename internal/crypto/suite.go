// Package crypto - CryptoSuite 密码套件抽象。
//
// 统一标准算法与国密算法（SM2/SM3/SM4），运行时可选。
//   - StandardCipher：AES-256-GCM + SHA-256 + HMAC-SHA256 + ECDSA P-256
//   - GMSMCipher：SM4-GCM + SM3 + HMAC-SM3 + SM2（需 -tags gmsm 编译）
//
// 配置：crypto.suite = "standard"（默认）| "gmsm"
package crypto

import (
	"errors"

	"yvonne/internal/memguard"
)

// Suite 是密码套件标识。
type Suite string

const (
	SuiteStandard Suite = "standard" // AES-256-GCM + SHA-256 + ECDSA P-256
	SuiteGMSM     Suite = "gmsm"     // SM4-GCM + SM3 + SM2（需 -tags gmsm）
)

// Cipher 是对称加密抽象（DEK 加解密）。
// 实现者：StandardCipher（AES-256-GCM）、GMSMCipher（SM4-GCM）
type Cipher interface {
	// Encrypt 加密明文，返回密文。
	Encrypt(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error)

	// Decrypt 解密密文，返回明文 SecureBuffer。
	Decrypt(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error)

	// KeySize 返回密钥长度（字节）：AES-256=32，SM4=16。
	KeySize() int

	// Name 返回算法名："aes-256-gcm" 或 "sm4-gcm"。
	Name() string
}

// Hash 是哈希抽象（审计链 + 签名）。
type Hash interface {
	// Sum 计算数据的哈希。
	Sum(data []byte) []byte

	// Size 返回哈希长度（字节）：SHA-256=32，SM3=32。
	Size() int

	// HMAC 计算 HMAC。
	HMAC(key, data []byte) []byte

	// Name 返回算法名："sha-256" 或 "sm3"。
	Name() string
}

// CryptoSuite 是完整密码套件（Cipher + Hash）。
type CryptoSuite interface {
	Cipher() Cipher
	Hash() Hash
	Name() string // "standard" 或 "gmsm"
}

// NewSuite 根据套件名创建 CryptoSuite。
// "standard" → AES-256-GCM + SHA-256（默认，无 build tag）
// "gmsm" → SM4-GCM + SM3（需 -tags gmsm 编译）
func NewSuite(suite Suite) (CryptoSuite, error) {
	switch suite {
	case SuiteStandard, "":
		return NewStandardSuite(), nil
	case SuiteGMSM:
		return NewGMSMSuite()
	default:
		return nil, errors.New("crypto: unsupported suite " + string(suite))
	}
}
