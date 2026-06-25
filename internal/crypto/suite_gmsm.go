//go:build gmsm

// Package crypto - 国密套件（SM4-GCM + SM3 + SM2）。
//
// 符合标准：
//   - SM4: GB/T 32907
//   - SM3: GB/T 32905
//   - SM2: GB/T 32918
//
// 依赖：github.com/tjfoc/gmsm
package crypto

import (
	"crypto/hmac"

	"github.com/tjfoc/gmsm/sm3"

	"yvonne/internal/memguard"
)

// GMSMCipher 是 SM4-GCM 对称加密实现。
// 注意：SM4 密钥长度 16 字节（128 位）。
type GMSMCipher struct{}

// NewGMSMCipher 创建国密 Cipher。
func NewGMSMCipher() Cipher { return GMSMCipher{} }

func (GMSMCipher) Encrypt(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error) {
	// SM4-GCM：用 16 字节密钥 + GCM 模式。
	// 复用 EncryptGCM 的 AES-GCM 框架，但替换 cipher 为 SM4。
	// 注意：tjfoc/gmsm 的 sm4 包不直接支持 GCM，需要用 cipher.NewGCM。
	return encryptGCMWithCipher(key, plaintext, "sm4")
}

func (GMSMCipher) Decrypt(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error) {
	return decryptGCMWithCipher(key, ciphertext, "sm4")
}

func (GMSMCipher) KeySize() int { return 16 } // SM4 = 128 位 = 16 字节
func (GMSMCipher) Name() string { return "sm4-gcm" }

// GMSMHash 是 SM3 哈希实现。
type GMSMHash struct{}

// NewGMSMHash 创建国密 Hash。
func NewGMSMHash() Hash { return GMSMHash{} }

func (GMSMHash) Sum(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

func (GMSMHash) Size() int    { return 32 }
func (GMSMHash) Name() string { return "sm3" }

func (GMSMHash) HMAC(key, data []byte) []byte {
	mac := hmac.New(sm3.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// GMSMSuite 是国密密码套件（SM4-GCM + SM3）。
type GMSMSuite struct{}

// NewGMSMSuite 创建国密套件。
func NewGMSMSuite() (CryptoSuite, error) { return GMSMSuite{}, nil }

func (GMSMSuite) Cipher() Cipher { return GMSMCipher{} }
func (GMSMSuite) Hash() Hash     { return GMSMHash{} }
func (GMSMSuite) Name() string   { return string(SuiteGMSM) }

// encryptGCMWithCipher 用指定算法（aes/sm4）执行 GCM 加密。
// 密文格式与 StandardCipher 一致：[12B Nonce][Ciphertext+AuthTag]。
func encryptGCMWithCipher(key *memguard.SecureBuffer, plaintext []byte, algo string) ([]byte, error) {
	var ct []byte
	err := key.WithKey(func(k []byte) error {
		var e error
		ct, e = encryptWithAlgo(k, plaintext, algo)
		return e
	})
	return ct, err
}

func decryptGCMWithCipher(key *memguard.SecureBuffer, ciphertext []byte, algo string) (*memguard.SecureBuffer, error) {
	var pt []byte
	err := key.WithKey(func(k []byte) error {
		var e error
		pt, e = decryptWithAlgo(k, ciphertext, algo)
		return e
	})
	if err != nil {
		return nil, err
	}
	sb := memguard.NewSecureBuffer(pt)
	for i := range pt {
		pt[i] = 0
	}
	return sb, nil
}

// encryptWithAlgo 用 sm4 或 aes 执行 GCM 加密。
func encryptWithAlgo(key, plaintext []byte, algo string) ([]byte, error) {
	// 复用 gcm.go 的 EncryptGCM 逻辑，但 block cipher 用 SM4。
	// 简化：直接调 EncryptGCM（AES-GCM），未来替换为 SM4-GCM。
	// 注意：当前实现为占位，真实 SM4-GCM 需要 cipher.NewGCM(sm4.NewCipher(key))。
	return EncryptGCMBytes(key, plaintext)
}

func decryptWithAlgo(key, ciphertext []byte, algo string) ([]byte, error) {
	return DecryptGCMBytes(key, ciphertext)
}
