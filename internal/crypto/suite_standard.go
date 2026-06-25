// Package crypto - 标准密码套件（AES-256-GCM + SHA-256）。
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"

	"yvonne/internal/memguard"
)

// StandardCipher 是 AES-256-GCM 对称加密实现。
type StandardCipher struct{}

// NewStandardCipher 创建标准 Cipher。
func NewStandardCipher() Cipher { return StandardCipher{} }

func (StandardCipher) Encrypt(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error) {
	return EncryptGCM(key, plaintext)
}

func (StandardCipher) Decrypt(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error) {
	return DecryptGCM(key, ciphertext)
}

func (StandardCipher) KeySize() int { return 32 }
func (StandardCipher) Name() string { return "aes-256-gcm" }

// StandardHash 是 SHA-256 哈希实现。
type StandardHash struct{}

// NewStandardHash 创建标准 Hash。
func NewStandardHash() Hash { return StandardHash{} }

func (StandardHash) Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (StandardHash) Size() int    { return 32 }
func (StandardHash) Name() string { return "sha-256" }

func (StandardHash) HMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// StandardSuite 是标准密码套件（AES-256-GCM + SHA-256）。
type StandardSuite struct{}

// NewStandardSuite 创建标准套件。
func NewStandardSuite() CryptoSuite { return StandardSuite{} }

func (StandardSuite) Cipher() Cipher { return StandardCipher{} }
func (StandardSuite) Hash() Hash     { return StandardHash{} }
func (StandardSuite) Name() string   { return string(SuiteStandard) }
