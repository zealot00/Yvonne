// Package crypto - GCM 辅助函数（字节切片版本，供 suite_gmsm 使用）。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptGCMBytes 用 AES-256-GCM 加密（字节切片密钥版本）。
// 密文格式：[12B Nonce][Ciphertext+AuthTag]。
func EncryptGCMBytes(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptGCMBytes 用 AES-256-GCM 解密（字节切片密钥版本）。
func DecryptGCMBytes(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) <= nonceSize {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
