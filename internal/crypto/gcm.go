// Package crypto 实现 Yvonne KMS 的核心加解密引擎。
//
// 红线：
//   - 仅使用 crypto/aes + crypto/cipher；GCM 是唯一允许的对称加密模式。
//   - 所有明文密钥/数据在内存中流转时必须以 *memguard.SecureBuffer 形式存在，
//     绝不直接传递明文 []byte。
//   - 任何临时存放明文的变量，必须 defer clear+KeepAlive 强制清理。
//   - Nonce 由 memguard.GenerateSecureRandom (CSPRNG) 生成，固定 12 字节。
//
// 输出格式约定（encryptGCM）：
//
//	[12 bytes Nonce][Ciphertext + 16 bytes AuthTag]
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"runtime"

	"yvonne/internal/memguard"
)

// gcmNonceSize 是 AES-GCM 标准 Nonce 长度（12 字节）。
const gcmNonceSize = 12

// gcmKeySize 是 AES-256 密钥长度（32 字节）。
const gcmKeySize = 32

// encryptGCM 用 AES-256-GCM 加密 plaintext。
//
// key 必须是 32 字节（AES-256）。Nonce 由 CSPRNG 生成并附加在密文头部。
// 返回格式：[12 bytes Nonce][Ciphertext + AuthTag]。
//
// 注意：plaintext 由调用方负责生命周期管理（可能是普通 []byte，
// 因为业务数据可能尚未进入 SecureBuffer；但密钥 key 必须是 SecureBuffer）。
func EncryptGCM(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error) {
	// CSPRNG 生成 12 字节 Nonce。Nonce 非密钥材料，但仍走统一熵源。
	nonce, err := memguard.GenerateSecureRandom(gcmNonceSize)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	var ciphertext []byte
	err = key.WithKey(func(secret []byte) error {
		if len(secret) != gcmKeySize {
			return fmt.Errorf("crypto: invalid AES key size %d, want %d", len(secret), gcmKeySize)
		}
		block, err := aes.NewCipher(secret)
		if err != nil {
			return fmt.Errorf("crypto: aes.NewCipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("crypto: cipher.NewGCM: %w", err)
		}
		// Seal: dst=nil, 返回全新分配的 ciphertext（含 AuthTag）。
		// ciphertext 是密文，非明文，不需要 SecureBuffer 包装。
		ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
		return nil
	})
	if err != nil {
		// 失败路径清理 nonce（虽然非敏感，但保持一致性，避免半状态残留）。
		clear(nonce)
		runtime.KeepAlive(nonce)
		return nil, err
	}

	// 拼接 [Nonce][Ciphertext+Tag]。
	out := make([]byte, 0, gcmNonceSize+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	// 清理 nonce（非密钥但保持纪律性清理）。
	clear(nonce)
	runtime.KeepAlive(nonce)
	return out, nil
}

// decryptGCM 用 AES-256-GCM 解密 ciphertext，返回包含明文的 SecureBuffer。
//
// 输入格式：[12 bytes Nonce][Ciphertext + AuthTag]。
// 解密后的明文直接存入新创建的 SecureBuffer，绝不以普通 []byte 形式返回。
// 若 AuthTag 校验失败或任何错误，立刻擦除临时内存并返回错误。
func DecryptGCM(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error) {
	if len(ciphertext) < gcmNonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short (len=%d, need >= %d)", len(ciphertext), gcmNonceSize)
	}
	// 注意：nonce/ct 都是密文形态，切片引用 ciphertext 底层数组，无需单独清理。
	nonce := ciphertext[:gcmNonceSize]
	ct := ciphertext[gcmNonceSize:]

	// plaintext 是明文，必须保证各路径都清理。
	var plaintext []byte
	err := key.WithKey(func(secret []byte) error {
		if len(secret) != gcmKeySize {
			return fmt.Errorf("crypto: invalid AES key size %d, want %d", len(secret), gcmKeySize)
		}
		block, err := aes.NewCipher(secret)
		if err != nil {
			return fmt.Errorf("crypto: aes.NewCipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("crypto: cipher.NewGCM: %w", err)
		}
		// Open: 认证失败时返回 (nil, error)，plaintext 不会被部分写入。
		plaintext, err = gcm.Open(nil, nonce, ct, nil)
		return err
	})
	if err != nil {
		// 失败路径：擦除任何可能的临时明文（gcm.Open 失败时 plaintext==nil，但防御性清理）。
		if plaintext != nil {
			clear(plaintext)
			runtime.KeepAlive(plaintext)
			plaintext = nil
		}
		return nil, fmt.Errorf("crypto: decrypt failed: %w", err)
	}

	// 成功路径：把明文封装进 SecureBuffer。
	// NewSecureBuffer 会拷贝 plaintext 并立即清零入参，保证只有一份明文副本。
	sb := memguard.NewSecureBuffer(plaintext)
	// 防御性：plaintext 已被 NewSecureBuffer 清零，再置 nil 切断引用。
	plaintext = nil
	return sb, nil
}

// errKeyRequired 用于明确区分"密钥为空"的错误。
var errKeyRequired = errors.New("crypto: key SecureBuffer must not be nil")
