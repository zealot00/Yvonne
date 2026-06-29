// Package crypto - 版本化加密优化版（零中间拷贝）。
//
// EncryptVersioned 直接输出 [Version][Nonce][Ciphertext+Tag] 格式，
// 比分别调用 EncryptGCM + EncodeVersionedCiphertext 少 1 次分配 + 1 次拷贝。
//
// 分配对比：
//
//	旧路径：EncryptGCM (2 alloc: Seal + 拼接) + Encode (1 alloc: make) = 3 alloc + 2 copy
//	新路径：EncryptVersioned (1 alloc: make + Seal in-place) = 1 alloc + 0 copy
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"runtime"

	"yvonne/internal/memguard"
)

// SafeUint32 安全转换 int → uint32（防整数溢出，gosec G115）。
// 版本号等业务字段均为小正整数，不会溢出，但显式校验防静态扫描告警。
func SafeUint32(v int) uint32 {
	if v < 0 || v > 4294967295 {
		return 0
	}
	return uint32(v)
}

// EncryptVersioned 直接加密并输出自路由密文格式。
//
// 输出格式：[Version (uint32, 4 bytes, BE)] [Nonce (12 bytes)] [Ciphertext + AuthTag]
//
// 优化：单次 make 分配完整缓冲区，gcm.Seal 直接写入尾部，零中间拷贝。
func EncryptVersioned(key *memguard.SecureBuffer, version uint32, plaintext []byte) ([]byte, error) {
	// 1. 生成 Nonce。
	nonce, err := memguard.GenerateSecureRandom(gcmNonceSize)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	var out []byte
	err = key.WithKey(func(secret []byte) error {
		if len(secret) != gcmKeySize {
			return fmt.Errorf("crypto: invalid AES key size %d, want %d", len(secret), gcmKeySize)
		}
		block, e := aes.NewCipher(secret)
		if e != nil {
			return fmt.Errorf("crypto: aes.NewCipher: %w", e)
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return fmt.Errorf("crypto: cipher.NewGCM: %w", e)
		}

		// 2. 一次性分配 [Version][Nonce][Ciphertext+Tag] 完整缓冲区。
		// gcm.Seal 的 overhead 是 Nonce + AuthTag(16 bytes)。
		// 但 gcm.Seal(dst, nonce, plaintext, nil) 返回 dst + ciphertext+tag，
		// 需要把 dst 预设为 [Version][Nonce] 的前缀。
		out = make([]byte, VersionPrefixSize, VersionPrefixSize+gcmNonceSize+len(plaintext)+gcm.Overhead())
		binary.BigEndian.PutUint32(out[:VersionPrefixSize], version)
		out = append(out, nonce...)
		out = gcm.Seal(out, nonce, plaintext, nil)
		return nil
	})

	if err != nil {
		clear(nonce)
		runtime.KeepAlive(nonce)
		return nil, err
	}

	// 清理 nonce（非密钥但保持纪律性清理）。
	clear(nonce)
	runtime.KeepAlive(nonce)

	return out, nil
}

// DecryptVersioned 直接从自路由密文解密。
//
// 输入格式：[Version (uint32, 4 bytes, BE)] [Nonce (12 bytes)] [Ciphertext + AuthTag]
//
// 返回：明文 SecureBuffer + 版本号。
// 优化：直接切片复用输入的 nonce 与 ciphertext，零拷贝。
func DecryptVersioned(key *memguard.SecureBuffer, raw []byte) (*memguard.SecureBuffer, uint32, error) {
	version, nonce, ciphertext, err := DecodeVersionedCiphertext(raw)
	if err != nil {
		return nil, 0, err
	}

	var plaintext *memguard.SecureBuffer
	err = key.WithKey(func(secret []byte) error {
		if len(secret) != gcmKeySize {
			return fmt.Errorf("crypto: invalid AES key size %d, want %d", len(secret), gcmKeySize)
		}
		block, e := aes.NewCipher(secret)
		if e != nil {
			return fmt.Errorf("crypto: aes.NewCipher: %w", e)
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return fmt.Errorf("crypto: cipher.NewGCM: %w", e)
		}

		// gcm.Open 返回全新分配的 plaintext []byte。
		pt, e := gcm.Open(nil, nonce, ciphertext, nil)
		if e != nil {
			return fmt.Errorf("crypto: gcm.Open: %w", e)
		}

		// 防御深度：gcm.Open 成功时 err==nil，pt 可能为 nil（空明文场景）。
		// 仅当 err==nil 且 pt==nil 且预期非空时才报错（此处无法判断预期，跳过）。
		// Crypto-3 的核心防御是 gcm.Open 失败时不使用 pt，已由上面的 err 检查覆盖。

		// 立即装入 SecureBuffer + clear 原 []byte。
		plaintext = memguard.NewSecureBuffer(pt)
		clear(pt)
		runtime.KeepAlive(pt)
		return nil
	})

	if err != nil {
		return nil, 0, err
	}

	return plaintext, version, nil
}
