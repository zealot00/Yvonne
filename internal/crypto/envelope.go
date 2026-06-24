// Package crypto - 信封加密 API。
//
// 企业级 KMS 中业务数据用 DEK（Data Encryption Key）加密，DEK 本身由 Master Key
// 加密后持久化。本文件实现 GenerateDataKey：一次性返回明文 DEK（供业务当次使用）
// 与密文 DEK（需持久化）。
package crypto

import (
	"fmt"

	"yvonne/internal/memguard"
)

// dekSize 是 DEK 字节长度：32 字节 = 256 bit，对应 AES-256。
const dekSize = 32

// GenerateDataKey 生成新的 DEK 并用 masterKey 加密。
//
// 返回值：
//   - plaintextDEK: 32 字节明文 DEK，封装在 SecureBuffer 中。业务方用完必须调用 Wipe()。
//   - encryptedDEK: 密文 DEK（含 Nonce 前缀），需由调用方持久化。
//   - err: 任何失败。失败时 plaintextDEK 必为 nil，确保无明文残留。
//
// 安全契约：
//   - 明文 DEK 仅在 SecureBuffer 内存在；加密时通过 WithKey 闭包临时访问。
//   - 任何失败路径都立即 Wipe 已生成的明文 DEK。
func GenerateDataKey(masterKey *memguard.SecureBuffer) (plaintextDEK *memguard.SecureBuffer, encryptedDEK []byte, err error) {
	if masterKey == nil {
		return nil, nil, errKeyRequired
	}

	// 1. 生成 32 字节随机 DEK，直接封装进 SecureBuffer（零中间拷贝）。
	plaintextDEK, err = memguard.NewSecureBufferFromRandom(dekSize)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}

	// 2. 用 masterKey 加密明文 DEK。失败时确保 plaintextDEK 被 Wipe。
	//    用具名返回值 + defer 做兜底，避免遗漏清理路径。
	defer func() {
		if err != nil && plaintextDEK != nil {
			plaintextDEK.Wipe()
			plaintextDEK = nil
		}
	}()

	encryptedDEK, err = encryptDEK(masterKey, plaintextDEK)
	if err != nil {
		encryptedDEK = nil
		// 显式 Wipe 明文 DEK，防止 return 覆盖具名返回值后 defer 跳过 Wipe。
		plaintextDEK.Wipe()
		plaintextDEK = nil
		return nil, nil, fmt.Errorf("crypto: encrypt DEK: %w", err)
	}

	return plaintextDEK, encryptedDEK, nil
}

// encryptDEK 在 SecureBuffer 闭包内调用 encryptGCM，避免明文 DEK 外泄到普通 []byte 变量。
func encryptDEK(masterKey, dek *memguard.SecureBuffer) ([]byte, error) {
	var ciphertext []byte
	err := dek.WithKey(func(plaintext []byte) error {
		var e error
		ciphertext, e = EncryptGCM(masterKey, plaintext)
		return e
	})
	if err != nil {
		// 失败时 ciphertext 可能含部分数据，清理后返回 nil。
		if ciphertext != nil {
			ciphertext = nil
		}
		return nil, err
	}
	return ciphertext, nil
}
