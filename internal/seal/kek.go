// Package seal - KEK（Key Encryption Key）抽象接口。
//
// 统一软件 CMK 与 HSM backend 两种实现，使主业务路径在三模式下统一工作：
//   - softwareKEK：包装明文 CMK（SecureBuffer），用 AES-256-GCM 加解密 DEK
//   - hsmKEK：包装 CryptoBackend，DEK 加解密下发到 HSM 芯片执行
//
// 安全契约：
//   - WrapDEK 接收明文 DEK（SecureBuffer），返回不透明密文（[]byte）
//   - UnwrapDEK 接收密文，返回明文 DEK（新 SecureBuffer，调用方负责 Wipe）
//   - HSM 模式下 CMK 明文永不进入 Go 进程内存
//   - 软件模式下密文格式 = [12B Nonce][Ciphertext+AuthTag]，与 crypto.EncryptGCM 字节级一致（零迁移）
package seal

import (
	"fmt"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
)

// KEKType 标识 KEK 的实现类型。
type KEKType string

const (
	KEKTypeSoftware KEKType = "software" // Shamir/LocalPKI/Dev：CMK 在 Go 内存（SecureBuffer）
	KEKTypeHSM      KEKType = "hsm"      // HSM：CMK 在芯片内，永不离开
)

// KEK 是保护 DEK 的主密钥抽象。
//
// 实现者：
//   - softwareKEK：等价于 AES-256-GCM(CMK, DEK)，与现有密文格式完全一致
//   - hsmKEK：通过 CryptoBackend.Wrap/Unwrap 下发到 HSM 芯片
type KEK interface {
	// WrapDEK 用 KEK 加密明文 DEK，返回不透明密文。
	WrapDEK(plaintextDEK *memguard.SecureBuffer) (ciphertext []byte, err error)

	// UnwrapDEK 解密 DEK 密文，返回新的 SecureBuffer（调用方负责 Wipe）。
	UnwrapDEK(ciphertext []byte) (plaintextDEK *memguard.SecureBuffer, err error)

	// Type 返回 KEK 类型（software / hsm）。
	Type() KEKType
}

// --- softwareKEK ---

// softwareKEK 包装明文 CMK，用 AES-256-GCM 加解密 DEK。
// 密文格式 = [12B Nonce][Ciphertext+AuthTag]，与 crypto.EncryptGCM 完全一致（向后兼容）。
type softwareKEK struct {
	cmk *memguard.SecureBuffer
}

// NewSoftwareKEK 创建软件 KEK。
func NewSoftwareKEK(cmk *memguard.SecureBuffer) KEK {
	return &softwareKEK{cmk: cmk}
}

func (s *softwareKEK) WrapDEK(plaintextDEK *memguard.SecureBuffer) ([]byte, error) {
	var ct []byte
	err := plaintextDEK.WithKey(func(dek []byte) error {
		var e error
		ct, e = crypto.EncryptGCM(s.cmk, dek)
		return e
	})
	return ct, err
}

func (s *softwareKEK) UnwrapDEK(ciphertext []byte) (*memguard.SecureBuffer, error) {
	return crypto.DecryptGCM(s.cmk, ciphertext)
}

func (s *softwareKEK) Type() KEKType { return KEKTypeSoftware }

// --- hsmKEK ---

// hsmKEK 包装 CryptoBackend，DEK 加解密下发到 HSM 芯片执行。
// CMK 明文永不离开芯片；DEK 明文通过返回值传出但仅短暂存在于 Go 内存。
type hsmKEK struct {
	backend CryptoBackend
}

// NewHSMKEK 创建 HSM KEK。
func NewHSMKEK(backend CryptoBackend) KEK {
	return &hsmKEK{backend: backend}
}

func (h *hsmKEK) WrapDEK(plaintextDEK *memguard.SecureBuffer) ([]byte, error) {
	var ct []byte
	err := plaintextDEK.WithKey(func(dek []byte) error {
		var e error
		ct, e = h.backend.Wrap(dek)
		return e
	})
	return ct, err
}

func (h *hsmKEK) UnwrapDEK(ciphertext []byte) (*memguard.SecureBuffer, error) {
	pt, err := h.backend.Unwrap(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("seal: hsm kek unwrap: %w", err)
	}
	// NewSecureBuffer 拷贝 pt 并清零入参。
	sb := memguard.NewSecureBuffer(pt)
	for i := range pt {
		pt[i] = 0
	}
	return sb, nil
}

func (h *hsmKEK) Type() KEKType { return KEKTypeHSM }
