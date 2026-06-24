// Package seal - HSM Unsealer + Mock 实现。
//
// HSMUnsealer 与 Shamir/LocalPKI 的本质区别：
//   - Shamir/LocalPKI：CMK 明文在解封后进入 Go 进程内存（SecureBuffer 保护）
//   - HSM：CMK 明文永远在芯片内，Go 进程只持有 CryptoBackend 会话引用
//
// 安全红线：
//   - HSM 模式下，MasterKeyRef 不传入明文 CMK，而是传入 CryptoBackend 实例
//   - 所有 DEK 加解密通过 CryptoBackend.Wrap/Unwrap 下发
//   - 内存 dump / core dump 无法找到 CMK
package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"yvonne/internal/memguard"
)

// HSMUnsealer 基于 HSM 硬件会话的解封器。
//
// 不持有明文 CMK，仅持有 CryptoBackend 会话引用。
// 所有 DEK 操作通过 backend 下发到 HSM 执行。
type HSMUnsealer struct {
	backend CryptoBackend
	mu      sync.RWMutex
	session bool // HSM 会话是否已建立
}

// NewHSMUnsealer 创建 HSM 解封器。
// backend 实现 CryptoBackend 接口（如 PKCS#11 连接、TPM 会话、MockHSMBackend）。
func NewHSMUnsealer(backend CryptoBackend) *HSMUnsealer {
	return &HSMUnsealer{
		backend: backend,
		session: true,
	}
}

// IsSealed HSM 模式下永远返回 false（会话已建立即视为 Unsealed）。
func (h *HSMUnsealer) IsSealed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return !h.session
}

// IsEmergencySealed 委托给底层 VaultState（HSMUnsealer 自身不处理紧急封印）。
func (h *HSMUnsealer) IsEmergencySealed() bool { return false }

// ProvideShare HSM 模式不使用 Shamir，直接报错。
func (h *HSMUnsealer) ProvideShare(share []byte) (bool, error) {
	return false, errors.New("seal: HSM mode does not use Shamir shares")
}

// MasterKeyRef HSM 模式下不传入明文 CMK。
// 调用方应使用 CryptoBackend 接口而非明文密钥。
// 此方法返回 error，提示调用方使用 HSM 专用路径。
func (h *HSMUnsealer) MasterKeyRef(action func(key *memguard.SecureBuffer) error) error {
	return errors.New("seal: HSM mode does not expose plaintext master key; use CryptoBackend instead")
}

// BackendRef 在闭包内访问 CryptoBackend 实例。
// 这是 HSM 模式下 DEK 加解密的唯一入口。
func (h *HSMUnsealer) BackendRef(action func(backend CryptoBackend) error) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.session {
		return errors.New("seal: HSM session not established")
	}
	return action(h.backend)
}

// Seal 断开 HSM 会话。
func (h *HSMUnsealer) Seal(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.session = false
}

// EmergencySeal 紧急封印：立即断开 HSM 会话。
func (h *HSMUnsealer) EmergencySeal(ctx context.Context) {
	h.Seal(ctx)
}

// State 返回当前状态。
func (h *HSMUnsealer) State() State {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.session {
		return StateUnsealed
	}
	return StateSealed
}

// Threshold HSM 模式不适用。
func (h *HSMUnsealer) Threshold() int { return 0 }

// TotalShares HSM 模式不适用。
func (h *HSMUnsealer) TotalShares() int { return 0 }

// --- MockHSMBackend ---

// MockHSMBackend 用随机 AES-256 密钥模拟 HSM 内部密钥。
//
// 测试用途：
//   - hsmKey 模拟芯片内的顶级主密钥，永不外泄
//   - Wrap/Unwrap 用 AES-256-GCM 加解密
//   - 真实 HSM 实现中这些操作在芯片内执行
type MockHSMBackend struct {
	hsmKey []byte // 模拟芯片内密钥（32 字节 AES-256）
	mu     sync.Mutex
}

// NewMockHSMBackend 创建 Mock HSM 后端，生成随机 32 字节 AES-256 密钥。
// 该密钥模拟芯片内密钥，不应被外部访问。
func NewMockHSMBackend() (*MockHSMBackend, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("seal: mock HSM generate key: %w", err)
	}
	return &MockHSMBackend{hsmKey: key}, nil
}

// Wrap 用模拟 HSM 密钥（AES-256-GCM）加密明文。
func (m *MockHSMBackend) Wrap(plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, err := aes.NewCipher(m.hsmKey)
	if err != nil {
		return nil, fmt.Errorf("seal: mock HSM wrap: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: mock HSM wrap: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("seal: mock HSM wrap nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Unwrap 用模拟 HSM 密钥（AES-256-GCM）解密密文。
func (m *MockHSMBackend) Unwrap(ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	block, err := aes.NewCipher(m.hsmKey)
	if err != nil {
		return nil, fmt.Errorf("seal: mock HSM unwrap: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: mock HSM unwrap: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("seal: mock HSM unwrap: ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: mock HSM unwrap: %w", err)
	}
	return plaintext, nil
}

// Close 模拟断开 HSM 连接（清零模拟密钥）。
func (m *MockHSMBackend) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.hsmKey {
		m.hsmKey[i] = 0
	}
}
