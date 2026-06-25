// Package seal - HSM 硬件安全模块桥接接口。
//
// 设计目标：
//   - "私钥永远不离开物理芯片"——HSM 模式下，CMK 明文从不进入 Go 进程内存。
//   - 所有 DEK 加解密操作通过 CryptoBackend 接口下发给 HSM 处理。
//   - 系统内存 dump / core dump 无法找到顶级主密钥。
//
// 接口层次：
//
//	CryptoBackend（HSM 会话）
//	  ├── Wrap(plaintext) → ciphertext   // DEK 加密
//	  └── Unwrap(ciphertext) → plaintext  // DEK 解密
//
// 实现者：
//   - MockHSMBackend：测试用，内部用随机 AES 密钥模拟芯片内密钥
//   - 未来：PKCS#11Backend、TPMBackend
package seal

// CryptoBackend 是硬件安全模块的桥接接口。
//
// HSM 模式下，所有对业务 DEK 的加解密操作都通过此接口下发，
// CMK 明文永远不离开物理芯片，不进入 Go 进程内存。
//
// 实现者必须保证：
//   - Wrap/Unwrap 在 HSM 内部执行，明文不通过返回值以外的途径泄露
//   - 线程安全（多个 goroutine 可并发调用）
//   - 连接断开时自动重连或返回 error
type CryptoBackend interface {
	// Wrap 用 HSM 内部密钥加密明文（如 DEK）。
	// 返回密文（HSM 特定格式，不透明）。
	Wrap(plaintext []byte) ([]byte, error)

	// Unwrap 用 HSM 内部密钥解密密文，返回明文。
	// 仅在 HSM 内部使用主密钥，明文通过返回值传出但主密钥不离开芯片。
	Unwrap(ciphertext []byte) ([]byte, error)
}

// HSMMode 表示 HSM 是否已启用且可用。
type HSMMode bool

const (
	HSMDisabled HSMMode = false
	HSMEnabled  HSMMode = true
)

// HSMConfig 是 HSM 后端配置（与 build tag 无关，始终可用）。
type HSMConfig struct {
	Backend string // "mock" | "pkcs11"（未来）| "tpm"（未来）
	KeyID   string // HSM 内密钥标识
	LibPath string // PKCS#11 库路径（未来）
	Slot    int    // PKCS#11 slot（未来）
	PIN     string // PKCS#11 PIN（未来）
}
