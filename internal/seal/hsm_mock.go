//go:build hsm

// Package seal - HSM Mock 后端（启用 hsm tag 时可用）。
//
// 编译命令：
//   - go build -tags hsm：启用 MockHSMBackend（测试用，无真实硬件）
//   - go build -tags 'hsm,pkcs11'：启用 PKCS#11（未来）
//   - go build -tags 'hsm,tpm'：启用 TPM 2.0（未来）
package seal

import "fmt"

// buildHSMBackend 在 hsm tag 编译时返回 MockHSMBackend。
// 未来可扩展 PKCS#11/TPM 分支。
func BuildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
	switch cfg.Backend {
	case "mock", "":
		return NewMockHSMBackend()
	// 未来：
	// case "pkcs11":
	//     return NewPKCS11Backend(cfg.LibPath, cfg.Slot, cfg.PIN, cfg.KeyID)
	// case "tpm":
	//     return NewTPMBackend(cfg.KeyID)
	default:
		return nil, fmt.Errorf("seal: unsupported hsm backend %q", cfg.Backend)
	}
}
