//go:build hsm && !pkcs11

// Package seal - HSM Mock 后端（启用 hsm tag 但不含 pkcs11 tag 时可用）。
//
// 编译命令：
//   - go build -tags hsm：启用 MockHSMBackend（测试用，无真实硬件）
//   - go build -tags 'hsm,pkcs11'：启用 PKCS#11（真实 HSM）
package seal

import "fmt"

// buildHSMBackend 在 hsm tag 编译时返回 MockHSMBackend。
func BuildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
	switch cfg.Backend {
	case "mock", "":
		return NewMockHSMBackend()
	default:
		return nil, fmt.Errorf("seal: unsupported hsm backend %q (rebuild with -tags 'hsm,pkcs11' for PKCS#11)", cfg.Backend)
	}
}
