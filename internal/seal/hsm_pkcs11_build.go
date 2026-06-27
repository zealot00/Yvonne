//go:build hsm && pkcs11

// Package seal - PKCS#11 后端装配（启用 hsm+pkcs11 tag 时可用）。
package seal

import "fmt"

// BuildHSMBackend 在 hsm+pkcs11 tag 编译时支持 mock 和 pkcs11 两种后端。
func BuildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
	switch cfg.Backend {
	case "mock", "":
		return NewMockHSMBackend()
	case "pkcs11":
		return NewPKCS11Backend(cfg.LibPath, cfg.Slot, cfg.PIN, cfg.KeyID)
	default:
		return nil, fmt.Errorf("seal: unsupported hsm backend %q", cfg.Backend)
	}
}
