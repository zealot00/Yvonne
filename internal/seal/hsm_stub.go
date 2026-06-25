//go:build !hsm

// Package seal - HSM stub（默认编译时返回 error，HSM 依赖可插拔）。
package seal

import "errors"

// buildHSMBackend 在默认编译（无 hsm tag）时返回 error。
func BuildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
	return nil, errors.New("seal: HSM support not compiled in (rebuild with -tags hsm)")
}
