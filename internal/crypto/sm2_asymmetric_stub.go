//go:build !gmsm

// Package crypto - SM2 非对称密钥 lifecycle 辅助（非 gmsm 构建的 stub）。
//
// 非 gmsm 构建下 SM2 不可用，返回明确错误。
package crypto

import (
	"errors"

	"yvonne/internal/memguard"
)

// errSM2RequiresGmsm 表示 SM2 需要 gmsm 构建标签。
var errSM2RequiresGmsm = errors.New("crypto: sm2 requires -tags gmsm")

// GenerateSM2AsymmetricKey 非 gmsm 构建返回错误。
func GenerateSM2AsymmetricKey() (privKeyPEM *memguard.SecureBuffer, pubKeyPEM []byte, err error) {
	return nil, nil, errSM2RequiresGmsm
}
