//go:build !gmsm

// Package lifecycle - SM2 密钥创建 stub（非 gmsm 构建）。
package lifecycle

import (
	"context"
	"errors"

	"yvonne/internal/seal"
)

// errSM2RequiresGmsmBuild 表示 SM2 需要 gmsm 构建标签。
var errSM2RequiresGmsmBuild = errors.New("lifecycle: sm2 requires -tags gmsm")

// createSM2Key 非 gmsm 构建返回错误。
func (m *Manager) createSM2Key(ctx context.Context, keyID string, kek seal.KEK) (*KeyMetadata, error) {
	return nil, errSM2RequiresGmsmBuild
}
