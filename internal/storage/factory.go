// Package storage - Backend 工厂：根据 config 返回对应实现。
package storage

import (
	"context"
	"fmt"

	"yvonne/internal/config"
)

// New 根据 cfg.Storage.Backend 创建对应 Backend。
func New(ctx context.Context, cfg config.StorageConfig) (Backend, error) {
	switch cfg.Backend {
	case "boltdb":
		return NewBoltBackend(cfg.Path, "yvonne")
	case "postgres":
		return NewPostgresBackend(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("storage: unsupported backend %q", cfg.Backend)
	}
}
