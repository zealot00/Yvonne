//go:build integration

package storage

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// pgxConnect 包装 pgx.Connect（测试辅助）。
func pgxConnect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return pgx.Connect(ctx, dsn)
}

// pgxParseConfig 包装 pgx.ParseConfig（测试辅助）。
func pgxParseConfig(dsn string) (*pgx.ConnConfig, error) {
	return pgx.ParseConfig(dsn)
}
