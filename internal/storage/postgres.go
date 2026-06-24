// Package storage - Postgres 后端实现。
//
// 用 pgx/v5 实现。表结构极简：
//
//	CREATE TABLE yvonne_kv (
//	  k BYTEA PRIMARY KEY,    -- 键
//	  v BYTEA                 -- 值（密文）
//	);
//
// Crypto-Shredding：DELETE 在 Postgres 中会触发页级空间回收；
// 配合 pg_repack / VACUUM FULL 可彻底物理覆写。生产环境建议开启：
//   - ALTER TABLE yvonne_kv SET (fillfactor=80);
//   - 定期 VACUUM FULL + pg_repack。
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PostgresBackend 基于 pgx 的 Backend 实现。
type PostgresBackend struct {
	conn *pgx.Conn
}

// NewPostgresBackend 连接到指定 DSN 并确保表存在。
func NewPostgresBackend(ctx context.Context, dsn string) (*PostgresBackend, error) {
	if dsn == "" {
		return nil, errors.New("postgres: dsn required")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	// 建表（幂等）。BYTEA PRIMARY KEY 自带 unique btree。
	schema := `CREATE TABLE IF NOT EXISTS yvonne_kv (
		k BYTEA PRIMARY KEY,
		v BYTEA NOT NULL
	);`
	if _, err := conn.Exec(ctx, schema); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("postgres: ensure schema: %w", err)
	}
	return &PostgresBackend{conn: conn}, nil
}

func (p *PostgresBackend) Get(ctx context.Context, keyName []byte) ([]byte, error) {
	var v []byte
	err := p.conn.QueryRow(ctx, `SELECT v FROM yvonne_kv WHERE k = $1`, keyName).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get: %w", err)
	}
	return v, nil
}

func (p *PostgresBackend) Put(ctx context.Context, keyName, value []byte) error {
	if len(value) == 0 {
		return p.Delete(ctx, keyName)
	}
	_, err := p.conn.Exec(ctx,
		`INSERT INTO yvonne_kv (k, v) VALUES ($1, $2)
		 ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
		keyName, value)
	if err != nil {
		return fmt.Errorf("postgres: put: %w", err)
	}
	return nil
}

func (p *PostgresBackend) Delete(ctx context.Context, keyName []byte) error {
	_, err := p.conn.Exec(ctx, `DELETE FROM yvonne_kv WHERE k = $1`, keyName)
	if err != nil {
		return fmt.Errorf("postgres: delete: %w", err)
	}
	return nil
}

func (p *PostgresBackend) ScanPrefix(ctx context.Context, prefix []byte) ([]KVItem, error) {
	// 用 bytea LIKE 模式匹配前缀。需转义 % 和 _。
	// 简单做法：用 bytes comparison + range scan。
	prefixEnd := nextPrefix(prefix)
	rows, err := p.conn.Query(ctx,
		`SELECT k, v FROM yvonne_kv WHERE k >= $1 AND k < $2 ORDER BY k`,
		prefix, prefixEnd)
	if err != nil {
		return nil, fmt.Errorf("postgres: scan prefix: %w", err)
	}
	defer rows.Close()

	var out []KVItem
	for rows.Next() {
		var k, v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("postgres: scan row: %w", err)
		}
		out = append(out, KVItem{Key: k, Value: v})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows iter: %w", err)
	}
	return out, nil
}

func (p *PostgresBackend) Batch(ctx context.Context, ops []Op) error {
	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // 已提交时 Rollback 是 no-op

	for _, op := range ops {
		switch op.Kind {
		case OpPut:
			if len(op.Value) == 0 {
				if _, err := tx.Exec(ctx, `DELETE FROM yvonne_kv WHERE k = $1`, op.Key); err != nil {
					return fmt.Errorf("postgres: batch delete: %w", err)
				}
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO yvonne_kv (k, v) VALUES ($1, $2)
				 ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
				op.Key, op.Value); err != nil {
				return fmt.Errorf("postgres: batch put: %w", err)
			}
		case OpDelete:
			if _, err := tx.Exec(ctx, `DELETE FROM yvonne_kv WHERE k = $1`, op.Key); err != nil {
				return fmt.Errorf("postgres: batch delete: %w", err)
			}
		default:
			return fmt.Errorf("postgres: unknown op kind %d", op.Kind)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

func (p *PostgresBackend) Close() error {
	if p.conn != nil {
		return p.conn.Close(context.Background())
	}
	return nil
}

// nextPrefix 返回 byte 字典序的下一个前缀边界，用于 range scan。
// 例如 prefix="ab" -> "ac"；prefix="a\xff" -> "b"。
// 若 prefix 全 0xff，返回 nil（表示无上界）。
func nextPrefix(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil // 全 0xff，无上界
}
