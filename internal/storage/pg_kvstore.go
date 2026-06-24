// Package storage - PostgresKVStore：基于 pgxpool 的 KVStore 实现（终极蓝图对齐版）。
//
// 所有方法首参为 ctx，WithTx callback 接收 KVStore 类型。
// 事务内的 pgTx 实现 KVStore + RowLocker（SELECT FOR UPDATE）。
package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresPoolConfig 是 Postgres 连接池配置。
type PostgresPoolConfig struct {
	DSN               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

// PostgresKVStore 是基于 pgxpool 的 KVStore 实现。
type PostgresKVStore struct {
	pool *pgxpool.Pool
}

// NewPostgresKVStore 用默认配置连接池。
func NewPostgresKVStore(ctx context.Context, dsn string) (*PostgresKVStore, error) {
	return NewPostgresKVStoreWithConfig(ctx, PostgresPoolConfig{DSN: dsn})
}

// NewPostgresKVStoreWithConfig 用自定义配置创建连接池并确保表存在。
func NewPostgresKVStoreWithConfig(ctx context.Context, cfg PostgresPoolConfig) (*PostgresKVStore, error) {
	if cfg.DSN == "" {
		return nil, errors.New("postgres: dsn required")
	}

	pcfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}

	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pcfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		pcfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pcfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		pcfg.HealthCheckPeriod = cfg.HealthCheckPeriod
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}

	schema := `CREATE TABLE IF NOT EXISTS yvonne_kv_str (
		k TEXT PRIMARY KEY,
		v BYTEA NOT NULL
	);`
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ensure schema: %w", err)
	}

	return &PostgresKVStore{pool: pool}, nil
}

// Pool 返回底层 *pgxpool.Pool。
func (p *PostgresKVStore) Pool() *pgxpool.Pool {
	return p.pool
}

// Put 写入 key/value。
func (p *PostgresKVStore) Put(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return fmt.Errorf("storage: empty key")
	}
	if len(value) == 0 {
		return p.Delete(ctx, key)
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO yvonne_kv_str (k, v) VALUES ($1, $2)
		 ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
		key, value)
	if err != nil {
		return fmt.Errorf("postgres: put: %w", err)
	}
	return nil
}

// Get 返回 key 对应的值。key 不存在返回 ErrNotFound。
func (p *PostgresKVStore) Get(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := p.pool.QueryRow(ctx,
		`SELECT v FROM yvonne_kv_str WHERE k = $1`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get: %w", err)
	}
	return v, nil
}

// Delete 物理删除 key。
func (p *PostgresKVStore) Delete(ctx context.Context, key string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM yvonne_kv_str WHERE k = $1`, key)
	if err != nil {
		return fmt.Errorf("postgres: delete: %w", err)
	}
	return nil
}

// Close 关闭连接池。
func (p *PostgresKVStore) Close(ctx context.Context) error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

// NotifyInvalidation 实现 lifecycle.Notifier 接口。
func (p *PostgresKVStore) NotifyInvalidation(keyID string) error {
	return NotifyInvalidation(p.pool, keyID)
}

// ScanPrefix 实现 PrefixScanner：SELECT WHERE k LIKE 'prefix%'。
func (p *PostgresKVStore) ScanPrefix(ctx context.Context, prefix string) (map[string][]byte, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT k, v FROM yvonne_kv_str WHERE k LIKE $1`, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("postgres: scan prefix: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]byte)
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("postgres: scan row: %w", err)
		}
		result[k] = v
	}
	return result, rows.Err()
}

// --- KVStore.WithTx 实现 ---

// WithTx 在事务内执行 fn。
func (p *PostgresKVStore) WithTx(ctx context.Context, fn func(txStore KVStore) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pgTx := &pgTx{tx: tx, ctx: ctx}
	if err := fn(pgTx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// pgTx 是 Postgres 事务上下文，实现 KVStore + RowLocker。
type pgTx struct {
	tx  pgx.Tx
	ctx context.Context
}

func (t *pgTx) Put(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return fmt.Errorf("storage: empty key")
	}
	if len(value) == 0 {
		return t.Delete(ctx, key)
	}
	_, err := t.tx.Exec(ctx,
		`INSERT INTO yvonne_kv_str (k, v) VALUES ($1, $2)
		 ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`,
		key, value)
	if err != nil {
		return fmt.Errorf("postgres: tx put: %w", err)
	}
	return nil
}

func (t *pgTx) Get(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := t.tx.QueryRow(ctx,
		`SELECT v FROM yvonne_kv_str WHERE k = $1`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("postgres: tx get: %w", err)
	}
	return v, nil
}

func (t *pgTx) Delete(ctx context.Context, key string) error {
	_, err := t.tx.Exec(ctx,
		`DELETE FROM yvonne_kv_str WHERE k = $1`, key)
	if err != nil {
		return fmt.Errorf("postgres: tx delete: %w", err)
	}
	return nil
}

// WithTx 嵌套事务：直接在当前事务内执行（savepoint 省略，简化）。
func (t *pgTx) WithTx(ctx context.Context, fn func(txStore KVStore) error) error {
	return fn(t)
}

// GetForUpdate 实现 RowLocker：SELECT ... FOR UPDATE 行级锁。
func (t *pgTx) GetForUpdate(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := t.tx.QueryRow(ctx,
		`SELECT v FROM yvonne_kv_str WHERE k = $1 FOR UPDATE`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get for update: %w", err)
	}
	return v, nil
}
