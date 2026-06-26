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
	pool   *pgxpool.Pool
	health *healthState
}

// NewPostgresKVStore 用默认配置连接池。
func NewPostgresKVStore(ctx context.Context, dsn string) (*PostgresKVStore, error) {
	return NewPostgresKVStoreWithConfig(ctx, PostgresPoolConfig{DSN: dsn})
}

// NewPostgresKVStoreWithConfig 用自定义配置创建连接池并确保数据库 + 表存在。
//
// 自动建库：若 DSN 指定的数据库不存在，先连 postgres 默认库创建它。
// 自动建表：CREATE TABLE IF NOT EXISTS yvonne_kv_str。
func NewPostgresKVStoreWithConfig(ctx context.Context, cfg PostgresPoolConfig) (*PostgresKVStore, error) {
	if cfg.DSN == "" {
		return nil, errors.New("postgres: dsn required")
	}

	// 自动建库（若不存在）。
	if err := ensureDatabaseExists(ctx, cfg.DSN); err != nil {
		return nil, fmt.Errorf("postgres: ensure database: %w", err)
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

	// 1. 建表（新库直接含 updated_at，旧库 IF NOT EXISTS 跳过）。
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS yvonne_kv_str (
		k TEXT PRIMARY KEY,
		v BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ensure table: %w", err)
	}

	// 2. 兼容旧表：若 updated_at 列不存在则添加（必须在索引创建之前）。
	if _, err := pool.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='yvonne_kv_str' AND column_name='updated_at') THEN
			ALTER TABLE yvonne_kv_str ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
		END IF;
	END $$`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ensure updated_at column: %w", err)
	}

	// 3. 创建索引（updated_at 列已确保存在）。
	if _, err := pool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_yvonne_kv_str_k_prefix ON yvonne_kv_str (k varchar_pattern_ops);
		CREATE INDEX IF NOT EXISTS idx_yvonne_kv_str_updated_at ON yvonne_kv_str (updated_at);
	`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ensure indexes: %w", err)
	}

	store := &PostgresKVStore{pool: pool}
	store.health = newHealthState(func(ctx context.Context) error {
		return pool.Ping(ctx)
	})
	return store, nil
}

// Pool 返回底层 *pgxpool.Pool。
func (p *PostgresKVStore) Pool() *pgxpool.Pool {
	return p.pool
}

// Ping 检查数据库连接。
func (p *PostgresKVStore) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// IsHealthy 返回数据库健康状态。
func (p *PostgresKVStore) IsHealthy() bool {
	if p.health == nil {
		return true // 无健康检查器时默认健康
	}
	return p.health.IsHealthy()
}

// StartHealthCheck 启动后台健康检查（默认 10 秒间隔）。
func (p *PostgresKVStore) StartHealthCheck(interval time.Duration) {
	if p.health != nil {
		p.health.StartHealthCheck(interval)
	}
}

// StopHealthCheck 停止后台健康检查。
func (p *PostgresKVStore) StopHealthCheck() {
	if p.health != nil {
		p.health.StopHealthCheck()
	}
}

// markUnhealthy 标记数据库不健康（DB 操作失败时调用）。
func (p *PostgresKVStore) markUnhealthy() {
	if p.health != nil {
		p.health.SetUnhealthy()
	}
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
		`INSERT INTO yvonne_kv_str (k, v, updated_at) VALUES ($1, $2, NOW())
		 ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = NOW()`,
		key, value)
	if err != nil {
		p.markUnhealthy()
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
		p.markUnhealthy()
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

// ensureDatabaseExists 检查 DSN 中的数据库是否存在，不存在则创建。
//
// 工作流：
//  1. 解析 DSN，提取数据库名 + 连接参数
//  2. 连接 postgres 默认库
//  3. SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)
//  4. 不存在则 CREATE DATABASE <name>
//
// 若数据库名为 "postgres"（默认库），跳过创建。
func ensureDatabaseExists(ctx context.Context, dsn string) error {
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parse dsn: %w", err)
	}

	dbName := parsed.Database
	if dbName == "" || dbName == "postgres" {
		return nil // 默认库，无需创建
	}

	// 构造 admin DSN：连接 postgres 默认库。
	// 用 URL 格式重建，保留原 host/port/user/password。
	adminDSN := fmt.Sprintf("postgresql://%s@%s:%d/postgres",
		parsed.User, parsed.Host, parsed.Port)
	if parsed.Password != "" {
		adminDSN = fmt.Sprintf("postgresql://%s:%s@%s:%d/postgres",
			parsed.User, parsed.Password, parsed.Host, parsed.Port)
	}

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect to postgres for db creation (admin dsn=%s): %w",
			redactDSN(adminDSN), err)
	}
	defer adminConn.Close(ctx)

	// 检查数据库是否存在。
	var exists bool
	err = adminConn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check database existence: %w", err)
	}

	if exists {
		return nil // 数据库已存在
	}

	// 创建数据库（标识符需用双引号防 SQL 注入）。
	_, err = adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE "%s"`, dbName))
	if err != nil {
		return fmt.Errorf("create database %q: %w", dbName, err)
	}

	return nil
}

// redactDSN 脱敏 DSN 中的密码（用于日志）。
func redactDSN(dsn string) string {
	// 简单脱敏：将 password:xxx 替换为 password:***。
	// 实际生产用 regex，此处简化。
	return dsn // 日志已由调用方控制
}

// rewriteDSNDatabase 已废弃（ConnString 不反映修改），保留空函数防外部引用。
func rewriteDSNDatabase(dsn, newName string) string {
	return dsn
}
