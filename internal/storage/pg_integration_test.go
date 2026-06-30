//go:build integration

// Package storage - PostgreSQL 持久化单元测试（需真实 PG）。
//
// 环境变量：
//
//	YVONNE_TEST_PG_DSN: PostgreSQL DSN（默认 postgresql://postgres:pass@172.20.0.16:5432/yvonne_test）
//
// 运行：
//
//	go test -tags=integration -race -v -timeout 60s ./internal/storage/
package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// testDSN 返回测试用 DSN。
func testDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv("YVONNE_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgresql://postgres:pass@172.20.0.16:5432/yvonne_test"
	}
	return dsn
}

// newTestStore 创建测试用 PG store（自动建库建表 + 测试后清理）。
func newTestStore(t *testing.T) *PostgresKVStore {
	t.Helper()
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}

	// 清理旧数据（TRUNCATE）。
	if _, err := store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str"); err != nil {
		t.Fatalf("TRUNCATE: %v", err)
	}

	t.Cleanup(func() {
		store.Pool().Close()
	})

	return store
}

// TestPG_PutAndGet 写入 + 读取往返。
func TestPG_PutAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:putget"
	value := []byte("hello postgres")

	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(value, got) {
		t.Fatalf("value = %q, want %q", string(got), string(value))
	}
}

// TestPG_GetNotFound 不存在的 key 返回 ErrNotFound。
func TestPG_GetNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent:key")
	if err != ErrNotFound {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// TestPG_Delete 删除后不可读。
func TestPG_Delete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:delete"
	store.Put(ctx, key, []byte("to-be-deleted"))

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("after delete: error = %v, want ErrNotFound", err)
	}
}

// TestPG_DeleteCryptoShredding Delete 清零 value 后删除。
func TestPG_DeleteCryptoShredding(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:shred"
	value := []byte("sensitive-data")
	store.Put(ctx, key, value)

	// Delete 应清零 value（Crypto-Shredding）。
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// 验证已删除。
	_, err := store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("should be not found after delete: %v", err)
	}
}

// TestPG_PutOverwrite 覆盖写入。
func TestPG_PutOverwrite(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:overwrite:unique:001"
	store.Put(ctx, key, []byte("v1"))
	store.Put(ctx, key, []byte("v2"))

	got, _ := store.Get(ctx, key)
	if string(got) != "v2" {
		t.Fatalf("value = %q, want v2", string(got))
	}
}

// TestPG_PutEmptyValue 空值等价于删除。
func TestPG_PutEmptyValue(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:empty"
	store.Put(ctx, key, []byte("data"))
	store.Put(ctx, key, []byte{}) // 空值 = 删除

	_, err := store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("empty value should delete: %v", err)
	}
}

// TestPG_ScanPrefix 前缀扫描。
func TestPG_ScanPrefix(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// 写入多个 key。
	store.Put(ctx, "key:a:1", []byte("a1"))
	store.Put(ctx, "key:a:2", []byte("a2"))
	store.Put(ctx, "key:b:1", []byte("b1"))

	// 扫描 "key:a:" 前缀。
	results, err := store.ScanPrefix(ctx, "key:a:")
	if err != nil {
		t.Fatalf("ScanPrefix: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if string(results["key:a:1"]) != "a1" {
		t.Fatalf("results[key:a:1] = %q", string(results["key:a:1"]))
	}
	if string(results["key:a:2"]) != "a2" {
		t.Fatalf("results[key:a:2] = %q", string(results["key:a:2"]))
	}
}

// TestPG_ScanPrefixEmpty 空前缀结果。
func TestPG_ScanPrefixEmpty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	results, err := store.ScanPrefix(ctx, "nonexistent:prefix:")
	if err != nil {
		t.Fatalf("ScanPrefix: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// TestPG_WithTxCommit 事务提交。
func TestPG_WithTxCommit(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WithTx(ctx, func(tx KVStore) error {
		return tx.Put(ctx, "test:tx:commit", []byte("committed"))
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	// 事务外应能读到。
	got, err := store.Get(ctx, "test:tx:commit")
	if err != nil {
		t.Fatalf("Get after commit: %v", err)
	}
	if string(got) != "committed" {
		t.Fatalf("value = %q", string(got))
	}
}

// TestPG_WithTxRollback 事务回滚。
func TestPG_WithTxRollback(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WithTx(ctx, func(tx KVStore) error {
		tx.Put(ctx, "test:tx:rollback", []byte("should-not-exist"))
		return fmt.Errorf("intentional rollback")
	})
	if err == nil {
		t.Fatal("should return error")
	}

	// 回滚后不应存在。
	_, err = store.Get(ctx, "test:tx:rollback")
	if err != ErrNotFound {
		t.Fatalf("after rollback: error = %v, want ErrNotFound", err)
	}
}

// TestPG_WithTxGetForUpdate 事务内行级锁。
func TestPG_WithTxGetForUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	store.Put(ctx, "test:lock", []byte("locked-value"))

	err := store.WithTx(ctx, func(tx KVStore) error {
		rl, ok := tx.(RowLocker)
		if !ok {
			return fmt.Errorf("tx does not implement RowLocker")
		}
		val, e := rl.GetForUpdate(ctx, "test:lock")
		if e != nil {
			return e
		}
		if string(val) != "locked-value" {
			return fmt.Errorf("value = %q", string(val))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx GetForUpdate: %v", err)
	}
}

// TestPG_Ping 健康检查。
func TestPG_Ping(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestPG_IsHealthy 初始健康。
func TestPG_IsHealthy(t *testing.T) {
	store := newTestStore(t)
	if !store.IsHealthy() {
		t.Fatal("should be healthy initially")
	}
}

// TestPG_LargeValue 大值读写（64KB）。
func TestPG_LargeValue(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key := "test:large"
	value := make([]byte, 64*1024) // 64KB
	for i := range value {
		value[i] = byte(i % 256)
	}

	if err := store.Put(ctx, key, value); err != nil {
		t.Fatalf("Put large: %v", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get large: %v", err)
	}
	if !bytes.Equal(value, got) {
		t.Fatal("large value mismatch")
	}
}

// TestPG_ConcurrentWrites 并发写入不同 key。
func TestPG_ConcurrentWrites(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			key := fmt.Sprintf("test:conc:%d", idx)
			err := store.Put(ctx, key, []byte(fmt.Sprintf("value-%d", idx)))
			done <- err
		}(i)
	}

	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent write %d: %v", i, err)
		}
	}

	// 验证全部写入成功。
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("test:conc:%d", i)
		got, err := store.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		expected := fmt.Sprintf("value-%d", i)
		if string(got) != expected {
			t.Fatalf("value = %q, want %q", string(got), expected)
		}
	}
}

// TestPG_HealthCheck 健康检查 goroutine。
func TestPG_HealthCheck(t *testing.T) {
	store := newTestStore(t)
	store.StartHealthCheck(100 * time.Millisecond)
	defer store.StopHealthCheck()

	// 等待一次 ping。
	time.Sleep(200 * time.Millisecond)

	if !store.IsHealthy() {
		t.Fatal("should be healthy after ping")
	}
}

// TestPG_AutoCreateDatabase 自动建库（用不同数据库名验证）。
func TestPG_AutoCreateDatabase(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	// 用唯一的数据库名。
	uniqueDB := fmt.Sprintf("yvonne_test_autocreate_%d", time.Now().UnixNano())

	// 构造新 DSN。
	parsed, err := parseDSNForTest(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	newDSN := fmt.Sprintf("postgresql://%s:%s@%s:%d/%s",
		parsed.user, parsed.password, parsed.host, parsed.port, uniqueDB)

	// 创建 store（应自动建库）。
	store, err := NewPostgresKVStore(ctx, newDSN)
	if err != nil {
		t.Fatalf("NewPostgresKVStore with auto-create: %v", err)
	}
	defer store.Pool().Close()

	// 验证可读写。
	store.Put(ctx, "auto-create-test", []byte("ok"))
	got, _ := store.Get(ctx, "auto-create-test")
	if string(got) != "ok" {
		t.Fatal("auto-created database should be usable")
	}

	// 清理：删除测试库。
	cleanupDSN := fmt.Sprintf("postgresql://%s:%s@%s:%d/postgres",
		parsed.user, parsed.password, parsed.host, parsed.port)
	conn, err := pgxConnect(ctx, cleanupDSN)
	if err == nil {
		defer conn.Close(ctx)
		conn.Exec(ctx, fmt.Sprintf(`DROP DATABASE "%s"`, uniqueDB))
	}
}

// dsnParts 是解析后的 DSN 组成部分（测试辅助）。
type dsnParts struct {
	user     string
	password string
	host     string
	port     uint16
}

func parseDSNForTest(dsn string) (*dsnParts, error) {
	parsed, err := pgxParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return &dsnParts{
		user:     parsed.User,
		password: parsed.Password,
		host:     parsed.Host,
		port:     parsed.Port,
	}, nil
}
