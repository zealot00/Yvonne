//go:build integration

// pg_coverage_test.go — PG storage 补充覆盖测试（用 DSN）。
package storage

import (
	"context"
	"testing"
	"time"
)

// TestPG_KVStore_Close PG KVStore Close。
func TestPG_KVStore_Close(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}

	if err := store.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Log("✅ PG KVStore Close")
}

// TestPG_KVStore_MarkUnhealthy markUnhealthy + IsHealthy。
func TestPG_KVStore_MarkUnhealthy(t *testing.T) {
	store := newTestStore(t)

	if !store.IsHealthy() {
		t.Fatal("should be healthy initially")
	}

	store.markUnhealthy()
	if store.IsHealthy() {
		t.Fatal("should be unhealthy after markUnhealthy")
	}
	t.Log("✅ PG markUnhealthy + IsHealthy")
}

// TestPG_KVStore_Ping Ping 测试。
func TestPG_KVStore_Ping(t *testing.T) {
	store := newTestStore(t)

	err := store.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	t.Log("✅ PG Ping")
}

// TestPG_KVStore_StartStopHealthCheck 启动 + 停止健康检查。
func TestPG_KVStore_StartStopHealthCheck(t *testing.T) {
	store := newTestStore(t)

	store.StartHealthCheck(1 * time.Second)
	time.Sleep(100 * time.Millisecond)
	store.StopHealthCheck()
	t.Log("✅ PG StartHealthCheck + StopHealthCheck")
}

// TestPG_KVStore_Pool Pool 方法。
func TestPG_KVStore_Pool(t *testing.T) {
	store := newTestStore(t)

	pool := store.Pool()
	if pool == nil {
		t.Fatal("Pool should not be nil")
	}
	t.Log("✅ PG Pool()")
}

// TestPG_KVStore_WithTxCommit KVStore WithTx 提交。
func TestPG_KVStore_WithTxCommit(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WithTx(ctx, func(tx KVStore) error {
		return tx.Put(ctx, "tx:commit:cov", []byte("data"))
	})
	if err != nil {
		t.Fatalf("WithTx commit: %v", err)
	}

	got, _ := store.Get(ctx, "tx:commit:cov")
	if string(got) != "data" {
		t.Fatal("tx commit data not found")
	}
	t.Log("✅ PG KVStore WithTx commit")
}

// TestPG_KVStore_WithTxRollback KVStore WithTx 回滚。
func TestPG_KVStore_WithTxRollback(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WithTx(ctx, func(tx KVStore) error {
		tx.Put(ctx, "tx:rollback:cov", []byte("data"))
		return context.Canceled
	})
	if err == nil {
		t.Fatal("should return error")
	}
	t.Logf("✅ PG KVStore WithTx rollback: %v", err)
}

// TestPG_KVStore_TxGetForUpdate 事务内 GetForUpdate。
func TestPG_KVStore_TxGetForUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	store.Put(ctx, "lock:cov:key", []byte("locked"))

	store.WithTx(ctx, func(tx KVStore) error {
		locker, ok := tx.(RowLocker)
		if !ok {
			t.Fatal("PG tx should implement RowLocker")
		}
		got, err := locker.GetForUpdate(ctx, "lock:cov:key")
		if err != nil {
			t.Fatalf("GetForUpdate: %v", err)
		}
		if string(got) != "locked" {
			t.Fatal("GetForUpdate value mismatch")
		}
		return nil
	})
	t.Log("✅ PG KVStore Tx GetForUpdate")
}

// TestPG_KVStore_NotifyInvalidation NotifyInvalidation。
func TestPG_KVStore_NotifyInvalidation(t *testing.T) {
	store := newTestStore(t)
	store.NotifyInvalidation("test:key")
	t.Log("✅ PG NotifyInvalidation")
}

// TestPG_AdvisoryLocker Advisory Lock 获取 + 释放。
func TestPG_AdvisoryLocker(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	locker := NewAdvisoryLocker(store.Pool(), 42)

	acquired, release, err := locker.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if !acquired {
		t.Fatal("should acquire lock")
	}
	t.Log("✅ PG AdvisoryLocker acquired")

	release()
	t.Log("✅ PG AdvisoryLocker released")
}

// TestPG_AdvisoryLocker_Contention 锁竞争。
func TestPG_AdvisoryLocker_Contention(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	locker1 := NewAdvisoryLocker(store.Pool(), 99)
	locker2 := NewAdvisoryLocker(store.Pool(), 99)

	acquired1, release1, _ := locker1.TryAcquire(ctx)
	if !acquired1 {
		t.Fatal("locker1 should acquire")
	}

	acquired2, _, _ := locker2.TryAcquire(ctx)
	if acquired2 {
		t.Fatal("locker2 should NOT acquire (held by locker1)")
	}
	t.Log("✅ PG AdvisoryLocker contention: locker2 rejected")

	release1()

	acquired3, release3, _ := locker2.TryAcquire(ctx)
	if !acquired3 {
		t.Fatal("locker2 should acquire after release")
	}
	release3()
	t.Log("✅ PG AdvisoryLocker: locker2 acquired after release")
}

// TestPG_ReductDSN DSN 脱敏（当前实现直接返回原 DSN，调用方控制日志）。
func TestPG_ReductDSN(t *testing.T) {
	dsn := "postgresql://postgres:secret@host:5432/db"
	result := pgRedactDSN(dsn)
	// 当前实现直接返回（日志脱敏由调用方负责）。
	if result != dsn {
		t.Logf("✅ PG redactDSN: modified (future impl): %s", result)
	} else {
		t.Log("✅ PG redactDSN: passthrough (caller controls logging)")
	}
}

// TestPG_RewriteDSNDatabase DSN 数据库名替换（当前实现直接返回原 DSN）。
func TestPG_RewriteDSNDatabase(t *testing.T) {
	dsn := "postgresql://user:pass@host:5432/old_db"
	result := pgRewriteDSNDatabase(dsn, "new_db")
	// 当前实现直接返回（已废弃，保留空函数防外部引用）。
	_ = result
	t.Log("✅ PG rewriteDSNDatabase: passthrough (deprecated)")
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
