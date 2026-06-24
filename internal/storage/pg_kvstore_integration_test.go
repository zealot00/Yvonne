//go:build integration

// PostgreSQL 集成测试（终极蓝图对齐版：KVStore 所有方法带 ctx）。
package storage

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func getTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("YVONNE_PG_DSN")
	if dsn == "" {
		t.Skip("YVONNE_PG_DSN not set; skipping PostgreSQL integration test")
	}
	return dsn
}

func newTestPostgresKVStore(t *testing.T) *PostgresKVStore {
	t.Helper()
	dsn := getTestDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStoreWithConfig(ctx, PostgresPoolConfig{
		DSN:               dsn,
		MaxConns:          4,
		MinConns:          1,
		MaxConnLifetime:   5 * time.Minute,
		MaxConnIdleTime:   1 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPostgresKVStoreWithConfig: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `TRUNCATE yvonne_kv_str`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(ctx, `TRUNCATE yvonne_kv_str`)
		store.Close(ctx)
	})
	return store
}

func TestPG_PutGetDelete(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:crud:001"
	val := []byte("hello-postgres")
	if err := store.Put(ctx, key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(val) {
		t.Fatalf("Get: got %q, want %q", got, val)
	}

	_, err = store.Get(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("Get nonexistent: got %v, want ErrNotFound", err)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

func TestPG_PutOverwrite(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:overwrite"
	if err := store.Put(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := store.Put(ctx, key, []byte("v2")); err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("got %q, want v2", got)
	}
}

func TestPG_WithTx_Commit(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:tx:commit"
	err := store.WithTx(ctx, func(txStore KVStore) error {
		return txStore.Put(ctx, key, []byte("committed"))
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after commit: %v", err)
	}
	if string(got) != "committed" {
		t.Fatalf("got %q, want committed", got)
	}
}

func TestPG_WithTx_Rollback(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:tx:rollback"
	err := store.WithTx(ctx, func(txStore KVStore) error {
		if err := txStore.Put(ctx, key, []byte("should-not-exist")); err != nil {
			return err
		}
		return fmt.Errorf("intentional rollback")
	})
	if err == nil {
		t.Fatal("WithTx should return error")
	}

	_, err = store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("Get after rollback: got %v, want ErrNotFound", err)
	}
}

func TestPG_WithTx_GetForUpdate_RowLock(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:rowlock"
	if err := store.Put(ctx, key, []byte("initial")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	tx1Started := make(chan struct{})
	tx1CanCommit := make(chan struct{})
	tx2Completed := make(chan error, 1)

	go func() {
		_ = store.WithTx(ctx, func(txStore KVStore) error {
			rl, ok := txStore.(RowLocker)
			if !ok {
				return fmt.Errorf("no RowLocker")
			}
			_, err := rl.GetForUpdate(ctx, key)
			if err != nil {
				return err
			}
			close(tx1Started)
			<-tx1CanCommit
			return txStore.Put(ctx, key, []byte("modified-by-tx1"))
		})
	}()

	<-tx1Started

	go func() {
		err := store.WithTx(ctx, func(txStore KVStore) error {
			rl, ok := txStore.(RowLocker)
			if !ok {
				return fmt.Errorf("no RowLocker")
			}
			_, err := rl.GetForUpdate(ctx, key)
			return err
		})
		tx2Completed <- err
	}()

	select {
	case err := <-tx2Completed:
		t.Fatalf("tx2 completed too fast (lock not working?): %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(tx1CanCommit)

	select {
	case err := <-tx2Completed:
		if err != nil {
			t.Fatalf("tx2 failed after tx1 commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tx2 timed out waiting for tx1 to commit")
	}

	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "modified-by-tx1" {
		t.Fatalf("got %q, want modified-by-tx1", got)
	}
}

func TestPG_ConnectionPoolStats(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("test:poolstats:%d", i)
		if err := store.Put(ctx, key, []byte("x")); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	stats := store.Pool().Stat()
	if stats.TotalConns() == 0 {
		t.Fatal("TotalConns = 0")
	}
	if stats.MaxConns() != 4 {
		t.Fatalf("MaxConns = %d, want 4", stats.MaxConns())
	}
}

func TestPG_ConcurrentPutGet(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n*2)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("test:concurrent:w:%d", idx)
			if err := store.Put(ctx, key, []byte(fmt.Sprintf("val-%d", idx))); err != nil {
				errs <- err
			}
		}(i)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("test:concurrent:w:%d", idx)
			_, _ = store.Get(ctx, key)
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent error: %v", err)
		}
	}
}

func TestPG_DeleteCryptoShredding(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	key := "test:shred"
	val := []byte("sensitive-ciphertext")
	if err := store.Put(ctx, key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Get(ctx, key)
	if err != ErrNotFound {
		t.Fatalf("Get after delete: got %v, want ErrNotFound", err)
	}

	var count int
	err = store.pool.QueryRow(ctx,
		`SELECT count(*) FROM yvonne_kv_str WHERE k = $1`, key).Scan(&count)
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Fatalf("row still exists after delete: count=%d", count)
	}
}

func TestPG_LifecycleRotateWithTx(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	keyID := "test:lifecycle:rotate"
	v1Key := fmt.Sprintf("key:%s:v:1", keyID)
	if err := store.Put(ctx, v1Key, []byte(`{"version":1,"state":"Active"}`)); err != nil {
		t.Fatalf("Put v1: %v", err)
	}

	err := store.WithTx(ctx, func(txStore KVStore) error {
		rl, ok := txStore.(RowLocker)
		if !ok {
			return fmt.Errorf("no RowLocker")
		}
		_, err := rl.GetForUpdate(ctx, v1Key)
		if err != nil {
			return err
		}
		if err := txStore.Put(ctx, v1Key, []byte(`{"version":1,"state":"Deactivated"}`)); err != nil {
			return err
		}
		v2Key := fmt.Sprintf("key:%s:v:2", keyID)
		return txStore.Put(ctx, v2Key, []byte(`{"version":2,"state":"Active"}`))
	})
	if err != nil {
		t.Fatalf("Rotate WithTx: %v", err)
	}

	v1Got, err := store.Get(ctx, v1Key)
	if err != nil {
		t.Fatalf("Get v1: %v", err)
	}
	if string(v1Got) != `{"version":1,"state":"Deactivated"}` {
		t.Fatalf("v1 = %q, want Deactivated", v1Got)
	}

	v2Got, err := store.Get(ctx, fmt.Sprintf("key:%s:v:2", keyID))
	if err != nil {
		t.Fatalf("Get v2: %v", err)
	}
	if string(v2Got) != `{"version":2,"state":"Active"}` {
		t.Fatalf("v2 = %q, want Active", v2Got)
	}
}

func TestPG_HealthCheck(t *testing.T) {
	store := newTestPostgresKVStore(t)
	ctx := context.Background()

	var result int
	err := store.pool.QueryRow(ctx, `SELECT 1`).Scan(&result)
	if err != nil {
		t.Fatalf("health check SELECT 1: %v", err)
	}
	if result != 1 {
		t.Fatalf("health check: got %d, want 1", result)
	}
}

var _ = pgx.ErrNoRows
