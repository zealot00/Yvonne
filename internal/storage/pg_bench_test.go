//go:build integration

package storage

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkPG_Put 单次写入性能。
func BenchmarkPG_Put(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	// 清理。
	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:put:%d", i)
		if err := store.Put(ctx, key, []byte("benchmark-value-32bytes")); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPG_Get 单次读取性能。
func BenchmarkPG_Get(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")

	ctx := context.Background()
	// 预写入。
	store.Put(ctx, "bench:get", []byte("benchmark-value-32bytes"))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := store.Get(ctx, "bench:get")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPG_PutGetRoundTrip 写入+读取往返。
func BenchmarkPG_PutGetRoundTrip(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:roundtrip:%d", i)
		store.Put(ctx, key, []byte("value"))
		store.Get(ctx, key)
	}
}

// BenchmarkPG_Delete 删除性能。
func BenchmarkPG_Delete(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	ctx := context.Background()
	// 预写入 b.N 条。
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:del:%d", i)
		store.Put(ctx, key, []byte("value"))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:del:%d", i)
		store.Delete(ctx, key)
	}
}

// BenchmarkPG_ScanPrefix 前缀扫描性能。
func BenchmarkPG_ScanPrefix(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	ctx := context.Background()
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")

	// 预写入 100 条。
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("bench:scan:%d", i)
		store.Put(ctx, key, []byte("value"))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan:")
	}
}

// BenchmarkPG_WithTxCommit 事务提交性能。
func BenchmarkPG_WithTxCommit(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.WithTx(ctx, func(tx KVStore) error {
			key := fmt.Sprintf("bench:tx:%d", i)
			return tx.Put(ctx, key, []byte("tx-value"))
		})
	}
}

// BenchmarkPG_ConcurrentPut 并发写入。
func BenchmarkPG_ConcurrentPut(b *testing.B) {
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Pool().Close()

	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench:conc:%d", i)
			store.Put(ctx, key, []byte("value"))
			i++
		}
	})
}
