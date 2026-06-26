//go:build integration

// 索引性能基准测试：对比有索引 vs 无索引的查询性能。
//
// 运行：
//
//	YVONNE_TEST_PG_DSN="postgresql://postgres:pass@172.20.0.16:5432/yvonne_bench" \
//	go test -tags=integration -bench BenchmarkIndex -benchmem -run=^$ -timeout 300s ./internal/storage/
package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// seedBenchmarkData 批量写入 N 条数据用于基准测试。
// 用批量 INSERT 而非逐条 Put（5000 条 Put 需 5000 次网络往返，太慢）。
func seedBenchmarkData(t testing.TB, store *PostgresKVStore, n int, prefix string) {
	t.Helper()
	ctx := context.Background()

	// 批量 INSERT，每批 500 条。
	batchSize := 500
	for start := 0; start < n; start += batchSize {
		end := start + batchSize
		if end > n {
			end = n
		}

		// 构造多值 INSERT（NOW() 直接写入 SQL，不用参数占位）。
		args := make([]interface{}, 0, batchSize*2)
		placeholder := make([]string, 0, batchSize)
		for i := start; i < end; i++ {
			key := fmt.Sprintf("%s:%06d", prefix, i)
			val := []byte(fmt.Sprintf("value-%d", i))
			paramIdx := (i - start) * 2
			placeholder = append(placeholder, fmt.Sprintf("($%d, $%d, NOW())", paramIdx+1, paramIdx+2))
			args = append(args, key, val)
		}

		query := fmt.Sprintf("INSERT INTO yvonne_kv_str (k, v, updated_at) VALUES %s ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = NOW()",
			strings.Join(placeholder, ", "))
		if _, err := store.Pool().Exec(ctx, query, args...); err != nil {
			t.Fatalf("batch insert (start=%d): %v", start, err)
		}
	}
}

// dropBenchmarkIndexes 删除索引（用于无索引对比）。
func dropBenchmarkIndexes(t testing.TB, store *PostgresKVStore) {
	t.Helper()
	ctx := context.Background()
	store.Pool().Exec(ctx, "DROP INDEX IF EXISTS idx_yvonne_kv_str_k_prefix")
	store.Pool().Exec(ctx, "DROP INDEX IF EXISTS idx_yvonne_kv_str_updated_at")
}

// recreateBenchmarkIndexes 重建索引。
func recreateBenchmarkIndexes(t testing.TB, store *PostgresKVStore) {
	t.Helper()
	ctx := context.Background()
	store.Pool().Exec(ctx, "CREATE INDEX IF NOT EXISTS idx_yvonne_kv_str_k_prefix ON yvonne_kv_str (k varchar_pattern_ops)")
	store.Pool().Exec(ctx, "CREATE INDEX IF NOT EXISTS idx_yvonne_kv_str_updated_at ON yvonne_kv_str (updated_at)")
}

// clearBenchmarkTable 清空表。
func clearBenchmarkTable(t testing.TB, store *PostgresKVStore) {
	t.Helper()
	store.Pool().Exec(context.Background(), "TRUNCATE yvonne_kv_str")
}

// --- ScanPrefix 基准（索引 vs 无索引） ---

// BenchmarkIndex_ScanPrefix_WithIndex_100 100 条数据 + 索引。
func BenchmarkIndex_ScanPrefix_WithIndex_100(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 100, "bench:scan")
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan:")
	}
}

// BenchmarkIndex_ScanPrefix_NoIndex_100 100 条数据 + 无索引。
func BenchmarkIndex_ScanPrefix_NoIndex_100(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 100, "bench:scan")
	dropBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan:")
	}
}

// BenchmarkIndex_ScanPrefix_WithIndex_1000 1000 条 + 索引。
func BenchmarkIndex_ScanPrefix_WithIndex_1000(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 1000, "bench:scan1k")
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan1k:")
	}
}

// BenchmarkIndex_ScanPrefix_NoIndex_1000 1000 条 + 无索引。
func BenchmarkIndex_ScanPrefix_NoIndex_1000(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 1000, "bench:scan1k")
	dropBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan1k:")
	}
}

// BenchmarkIndex_ScanPrefix_WithIndex_5000 5000 条 + 索引。
func BenchmarkIndex_ScanPrefix_WithIndex_5000(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 5000, "bench:scan5k")
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan5k:")
	}
}

// BenchmarkIndex_ScanPrefix_NoIndex_5000 5000 条 + 无索引。
func BenchmarkIndex_ScanPrefix_NoIndex_5000(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 5000, "bench:scan5k")
	dropBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.ScanPrefix(ctx, "bench:scan5k:")
	}
}

// --- Get 基准（主键索引，无对比需要） ---

// BenchmarkIndex_Get_WithIndex 1000 条数据 + 主键查询。
func BenchmarkIndex_Get_WithIndex(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, 1000, "bench:get")
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:get:%06d", i%1000)
		store.Get(ctx, key)
	}
}

// --- Put 基准（有索引 vs 无索引） ---

// BenchmarkIndex_Put_WithIndex Put + 索引。
func BenchmarkIndex_Put_WithIndex(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:put:idx:%06d", i)
		store.Put(ctx, key, []byte("value"))
	}
}

// BenchmarkIndex_Put_NoIndex Put + 无索引（仅主键）。
func BenchmarkIndex_Put_NoIndex(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	dropBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:put:noidx:%06d", i)
		store.Put(ctx, key, []byte("value"))
	}
}

// --- Delete 基准 ---

// BenchmarkIndex_Delete_WithIndex Delete + 索引。
func BenchmarkIndex_Delete_WithIndex(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	// 预写入 b.N 条。
	seedBenchmarkData(b, store, b.N, "bench:del:idx")
	recreateBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:del:idx:%06d", i)
		store.Delete(ctx, key)
	}
}

// BenchmarkIndex_Delete_NoIndex Delete + 无索引。
func BenchmarkIndex_Delete_NoIndex(b *testing.B) {
	store := newBenchStore(b)
	defer store.Pool().Close()

	clearBenchmarkTable(b, store)
	seedBenchmarkData(b, store, b.N, "bench:del:noidx")
	dropBenchmarkIndexes(b, store)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench:del:noidx:%06d", i)
		store.Delete(ctx, key)
	}
}

// newBenchStore 创建基准测试 store。
func newBenchStore(b testing.TB) *PostgresKVStore {
	b.Helper()
	dsn := testDSN(b)
	store, err := NewPostgresKVStore(context.Background(), dsn)
	if err != nil {
		b.Fatal(err)
	}
	return store
}
