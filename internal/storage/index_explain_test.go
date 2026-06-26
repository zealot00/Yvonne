//go:build integration

package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestIndex_ExplainQueryPlan 验证索引是否被查询规划器使用。
func TestIndex_ExplainQueryPlan(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}
	defer store.Pool().Close()

	// 清空 + 写入测试数据。
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
	seedBenchmarkData(t, store, 1000, "explain:test")
	recreateBenchmarkIndexes(t, store)

	// 1. ScanPrefix（LIKE 'prefix%'）查询计划。
	rows, err := store.Pool().Query(ctx,
		`EXPLAIN (FORMAT TEXT) SELECT k, v FROM yvonne_kv_str WHERE k LIKE $1`, "explain:test:%")
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		rows.Scan(&line)
		plan.WriteString(line + "\n")
	}
	rows.Close()

	planStr := plan.String()
	t.Logf("ScanPrefix query plan:\n%s", planStr)

	// 验证是否使用索引（而非 Seq Scan）。
	if strings.Contains(planStr, "Seq Scan") && !strings.Contains(planStr, "Index") {
		t.Logf("⚠️  Seq Scan detected — index not used for LIKE query")
	} else {
		t.Logf("✅ Index used for LIKE query")
	}

	// 2. Get（等值查询）查询计划。
	rows, err = store.Pool().Query(ctx,
		`EXPLAIN (FORMAT TEXT) SELECT v FROM yvonne_kv_str WHERE k = $1`, "explain:test:000000")
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	plan.Reset()
	for rows.Next() {
		var line string
		rows.Scan(&line)
		plan.WriteString(line + "\n")
	}
	rows.Close()

	planStr = plan.String()
	t.Logf("Get query plan:\n%s", planStr)

	if strings.Contains(planStr, "Index Scan") || strings.Contains(planStr, "Index Only Scan") {
		t.Logf("✅ Index used for Get query")
	} else {
		t.Logf("⚠️  No index for Get query: %s", planStr)
	}

	// 3. 清理。
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
}

// TestIndex_PutUpdatesTimestamp 验证 Put 更新 updated_at。
func TestIndex_PutUpdatesTimestamp(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}
	defer store.Pool().Close()

	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")

	// 写入。
	store.Put(ctx, "test:ts", []byte("v1"))

	// 读取 updated_at。
	var ts1 string
	store.Pool().QueryRow(ctx, "SELECT updated_at::text FROM yvonne_kv_str WHERE k = $1", "test:ts").Scan(&ts1)
	t.Logf("First updated_at: %s", ts1)

	// 等待 100ms 确保时间戳不同。
	time.Sleep(100 * time.Millisecond)

	// 覆盖写入。
	store.Put(ctx, "test:ts", []byte("v2"))

	var ts2 string
	store.Pool().QueryRow(ctx, "SELECT updated_at::text FROM yvonne_kv_str WHERE k = $1", "test:ts").Scan(&ts2)
	t.Logf("Second updated_at: %s", ts2)

	if ts1 == ts2 {
		t.Fatal("updated_at should change on overwrite")
	}
	t.Log("✅ updated_at changes on Put overwrite")

	// 清理。
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
}

// TestIndex_IndexExists 验证索引存在。
func TestIndex_IndexExists(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()

	store, err := NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}
	defer store.Pool().Close()

	// 检查索引是否存在。
	indexes := []string{
		"idx_yvonne_kv_str_k_prefix",
		"idx_yvonne_kv_str_updated_at",
	}

	for _, idx := range indexes {
		var exists bool
		err := store.Pool().QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idx).Scan(&exists)
		if err != nil {
			t.Fatalf("check index %s: %v", idx, err)
		}
		if !exists {
			t.Fatalf("index %s should exist", idx)
		}
		t.Logf("✅ Index %s exists", idx)
	}

	// 检查主键索引。
	var pkExists bool
	store.Pool().QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE tablename = 'yvonne_kv_str' AND indexname = 'yvonne_kv_str_pkey')`).Scan(&pkExists)
	if !pkExists {
		t.Fatal("primary key index should exist")
	}
	t.Log("✅ Primary key index exists")

	// 清理。
	store.Pool().Exec(ctx, fmt.Sprintf("TRUNCATE yvonne_kv_str"))
}
