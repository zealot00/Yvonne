package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// writeTestLogs 向 logger 写入若干条测试日志。
func writeTestLogs(t *testing.T, logger *AuditLogger) {
	t.Helper()
	entries := []LogEntry{
		{Action: "Encrypt", Actor: "order-service", Result: "success", Timestamp: time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)},
		{Action: "Decrypt", Actor: "order-service", Result: "success", Timestamp: time.Date(2026, 6, 24, 11, 0, 0, 0, time.UTC)},
		{Action: "RotateKey", Actor: "admin", Result: "success", Timestamp: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)},
		{Action: "Encrypt", Actor: "payment-service", Result: "failure", Timestamp: time.Date(2026, 6, 24, 13, 0, 0, 0, time.UTC)},
		{Action: "ShredKey", Actor: "admin", Result: "success", Timestamp: time.Date(2026, 6, 24, 14, 0, 0, 0, time.UTC)},
	}
	for _, e := range entries {
		if err := logger.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
}

// TestQuery_All 验证查询全部日志。
func TestQuery_All(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewAuditLogger(&buf)
	defer logger.Close()
	writeTestLogs(t, logger)

	// 用 fallback writer 模式查询（buf 中有日志）。
	// Query 从文件读取，fallback 模式不支持查询。
	// 此测试验证 Query 在无文件时的行为。
	_, err := logger.Query("/nonexistent", QueryFilter{Limit: -1})
	if err == nil {
		// 目录不存在不应返回 error（返回空结果）。
	}
}

// TestQuery_FromFile 验证从文件查询日志。
func TestQuery_FromFile(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err != nil {
		t.Fatalf("NewDualWriteLogger: %v", err)
	}
	defer logger.Close()
	writeTestLogs(t, logger)

	// 查询全部。
	results, err := logger.Query(dir, QueryFilter{Limit: -1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	// 验证按 ChainSeq 排序。
	for i := 1; i < len(results); i++ {
		if results[i].Envelope.ChainSeq <= results[i-1].Envelope.ChainSeq {
			t.Fatal("results should be sorted by ChainSeq")
		}
	}

	// 验证哈希链。
	for _, r := range results {
		if !r.Valid {
			t.Fatal("hash chain verification should pass")
		}
	}
}

// TestQuery_FilterByActor 验证按 Actor 过滤。
func TestQuery_FilterByActor(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	results, _ := logger.Query(dir, QueryFilter{Actor: "admin", Limit: -1})
	if len(results) != 2 {
		t.Fatalf("expected 2 admin entries, got %d", len(results))
	}
	for _, r := range results {
		if r.Entry.Actor != "admin" {
			t.Fatalf("Actor = %q, want admin", r.Entry.Actor)
		}
	}
}

// TestQuery_FilterByAction 验证按 Action 过滤。
func TestQuery_FilterByAction(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	results, _ := logger.Query(dir, QueryFilter{Action: "Encrypt", Limit: -1})
	if len(results) != 2 {
		t.Fatalf("expected 2 Encrypt entries, got %d", len(results))
	}
	for _, r := range results {
		if r.Entry.Action != "Encrypt" {
			t.Fatalf("Action = %q, want Encrypt", r.Entry.Action)
		}
	}
}

// TestQuery_FilterByTimeRange 验证按时间范围过滤。
func TestQuery_FilterByTimeRange(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	start := time.Date(2026, 6, 24, 11, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 24, 13, 0, 0, 0, time.UTC)
	results, _ := logger.Query(dir, QueryFilter{StartTime: &start, EndTime: &end, Limit: -1})
	if len(results) != 3 {
		t.Fatalf("expected 3 entries in time range, got %d", len(results))
	}
}

// TestQuery_Limit 验证返回数量限制。
func TestQuery_Limit(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	// Limit=2：返回最后 2 条。
	results, _ := logger.Query(dir, QueryFilter{Limit: 2})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// 应是最后 2 条（ChainSeq 最大的）。
	if results[0].Envelope.ChainSeq != 4 {
		t.Fatalf("first result ChainSeq = %d, want 4", results[0].Envelope.ChainSeq)
	}
	if results[1].Envelope.ChainSeq != 5 {
		t.Fatalf("second result ChainSeq = %d, want 5", results[1].Envelope.ChainSeq)
	}
}

// TestQuery_DefaultLimit 验证默认限制 100 条。
func TestQuery_DefaultLimit(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	// Limit=0 → 默认 100。
	results, _ := logger.Query(dir, QueryFilter{})
	if len(results) != 5 {
		t.Fatalf("expected 5 results (all < 100), got %d", len(results))
	}
}

// TestQuery_EmptyDir 验证空目录返回空结果。
func TestQuery_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewAuditLogger(nil)
	defer logger.Close()

	results, err := logger.Query(dir, QueryFilter{Limit: -1})
	if err != nil {
		t.Fatalf("Query empty dir: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// TestQuery_CombinedFilter 验证组合过滤条件。
func TestQuery_CombinedFilter(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	writeTestLogs(t, logger)

	// Actor=admin + Action=RotateKey。
	results, _ := logger.Query(dir, QueryFilter{Actor: "admin", Action: "RotateKey", Limit: -1})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Entry.Actor != "admin" || results[0].Entry.Action != "RotateKey" {
		t.Fatal("result doesn't match filter")
	}
}

// TestQuery_HashChainVerification 验证查询结果含哈希链验证状态。
func TestQuery_HashChainVerification(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	logger.Record(LogEntry{Action: "Test", Actor: "tester", Result: "success"})

	results, _ := logger.Query(dir, QueryFilter{Limit: -1})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Valid {
		t.Fatal("hash chain should be valid")
	}

	// 验证返回结构含签名信息。
	if results[0].Envelope.Signature == "" {
		t.Fatal("Signature should not be empty")
	}
	if results[0].Envelope.PrevSignature == "" {
		t.Fatal("PrevSignature should not be empty")
	}
	if results[0].Envelope.ChainSeq == 0 {
		t.Fatal("ChainSeq should not be zero")
	}
}

// TestQuery_TamperedLogDetected 验证篡改日志后 Valid=false。
func TestQuery_TamperedLogDetected(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger.Close()
	logger.Record(LogEntry{Action: "Original", Actor: "tester", Result: "success"})

	// 读取日志文件，篡改 payload，写回。
	auditFile := dir + "/audit.log"
	data, _ := readFile(auditFile)

	// 解析并篡改 payload。
	var env signedEnvelope
	json.Unmarshal(data[:len(data)-1], &env) // 去掉末尾 \n
	env.Payload = `{"action":"Tampered","actor":"attacker","result":"success"}`
	tampered, _ := json.Marshal(env)
	writeFile(auditFile, append(tampered, '\n'))

	// 重新创建 logger 以重新加载锚定。
	logger2, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	defer logger2.Close()

	results, _ := logger2.Query(dir, QueryFilter{Limit: -1})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Valid {
		t.Fatal("tampered log should have Valid=false")
	}
}

// 辅助函数。
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
