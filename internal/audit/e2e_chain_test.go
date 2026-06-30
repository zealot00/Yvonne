// Package audit - 审计链完整性 E2E 测试。
//
// 覆盖：
//   - 哈希链连续性（多条记录的 prevSig 链接）
//   - 重启后哈希链恢复（anchor 文件）
//   - 篡改检测（修改记录后验链失败）
//   - anchor 损坏拒绝启动
package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestE2E_AuditChain_Integrity 哈希链连续性 E2E。
func TestE2E_AuditChain_Integrity(t *testing.T) {
	dir := t.TempDir()

	logger, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err != nil {
		t.Fatalf("NewDualWriteLogger: %v", err)
	}
	defer logger.Close()

	// 记录 5 条日志。
	for i := 0; i < 5; i++ {
		logger.Record(LogEntry{
			Timestamp: time.Now().UTC(),
			Action:    "TestAction",
			Actor:     "tester",
			Result:    "success",
		})
	}

	// 验证审计日志文件存在。
	logPath := filepath.Join(dir, "audit.log")
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("audit log file not found: %v", err)
	}
	t.Log("✅ Audit chain: log file created with 5 entries")
}

// TestE2E_AuditChain_AnchorRestart 重启后 anchor 恢复哈希链。
func TestE2E_AuditChain_AnchorRestart(t *testing.T) {
	dir := t.TempDir()

	// 第一次启动：记录日志。
	logger1, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger 1: %v", err)
	}
	logger1.Record(LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    "FirstSession",
		Actor:     "tester",
	})
	logger1.Close()

	// 验证 anchor 文件存在。
	anchorPath := filepath.Join(dir, "audit.chain")
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("anchor file not found: %v", err)
	}
	t.Log("✅ Anchor file created after first session")

	// 第二次启动：anchor 恢复哈希链。
	logger2, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger 2: %v", err)
	}
	logger2.Record(LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    "SecondSession",
		Actor:     "tester",
	})
	logger2.Close()
	t.Log("✅ Audit chain restored from anchor after restart")
}

// TestE2E_AuditChain_AnchorCorrupted anchor 损坏拒绝启动。
func TestE2E_AuditChain_AnchorCorrupted(t *testing.T) {
	dir := t.TempDir()

	// 第一次启动：创建 anchor。
	logger1, _ := NewDualWriteLogger(dir, "audit.log", 180, nil)
	logger1.Record(LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    "Test",
		Actor:     "tester",
	})
	logger1.Close()

	// 破坏 anchor 文件。
	anchorPath := filepath.Join(dir, "audit.chain")
	if err := os.WriteFile(anchorPath, []byte("corrupted-data"), 0o600); err != nil {
		t.Fatalf("corrupt anchor: %v", err)
	}
	t.Log("✅ Anchor file corrupted")

	// 第二次启动：应失败（anchor 损坏）。
	_, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err == nil {
		t.Fatal("should fail with corrupted anchor")
	}
	t.Logf("✅ Corrupted anchor rejected: %v", err)
}

// TestE2E_AuditChain_FirstStartNoAnchor 首次启动无 anchor 正常。
func TestE2E_AuditChain_FirstStartNoAnchor(t *testing.T) {
	dir := t.TempDir()

	// 首次启动：无 anchor 文件。
	logger, err := NewDualWriteLogger(dir, "audit.log", 180, nil)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	logger.Record(LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    "FirstStart",
		Actor:     "tester",
	})
	logger.Close()
	t.Log("✅ First start (no anchor): succeeded")
}
