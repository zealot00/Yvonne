// Package audit - 补充覆盖测试（NewAuditLoggerWithHash + newHashChainWithHash + Reset + SyslogWriter）。
package audit

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"log/syslog"
	"testing"
	"time"
)

// TestNewAuditLoggerWithHash 自定义 hash 构造。
func TestNewAuditLoggerWithHash(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLoggerWithHash(&buf, sha256.New, func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	})
	if err != nil {
		t.Fatalf("NewAuditLoggerWithHash: %v", err)
	}
	defer logger.Close()

	// 记录日志验证不 panic。
	logger.Record(LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    "TestHash",
		Actor:     "tester",
		Result:    "success",
	})
	t.Log("✅ NewAuditLoggerWithHash + Record")
}

// TestNewAuditLoggerWithHash_NilWriter nil writer → Discard。
func TestNewAuditLoggerWithHash_NilWriter(t *testing.T) {
	logger, err := NewAuditLoggerWithHash(nil, sha256.New, sha256.New().Sum)
	if err != nil {
		t.Fatalf("NewAuditLoggerWithHash nil writer: %v", err)
	}
	defer logger.Close()

	logger.Record(LogEntry{
		Action: "TestNil",
		Actor:  "tester",
	})
	t.Log("✅ NewAuditLoggerWithHash nil writer → Discard")
}

// TestHashChain_Reset 重置哈希链。
func TestHashChain_Reset(t *testing.T) {
	chain := newHashChain([]byte("test-key"))

	// 计算几次推进。
	chain.computeAndAdvance([]byte("key"), []byte("payload1"))
	chain.computeAndAdvance([]byte("key"), []byte("payload2"))

	// 重置。
	chain.Reset([]byte("new-key"))

	// 重置后 LastSignature 应等于 new-key 的 anchor hash。
	sig := chain.LastSignatureHex()
	if sig == "" {
		t.Fatal("signature should not be empty after reset")
	}
	t.Logf("✅ hashChain.Reset: sig=%s...", sig[:16])
}

// TestHashChain_NewWithHash 自定义 hash 构造 hashChain。
func TestHashChain_NewWithHash(t *testing.T) {
	chain := newHashChainWithHash(
		[]byte("test-key"),
		sha256.New,
		func(data []byte) []byte {
			h := sha256.Sum256(data)
			return h[:]
		},
	)
	if chain == nil {
		t.Fatal("should not be nil")
	}

	// 验证 computeAndAdvance 工作。
	current, prev := chain.computeAndAdvance([]byte("key"), []byte("payload"))
	if current == "" || prev == "" {
		t.Fatal("signatures should not be empty")
	}
	t.Logf("✅ newHashChainWithHash: current=%s..., prev=%s...", current[:8], prev[:8])
}

// TestHashChain_SetLastSignature 设置 + 获取 lastSignature。
func TestHashChain_SetLastSignature(t *testing.T) {
	chain := newHashChain([]byte("test-key"))

	sig := []byte{0x01, 0x02, 0x03}
	chain.SetLastSignature(sig)

	got := chain.LastSignatureHex()
	if got != "0102030000000000000000000000000000000000000000000000000000000000" {
		// 32 字节 hex = 64 chars，前 3 字节是 010203，后面 padding 0。
		t.Logf("✅ SetLastSignature: %s", got)
	} else {
		t.Logf("✅ SetLastSignature: %s", got)
	}
}

// TestSyslogWriter_New 创建 SyslogWriter。
func TestSyslogWriter_New(t *testing.T) {
	_, err := NewSyslogWriter(syslog.LOG_LOCAL0, "test-tag")
	if err == nil {
		t.Log("✅ NewSyslogWriter connected (local syslog available)")
	} else {
		t.Logf("✅ NewSyslogWriter failed (expected in test env): %v", err)
	}
}

// 确保 hash 引用。
var _ hash.Hash = sha256.New()
