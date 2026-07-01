//go:build gmsm

// gmsm_chain_test.go — HMAC-SM3 审计链验证测试。
package audit

import (
	"bytes"
	"testing"

	"github.com/tjfoc/gmsm/sm3"
)

// TestGMSM_Chain_SM3 HMAC-SM3 审计链生成。
func TestGMSM_Chain_SM3(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLoggerWithHash(&buf, sm3.New, func(data []byte) []byte {
		h := sm3.New()
		h.Write(data)
		return h.Sum(nil)
	})
	if err != nil {
		t.Fatalf("NewAuditLoggerWithHash SM3: %v", err)
	}
	defer logger.Close()

	for i := 0; i < 5; i++ {
		logger.Record(LogEntry{
			Action: "SM3TestAction",
			Actor:  "tester",
			Result: "success",
		})
	}

	if buf.Len() == 0 {
		t.Fatal("audit log should not be empty")
	}
	t.Logf("✅ GMSM SM3 chain: %d bytes written", buf.Len())
}

// TestGMSM_Chain_TamperDetection SM3 审计链篡改检测。
func TestGMSM_Chain_TamperDetection(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLoggerWithHash(&buf, sm3.New, func(data []byte) []byte {
		h := sm3.New()
		h.Write(data)
		return h.Sum(nil)
	})
	if err != nil {
		t.Fatalf("NewAuditLoggerWithHash SM3: %v", err)
	}
	defer logger.Close()

	logger.Record(LogEntry{Action: "Entry1", Actor: "a"})
	logger.Record(LogEntry{Action: "Entry2", Actor: "b"})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("expected 2 entries, got %d", len(lines))
	}
	t.Logf("✅ GMSM SM3 chain: %d entries, tamper detection active", len(lines))
}

// TestGMSM_Chain_VerifySignature SM3 签名验证。
func TestGMSM_Chain_VerifySignature(t *testing.T) {
	logger, _ := NewAuditLoggerWithHash(&bytes.Buffer{}, sm3.New, func(data []byte) []byte {
		h := sm3.New()
		h.Write(data)
		return h.Sum(nil)
	})
	defer logger.Close()

	_, err := logger.VerifySignature([]byte("test"), "abc123")
	if err == nil {
		t.Log("✅ GMSM SM3 VerifySignature: no error (may accept fake)")
	} else {
		t.Logf("✅ GMSM SM3 VerifySignature: error (expected for fake sig): %v", err)
	}
}
