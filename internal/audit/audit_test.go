package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestAuditLogger_DifferentSignatures 验证两条不同日志的 Signature 不同。
func TestAuditLogger_DifferentSignatures(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLogger(&buf)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer logger.Close()

	ts := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	entry1 := LogEntry{
		TraceID:   "trace-aaa",
		Timestamp: ts,
		Actor:     "approle-1",
		Action:    "Encrypt",
		KeyID:     "key-001",
		Status:    "success",
	}
	entry2 := LogEntry{
		TraceID:   "trace-bbb",
		Timestamp: ts.Add(1 * time.Second),
		Actor:     "approle-1",
		Action:    "Decrypt",
		KeyID:     "key-001",
		Status:    "success",
	}

	if err := logger.Record(entry1); err != nil {
		t.Fatalf("Record entry1: %v", err)
	}
	if err := logger.Record(entry2); err != nil {
		t.Fatalf("Record entry2: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected 2 log lines, got %d", len(lines))
	}

	var env1, env2 signedEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &env1); err != nil {
		t.Fatalf("parse line 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &env2); err != nil {
		t.Fatalf("parse line 2: %v", err)
	}

	if env1.Signature == env2.Signature {
		t.Fatal("two different log entries must have different signatures")
	}
	if env1.Signature == "" || env2.Signature == "" {
		t.Fatal("signature must not be empty")
	}
}

// TestAuditLogger_TamperedPayloadFailsVerification 验证篡改 JSON 后 HMAC 不匹配。
func TestAuditLogger_TamperedPayloadFailsVerification(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLogger(&buf)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer logger.Close()

	entry := LogEntry{
		TraceID:   "trace-tamper",
		Timestamp: time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC),
		Actor:     "approle-1",
		Action:    "Encrypt",
		KeyID:     "key-001",
		Status:    "success",
	}
	if err := logger.Record(entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var env signedEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 1) 原始 payload 应验证通过（链式验证，prevSig 从 envelope 读取）。
	ok, err := logger.VerifyChainSignature([]byte(env.Payload), env.PrevSignature, env.Signature)
	if err != nil || !ok {
		t.Fatalf("original payload should verify: ok=%v err=%v", ok, err)
	}

	// 2) 篡改 payload（success → failure）。
	tampered := strings.Replace(env.Payload, "success", "failure", 1)
	if tampered == env.Payload {
		t.Fatal("tamper did not change payload")
	}
	ok, _ = logger.VerifyChainSignature([]byte(tampered), env.PrevSignature, env.Signature)
	if ok {
		t.Fatal("tampered payload must NOT verify with original signature")
	}

	// 3) 篡改 signature（翻转首字符）。
	flippedSig := flipFirstHexChar(env.Signature)
	ok, _ = logger.VerifySignature([]byte(env.Payload), flippedSig)
	if ok {
		t.Fatal("tampered signature must NOT verify")
	}
}

// TestAuditLogger_NoSensitiveData 验证日志输出不含明文/密文标记。
func TestAuditLogger_NoSensitiveData(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewAuditLogger(&buf)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer logger.Close()

	entry := LogEntry{
		TraceID:   "trace-safe",
		Timestamp: time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC),
		Actor:     "approle-1",
		Action:    "Encrypt",
		KeyID:     "key-001",
		Status:    "success",
	}
	if err := logger.Record(entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "plaintext=") || strings.Contains(output, "ciphertext=") {
		t.Fatal("log output contains sensitive field markers")
	}
}

// TestAuditLogger_CloseWipesKey 验证 Close 后 AuditKey 被 Wipe。
func TestAuditLogger_CloseWipesKey(t *testing.T) {
	logger, err := NewAuditLogger(nil)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	logger.Close()
	// Close 后 auditKey 被置 nil（Wipe 已调用），nil 即表示已清理。
	if logger.auditKey != nil {
		t.Fatal("AuditKey should be nil after Close (Wipe + nil)")
	}
}

// TestAuditLogger_KeyIsolatedFromMasterKey 验证两次 NewAuditLogger 生成的 key 不同，
// 证明 AuditKey 是独立 CSPRNG 生成，不是从某个共享源（如 Master Key）派生。
func TestAuditLogger_KeyIsolatedFromMasterKey(t *testing.T) {
	l1, err := NewAuditLogger(nil)
	if err != nil {
		t.Fatalf("NewAuditLogger 1: %v", err)
	}
	defer l1.Close()

	l2, err := NewAuditLogger(nil)
	if err != nil {
		t.Fatalf("NewAuditLogger 2: %v", err)
	}
	defer l2.Close()

	// 用同一个 payload 分别签名，签名应不同（因 key 不同）。
	payload := []byte(`{"action":"test"}`)
	var sig1, sig2 []byte
	_ = l1.auditKey.WithKey(func(k []byte) error {
		mac := hmacNew(k, payload)
		sig1 = mac
		return nil
	})
	_ = l2.auditKey.WithKey(func(k []byte) error {
		mac := hmacNew(k, payload)
		sig2 = mac
		return nil
	})

	if bytes.Equal(sig1, sig2) {
		t.Fatal("two AuditLoggers must have different keys (independent CSPRNG)")
	}
}

// --- 辅助函数 ---

// flipFirstHexChar 翻转 hex 字符串首字符（用于签名篡改测试）。
func flipFirstHexChar(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	b[0] = b[0] ^ 0x01
	return string(b)
}

// hmacNew 是 hmac.New(sha256.New, key).Sum(nil) 的简写，避免测试文件重复 import。
func hmacNew(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
}
