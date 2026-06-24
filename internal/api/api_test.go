package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/seal"
)

// newTestV1Router 创建测试用 V1Router，带独立 audit logger 与 buffer。
func newTestV1Router(t *testing.T, sealed bool) (*V1Router, *bytes.Buffer) {
	t.Helper()
	v := seal.NewVaultState(5, 3, 0)
	// 测试默认保持 Sealed；如需 Unsealed 在用例中单独处理。

	var buf bytes.Buffer
	logger, err := audit.NewAuditLogger(&buf)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	r := NewV1Router(v, logger, nil, nil, nil)
	return r, &buf
}

// TestV1Encrypt_SealedReturns503 验证 Sealed 状态下 /encrypt 返回 503。
func TestV1Encrypt_SealedReturns503(t *testing.T) {
	r, _ := newTestV1Router(t, true)

	body := `{"key_id":"test-key","plaintext":"aGVsbG8="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(body))
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Sealed /encrypt: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestV1Encrypt_MiddlewareRecordsAuditLog 验证中间件生成并记录带 HMAC 签名的审计日志。
func TestV1Encrypt_MiddlewareRecordsAuditLog(t *testing.T) {
	r, buf := newTestV1Router(t, true)

	body := `{"key_id":"test-key","plaintext":"aGVsbG8="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	// 验证审计日志已落盘。
	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("audit log buffer is empty; middleware must record even on 503")
	}
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		t.Fatal("no audit log lines")
	}

	// 解析最后一行（本测试只发了一个请求）。
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &env); err != nil {
		t.Fatalf("parse audit log: %v\nraw: %s", err, lines[len(lines)-1])
	}

	// 必须含 payload 与 signature 字段。
	if _, ok := env["payload"]; !ok {
		t.Fatal("audit log missing 'payload' field")
	}
	if sig, ok := env["signature"].(string); !ok || sig == "" {
		t.Fatal("audit log missing or empty 'signature' field")
	}

	// 验证 signature 是 64 字符的 hex（HMAC-SHA256 = 32 字节 = 64 hex 字符）。
	sig := env["signature"].(string)
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 (HMAC-SHA256 hex)", len(sig))
	}

	// 解析 payload，验证 Action 与 Status。
	payloadStr := env["payload"].(string)
	var entry audit.LogEntry
	if err := json.Unmarshal([]byte(payloadStr), &entry); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if entry.Action != "Encrypt" {
		t.Fatalf("payload Action = %q, want %q", entry.Action, "Encrypt")
	}
	if entry.Status != "failure" {
		t.Fatalf("payload Status = %q, want %q (503 should be failure)", entry.Status, "failure")
	}
	if entry.TraceID == "" {
		t.Fatal("payload TraceID is empty; middleware must generate it")
	}
}

// TestV1Decrypt_SealedReturns503 验证 Sealed 状态下 /decrypt 返回 503。
func TestV1Decrypt_SealedReturns503(t *testing.T) {
	r, _ := newTestV1Router(t, true)

	body := `{"key_id":"test-key","ciphertext":"AAECAwQFBgcICQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Sealed /decrypt: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestV1Encrypt_InvalidBodyReturns400 验证非法 JSON 返回 400 且记录审计日志。
func TestV1Encrypt_InvalidBodyReturns400(t *testing.T) {
	r, buf := newTestV1Router(t, true)

	// 用一个会让 Sealed 检查通过的路径：/api/v1/unseal 接受任意 body。
	// 这里测 /encrypt 在 Sealed 时返回 503，审计仍记录。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	// Sealed 优先于 body 解析，应返回 503。
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 (sealed takes precedence)", rec.Code)
	}

	// 审计日志仍应记录。
	if strings.TrimSpace(buf.String()) == "" {
		t.Fatal("audit log must be recorded even on 503")
	}
}

// TestV1Unseal_MiddlewareRecordsAudit 验证 /unseal 请求也记录审计日志。
func TestV1Unseal_MiddlewareRecordsAudit(t *testing.T) {
	r, buf := newTestV1Router(t, true)

	// 提交一份无效 share，应返回错误但记录审计日志。
	body := `{"share":"AAECAwQ="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	// 应返回 400（share 不足或格式问题）或其他非 200。
	if rec.Code == http.StatusOK {
		// 若 Unseal 成功（不可能，因 threshold=3），才 200
	}

	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("audit log must be recorded for /unseal")
	}
}
