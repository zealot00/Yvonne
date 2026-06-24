package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// TestEmergencySeal_API_Success 验证 POST /api/v1/sys/panic 成功触发紧急封印。
func TestEmergencySeal_API_Success(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("super-secret-admin-token")

	body := `{"admin_token":"super-secret-admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("panic: got %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	if !v.IsEmergencySealed() {
		t.Fatal("vault should be emergency sealed")
	}
}

// TestEmergencySeal_API_WrongToken 验证错误 Admin Token 返回 403。
func TestEmergencySeal_API_WrongToken(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("correct-token")

	body := `{"admin_token":"wrong-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token: got %d, want 403", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("vault should NOT be emergency sealed with wrong token")
	}
}

// TestEmergencySeal_API_NoConfirm 验证缺少 confirm=true 返回 400。
func TestEmergencySeal_API_NoConfirm(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	body := `{"admin_token":"admin-token","confirm":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no confirm: got %d, want 400", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("vault should NOT be emergency sealed without confirm")
	}
}

// TestEmergencySeal_API_NoAdminTokenConfigured 验证未配置 Admin Token 返回 403。
func TestEmergencySeal_API_NoAdminTokenConfigured(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	// 不调用 SetAdminToken

	body := `{"admin_token":"any","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("no admin token configured: got %d, want 403", rec.Code)
	}
}

// TestEmergencySeal_API_BlocksAllSubsequentRequests 验证紧急封印后所有 API 返回 503。
func TestEmergencySeal_API_BlocksAllSubsequentRequests(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	// 触发紧急封印。
	panicBody := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(panicBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("panic trigger: got %d", rec.Code)
	}

	// 尝试 encrypt 应返回 503。
	encBody := `{"key_id":"test","plaintext":"aGk="}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(encBody))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("encrypt after emergency seal: got %d, want 503", rec2.Code)
	}

	// 尝试 unseal 应返回 503。
	unsealBody := `{"share":"AAECAwQ="}`
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", strings.NewReader(unsealBody))
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("unseal after emergency seal: got %d, want 503", rec3.Code)
	}
}

// TestEmergencySeal_API_AuditLogRecorded 验证紧急封印记录了审计日志。
func TestEmergencySeal_API_AuditLogRecorded(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	body := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("panic: got %d", rec.Code)
	}

	// 验证审计日志含 EmergencySeal action。
	output := buf.String()
	if !strings.Contains(output, "EmergencySeal") {
		t.Fatalf("audit log should contain EmergencySeal action, got: %s", output)
	}
}

// --- 补充分支覆盖 ---

// TestEmergencySeal_API_MethodNotAllowed 验证非 POST 方法返回 405。
func TestEmergencySeal_API_MethodNotAllowed(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sys/panic", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sys/panic: got %d, want 405", rec.Code)
	}
}

// TestEmergencySeal_API_InvalidJSON 验证非 JSON body 返回 400。
func TestEmergencySeal_API_InvalidJSON(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON: got %d, want 400", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("should NOT be emergency sealed with invalid JSON")
	}
}

// TestEmergencySeal_API_ConfirmMissing 验证 confirm 字段缺失（默认 false）返回 400。
func TestEmergencySeal_API_ConfirmMissing(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	// confirm 字段缺失，JSON 解析后 Confirm=false。
	body := `{"admin_token":"admin-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing confirm: got %d, want 400", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("should NOT be emergency sealed without confirm field")
	}
}

// TestEmergencySeal_API_EmptyAdminToken 验证 Admin Token 配置为空串时返回 403。
func TestEmergencySeal_API_EmptyAdminToken(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("") // 显式设为空串

	body := `{"admin_token":"any","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty admin token: got %d, want 403", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("should NOT be emergency sealed with empty admin token config")
	}
}

// TestEmergencySeal_API_EmptyTokenInRequest 验证请求中 admin_token 为空串时返回 403。
func TestEmergencySeal_API_EmptyTokenInRequest(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("correct-token")

	// 请求中 admin_token 为空串。
	body := `{"admin_token":"","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty token in request: got %d, want 403", rec.Code)
	}
	if v.IsEmergencySealed() {
		t.Fatal("should NOT be emergency sealed with empty token")
	}
}

// TestEmergencySeal_API_DifferentTokenLength 验证不同长度 Token 不泄露计时信息。
func TestEmergencySeal_API_DifferentTokenLength(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("exact-32-char-token-aaaaaaaaaa")

	// 短 Token。
	shortBody := `{"admin_token":"short","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(shortBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("short token: got %d, want 403", rec.Code)
	}

	// 长 Token。
	longBody := `{"admin_token":"this-is-a-very-long-token-that-does-not-match","confirm":true}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(longBody))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("long token: got %d, want 403", rec2.Code)
	}

	if v.IsEmergencySealed() {
		t.Fatal("should NOT be emergency sealed with wrong tokens")
	}
}

// TestEmergencySeal_API_WorksEvenWhenSealed 验证 Sealed 状态下仍可触发紧急封印。
// 紧急封印应无视当前状态（已 Sealed 也能冰冻）。
func TestEmergencySeal_API_WorksEvenWhenSealed(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	// 不 Unseal——保持 Sealed 状态。

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	body := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("emergency seal on sealed vault: got %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !v.IsEmergencySealed() {
		t.Fatal("should be emergency sealed even from sealed state")
	}
}

// TestEmergencySeal_API_SealedVaultBlocksAll 验证紧急封印后 health 端点返回冰冻状态。
func TestEmergencySeal_API_SealedVaultBlocksAll(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	// 触发紧急封印。
	body := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("panic: got %d", rec.Code)
	}

	// health 端点应仍可访问（返回 sealed=true）。
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sys/health", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("health after emergency seal: got %d, want 200", rec2.Code)
	}
}
