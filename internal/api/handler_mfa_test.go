// Package api - MFA API 集成测试。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/seal"
)

// newMFATestRouter 创建带 MFAStore 的测试 router。
func newMFATestRouter(t *testing.T) (*V1Router, auth.MFAStore) {
	t.Helper()
	router, mgr, mk := newV12TestRouter(t)
	mfaStore := auth.NewMemoryMFAStore()
	router.SetMFAStore(mfaStore)
	_ = mgr
	_ = mk
	return router, mfaStore
}

// TestMFA_Setup MFA 注册返回 secret + URI。
func TestMFA_Setup(t *testing.T) {
	router, _ := newMFATestRouter(t)

	// 注入 Policy（模拟已认证用户）。
	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "admin"})

	body := mfaSetupRequest{RoleID: "admin"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/setup", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleMFASetup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA setup: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data mfaSetupResponse `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.Secret == "" {
		t.Fatal("secret should not be empty")
	}
	if resp.Data.URI == "" {
		t.Fatal("URI should not be empty")
	}
	t.Logf("✅ MFA setup: secret=%s...", resp.Data.Secret[:8])
	t.Logf("✅ URI: %s", resp.Data.URI)
}

// TestMFA_Setup_EmptyRoleID 空 role_id 拒绝。
func TestMFA_Setup_EmptyRoleID(t *testing.T) {
	router, _ := newMFATestRouter(t)

	body := mfaSetupRequest{RoleID: ""}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/setup", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFASetup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ Empty role_id rejected")
}

// TestMFA_Verify_Success 注册 + 验证往返。
func TestMFA_Verify_Success(t *testing.T) {
	router, store := newMFATestRouter(t)

	// 1. Setup（直接调 store 模拟已 setup）。
	secret, _ := auth.GenerateTOTPSecret()
	store.SaveMFAState(&auth.MFAState{
		RoleID:    "admin",
		Secret:    secret,
		Enabled:   false,
		CreatedAt: time.Now(),
	})

	// 2. 生成当前 TOTP code。
	code, _ := auth.GenerateTOTP(secret, time.Now())

	// 3. Verify。
	body := mfaVerifyRequest{RoleID: "admin", Code: code}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFAVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA verify: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	// 4. 确认 MFA 已启用。
	state, _ := store.GetMFAState("admin")
	if !state.Enabled {
		t.Fatal("MFA should be enabled after verify")
	}
	t.Log("✅ MFA verify: enabled=true")
}

// TestMFA_Verify_InvalidCode 错误 code 拒绝。
func TestMFA_Verify_InvalidCode(t *testing.T) {
	router, store := newMFATestRouter(t)

	secret, _ := auth.GenerateTOTPSecret()
	store.SaveMFAState(&auth.MFAState{
		RoleID:    "admin",
		Secret:    secret,
		Enabled:   false,
		CreatedAt: time.Now(),
	})

	body := mfaVerifyRequest{RoleID: "admin", Code: "000000"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFAVerify(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	// 确认 MFA 未启用。
	state, _ := store.GetMFAState("admin")
	if state.Enabled {
		t.Fatal("MFA should NOT be enabled after invalid code")
	}
	t.Log("✅ Invalid code rejected, MFA not enabled")
}

// TestMFA_Verify_NotSetup 未 setup 先 verify 拒绝。
func TestMFA_Verify_NotSetup(t *testing.T) {
	router, _ := newMFATestRouter(t)

	body := mfaVerifyRequest{RoleID: "nonexistent", Code: "123456"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFAVerify(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	t.Log("✅ Verify before setup rejected (404)")
}

// TestMFA_Disable 禁用 MFA。
func TestMFA_Disable(t *testing.T) {
	router, store := newMFATestRouter(t)

	// Setup + Enable。
	secret, _ := auth.GenerateTOTPSecret()
	store.SaveMFAState(&auth.MFAState{
		RoleID:     "admin",
		Secret:     secret,
		Enabled:    true,
		CreatedAt:  time.Now(),
		VerifiedAt: time.Now(),
	})

	code, _ := auth.GenerateTOTP(secret, time.Now())

	body := mfaDisableRequest{RoleID: "admin", Code: code}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFADisable(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA disable: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	// 确认已删除。
	_, err := store.GetMFAState("admin")
	if err == nil {
		t.Fatal("MFA state should be deleted")
	}
	t.Log("✅ MFA disable: state deleted")
}

// TestMFA_Disable_InvalidCode 禁用需验证 code。
func TestMFA_Disable_InvalidCode(t *testing.T) {
	router, store := newMFATestRouter(t)

	secret, _ := auth.GenerateTOTPSecret()
	store.SaveMFAState(&auth.MFAState{
		RoleID:     "admin",
		Secret:     secret,
		Enabled:    true,
		CreatedAt:  time.Now(),
		VerifiedAt: time.Now(),
	})

	body := mfaDisableRequest{RoleID: "admin", Code: "000000"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleMFADisable(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	// 确认未删除。
	state, err := store.GetMFAState("admin")
	if err != nil || !state.Enabled {
		t.Fatal("MFA should still be enabled after invalid disable code")
	}
	t.Log("✅ Disable with invalid code rejected")
}

// TestMFAMiddleware_SensitiveOperation 敏感操作需 MFA。
func TestMFAMiddleware_SensitiveOperation(t *testing.T) {
	router, store := newMFATestRouter(t)

	// Setup + Enable MFA for role。
	secret, _ := auth.GenerateTOTPSecret()
	store.SaveMFAState(&auth.MFAState{
		RoleID:     "admin",
		Secret:     secret,
		Enabled:    true,
		CreatedAt:  time.Now(),
		VerifiedAt: time.Now(),
	})

	// 模拟带 RequireMFA 的 Policy。
	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:      "admin",
		RequireMFA:  true,
		AllowedKeys: []string{"*"},
	})

	// 敏感操作 ShredKey 无 MFA code → 401。
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/shred", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	called := false
	router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if called {
		t.Fatal("handler should NOT be called without MFA code")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	t.Log("✅ Sensitive op without MFA code: rejected (401)")

	// 带 MFA code → 通过。
	code, _ := auth.GenerateTOTP(secret, time.Now())
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/shred", nil)
	req2.Header.Set("X-MFA-Code", code)
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()

	called2 := false
	router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		called2 = true
		w.WriteHeader(http.StatusOK)
	})(w2, req2)

	if !called2 {
		t.Fatal("handler should be called with valid MFA code")
	}
	t.Log("✅ Sensitive op with valid MFA code: passed")
}

// TestMFAMiddleware_NonSensitive 非敏感操作不需 MFA。
func TestMFAMiddleware_NonSensitive(t *testing.T) {
	router, _ := newMFATestRouter(t)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:      "admin",
		RequireMFA:  true,
		AllowedKeys: []string{"*"},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	called := false
	router.mfaMiddleware("Encrypt", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if !called {
		t.Fatal("non-sensitive op should pass without MFA")
	}
	t.Log("✅ Non-sensitive op: no MFA required")
}

// 确保 lifecycle/seal 被引用（辅助函数在 v12 测试文件中）。
var _ lifecycle.KeyMetadata
var _ seal.KEK
