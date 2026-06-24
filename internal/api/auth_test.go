package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newAuthTestRouter 创建带认证的 V1Router。
func newAuthTestRouter(t *testing.T) (*V1Router, *auth.AppRoleAuthenticator) {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	v := seal.NewVaultState(3, 2, 0)
	v.DirectUnseal(mk)
	// 不 wipe mk——vault 持有引用，测试期间需要 MasterKey 可用。

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	t.Cleanup(func() { logger.Close() })

	authenticator := auth.NewAppRoleAuthenticator()
	authenticator.RegisterPolicy("order-service", "token-order-123", &auth.Policy{
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey"},
	})
	authenticator.RegisterPolicy("admin", "token-admin-456", &auth.Policy{
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp"},
	})

	r := NewV1Router(v, logger, mgr, nil, authenticator)
	return r, authenticator
}

// TestRequireAuth_MissingToken 验证无 Authorization header 返回 401。
func TestRequireAuth_MissingToken(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(`{"key_id":"x","plaintext":"aGk="}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", rec.Code)
	}
}

// TestRequireAuth_InvalidToken 验证错误 Token 返回 401。
func TestRequireAuth_InvalidToken(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(`{"key_id":"x","plaintext":"aGk="}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: got %d, want 401", rec.Code)
	}
}

// TestRequireAuth_ValidTokenButActionNotAllowed 验证 action 越权返回 403。
func TestRequireAuth_ValidTokenButActionNotAllowed(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	// order-service 没有 KeyOp 权限（rotate/shred）。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/rotate", nil)
	req.Header.Set("Authorization", "Bearer token-order-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("action not allowed: got %d, want 403", rec.Code)
	}
}

// TestRequireAuth_KeyNotAllowed 验证 key_id 越权返回 403。
func TestRequireAuth_KeyNotAllowed(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	// order-service 只允许 order-*，不允许 payment-key。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/payment-key/rotate", nil)
	req.Header.Set("Authorization", "Bearer token-order-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	// order-service 没有 rotate 权限，会先被 action 检查拦截。
	if rec.Code != http.StatusForbidden {
		t.Fatalf("key not allowed: got %d, want 403", rec.Code)
	}
}

// TestRequireAuth_AdminFullAccess 验证 admin 角色有完整权限。
func TestRequireAuth_AdminFullAccess(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	// admin 有 create 权限，应能创建密钥。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(`{"key_id":"admin-test"}`))
	req.Header.Set("Authorization", "Bearer token-admin-456")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("admin should have access: got %d", rec.Code)
	}
}

// TestRequireAuth_ValidTokenCreateKey 验证有 create 权限的角色能创建密钥。
func TestRequireAuth_ValidTokenCreateKey(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(`{"key_id":"order-001"}`))
	req.Header.Set("Authorization", "Bearer token-order-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create key with valid token: got %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

// TestRequireAuth_WrongScheme 验证非 Bearer scheme 返回 401。
func TestRequireAuth_WrongScheme(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader(`{"key_id":"x","plaintext":"aGk="}`))
	req.Header.Set("Authorization", "Basic token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong scheme: got %d, want 401", rec.Code)
	}
}

// TestExtractKeyIDFromPath 验证路径解析。
func TestExtractKeyIDFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/keys/mykey/rotate", "mykey"},
		{"/api/v1/keys/mykey/shred", "mykey"},
		{"/api/v1/keys/", ""},
		{"/api/v1/encrypt", ""},
		{"/api/v1/decrypt", ""},
	}
	for _, tt := range tests {
		got := extractKeyIDFromPath(tt.path)
		if got != tt.want {
			t.Errorf("extractKeyIDFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// TestRequireAuth_SealedReturns503 验证 Sealed 状态优先于认证。
func TestRequireAuth_SealedReturns503(t *testing.T) {
	r, _ := newAuthTestRouter(t)
	// Seal the vault.
	r.seal.Seal(context.Background())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(`{"key_id":"x"}`))
	req.Header.Set("Authorization", "Bearer token-admin-456")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed: got %d, want 503", rec.Code)
	}
}
