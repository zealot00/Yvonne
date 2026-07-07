// Package admin - 补充覆盖测试。
package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newAdminTestServer 创建测试 admin server。
func newAdminTestServer(t *testing.T) *Server {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	srv := NewServer(vault)
	srv.SetManager(mgr)
	return srv
}

// TestAdmin_ListKeys 列出密钥。
func TestAdmin_ListKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	ctx := context.Background()
	mgr.CreateKey(ctx, "key-1", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "key-2", seal.NewSoftwareKEK(mk), 0)

	srv := NewServer(vault)
	srv.SetManager(mgr)

	req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 200 {
		t.Fatalf("ListKeys: %d, body=%s", w.Code, w.Body.String())
	}
	t.Logf("✅ ListKeys: %s", w.Body.String()[:50])
}

// TestAdmin_ListKeys_NoManager 无 manager。
func TestAdmin_ListKeys_NoManager(t *testing.T) {
	srv := NewServer(testVault(t))

	req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	t.Log("✅ ListKeys no manager → empty list")
}

// TestAdmin_ListKeys_MethodNotAllowed 非 GET 拒绝。
func TestAdmin_ListKeys_MethodNotAllowed(t *testing.T) {
	srv := newAdminTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 405 {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	t.Log("✅ ListKeys POST → 405")
}

// TestAdmin_SetAdminToken 设置 admin token。
func TestAdmin_SetAdminToken(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("test-token")
	if srv.adminToken != "test-token" {
		t.Fatal("token not set")
	}
	t.Log("✅ SetAdminToken")
}

// TestAdmin_SetManager 设置 manager。
func TestAdmin_SetManager(t *testing.T) {
	srv := NewServer(testVault(t))
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	srv.SetManager(mgr)
	if srv.manager == nil {
		t.Fatal("manager not set")
	}
	t.Log("✅ SetManager")
}

// TestAdmin_ServeHTTP_PublicIndex 设置 token 后根路径仍可访问（v1.4.2 不再有双层 auth）。
// 公共页面不需要 auth；受保护 API 需要 session 或 Bearer。
func TestAdmin_ServeHTTP_PublicIndex(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")
	wireMinimalStorage(srv)

	// 根路径无认证 → 公开 index（200 / SPA 占位）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// 可能 200 / 404 / 405（取决于 index handler），不应是 401
	if w.Code == 401 {
		t.Fatalf("public index should not be 401, got %d", w.Code)
	}
	t.Logf("✅ ServeHTTP public index → %d (no longer 401)", w.Code)

	// 受保护 API 无认证 → 401
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard", nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("protected API without auth should be 401, got %d", w2.Code)
	}
	t.Log("✅ ServeHTTP protected API no auth → 401")

	// Bearer 通过
	req3 := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard", nil)
	req3.Header.Set("Authorization", "Bearer secret")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)
	if w3.Code == 401 {
		t.Fatalf("Bearer should pass protected API, got %d", w3.Code)
	}
	t.Logf("✅ ServeHTTP protected API + Bearer → %d", w3.Code)
}

// wireMinimalStorage 给一个最小可用的 Server 注入 v1.4.2 存储（测试 helper）。
func wireMinimalStorage(s *Server) {
	if s.sessions == nil {
		s.sessions = NewMemorySessionStore()
	}
	if s.captchaStore == nil {
		s.captchaStore = NewMemoryCaptchaStore()
	}
	if s.loginStates == nil {
		s.loginStates = NewMemoryLoginStateStore()
	}
	if s.devices == nil {
		s.devices = NewMemoryDeviceStore()
	}
	if s.auditor == nil {
		s.auditor = &NoopAuditor{}
	}
	if s.idleTimeout == 0 {
		s.idleTimeout = 30 * time.Minute
	}
	if s.hardCap == 0 {
		s.hardCap = 8 * time.Hour
	}
	if s.sessionSecret == nil {
		s.sessionSecret = []byte("test-session-secret-32-bytes-pad!")
	}
}

// 辅助函数。
func testMK(t *testing.T) *memguard.SecureBuffer {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	return mk
}

// testVault 创建测试 vault。
func testVault(t *testing.T) seal.Unsealer {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)
	return vault
}
