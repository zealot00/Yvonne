// Package admin - 补充覆盖测试。
package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

// TestAdmin_Authenticate_BasicAuth Basic Auth 认证。
func TestAdmin_Authenticate_BasicAuth(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")

	if !srv.authenticate(req) {
		t.Fatal("BasicAuth should succeed")
	}
	t.Log("✅ authenticate BasicAuth correct")
}

// TestAdmin_Authenticate_BasicAuthWrong Basic Auth 错误密码。
func TestAdmin_Authenticate_BasicAuthWrong(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")

	if srv.authenticate(req) {
		t.Fatal("BasicAuth should fail")
	}
	t.Log("✅ authenticate BasicAuth wrong → false")
}

// TestAdmin_Authenticate_Bearer Bearer token 认证。
func TestAdmin_Authenticate_Bearer(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")

	if !srv.authenticate(req) {
		t.Fatal("Bearer should succeed")
	}
	t.Log("✅ authenticate Bearer correct")
}

// TestAdmin_Authenticate_BearerWrong Bearer 错误。
func TestAdmin_Authenticate_BearerWrong(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong")

	if srv.authenticate(req) {
		t.Fatal("Bearer should fail")
	}
	t.Log("✅ authenticate Bearer wrong → false")
}

// TestAdmin_Authenticate_NoAuth 无认证头。
func TestAdmin_Authenticate_NoAuth(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if srv.authenticate(req) {
		t.Fatal("no auth should fail")
	}
	t.Log("✅ authenticate no auth → false")
}

// TestAdmin_ServeHTTP_WithAuth 设置 token 后需要认证。
func TestAdmin_ServeHTTP_WithAuth(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")

	// 无认证 → 401。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	t.Log("✅ ServeHTTP no auth → 401")

	// 有认证 → 通过。
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.SetBasicAuth("admin", "secret")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	// 可能返回 404（根路径无 handler），但不应该是 401。
	if w2.Code == 401 {
		t.Fatal("should pass with auth")
	}
	t.Logf("✅ ServeHTTP with auth → %d", w2.Code)
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
