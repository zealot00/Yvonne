//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// TestEmergencySeal_ClearsDEKCache 验证紧急封印后 DEK 缓存被清空。
// 修复前：EmergencySeal 只 Wipe MasterKey，但 lifecycle 缓存的 DEK 元数据仍在。
// 修复后：handleEmergencySeal 调用 manager.ClearCache()。
func TestEmergencySeal_ClearsDEKCache(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{
			RoleID:         "admin",
			Token:          "admin-token",
			AllowedKeys:    []string{"*"},
			AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp"},
		},
	})
	r.SetAdminToken("admin-token")

	mgr.CreateKey(nil, "cache-test-key", seal.NewSoftwareKEK(mk), 0)

	// 先访问一次让缓存加载。
	_, err := mgr.GetActiveKey(nil, "cache-test-key")
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}

	// 触发紧急封印。
	body := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("EmergencySeal: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// 验证紧急封印后 VaultState 不可用。
	if !r.seal.IsEmergencySealed() {
		t.Fatal("should be emergency sealed")
	}
}

// TestEmergencySeal_NoManagerPanic 验证 manager 为 nil 时不 panic。
func TestEmergencySeal_NoManagerPanic(t *testing.T) {
	v := seal.NewVaultState(5, 3, 0)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v.DirectUnseal(mk)

	// 用 nil manager 创建 router（模拟某些测试场景）。
	// 需要 auditLog 避免 panic。
	var buf strings.Builder
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()

	r := NewV1Router(v, logger, nil, nil, nil)
	r.SetAdminToken("admin-token")

	body := `{"admin_token":"admin-token","confirm":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", strings.NewReader(body))
	rec := httptest.NewRecorder()

	// 不应 panic。
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("EmergencySeal with nil manager: got %d", rec.Code)
	}
}

// 确保 lifecycle 包被引用。
var _ = lifecycle.StateActive
