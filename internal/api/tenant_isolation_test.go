// Package api — 多租户隔离 E2E 测试。
package api

import (
	"bytes"
	"context"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestTenantIsolation_BasicCrossTenantAccess 多租户：tenant-a 无法访问 tenant-b 的密钥。
func TestTenantIsolation_BasicCrossTenantAccess(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog := newAuditLoggerForTest(t, &auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetMFAStore(auth.NewMemoryMFAStore())
	router.SetApprovalStore(auth.NewMemoryApprovalStore())

	// 模拟 tenant-a 用户创建密钥。
	ctxA := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         "admin-a",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
		TenantID:       "tenant-a",
	})
	ctxA = auth.WithTenant(ctxA, "tenant-a")

	// tenant-a 创建密钥。
	mgr.CreateKey(context.Background(), auth.ScopedKeyID("tenant-a", "shared-key"), seal.NewSoftwareKEK(mk), 0)
	t.Log("✅ tenant-a created key 'shared-key'")

	// tenant-a 加密。
	enc := doJSON(t, router, "POST", "/api/v1/encrypt",
		map[string]interface{}{"key_id": "shared-key", "plaintext": []byte("tenant-a data")},
		ctxA)
	if enc.Code != 200 {
		t.Fatalf("tenant-a encrypt: %d, body=%s", enc.Code, enc.Body.String())
	}
	t.Log("✅ tenant-a encrypt succeeded")

	// tenant-b 尝试访问 tenant-a 的密钥 → 应失败。
	ctxB := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         "admin-b",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
		TenantID:       "tenant-b",
	})
	ctxB = auth.WithTenant(ctxB, "tenant-b")

	enc2 := doJSON(t, router, "POST", "/api/v1/encrypt",
		map[string]interface{}{"key_id": "shared-key", "plaintext": []byte("tenant-b data")},
		ctxB)
	if enc2.Code == 200 {
		t.Fatal("tenant-b should NOT access tenant-a's key")
	}
	t.Logf("✅ tenant-b access denied: %d", enc2.Code)
}

// TestTenantIsolation_CreateSameKeyName 不同租户可创建同名密钥。
func TestTenantIsolation_CreateSameKeyName(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog := newAuditLoggerForTest(t, &auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)

	// tenant-a 创建 "order-key"。
	ctxA := auth.WithTenant(auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "a", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}, TenantID: "tenant-a",
	}), "tenant-a")

	w := doJSON(t, router, "POST", "/api/v1/keys", map[string]interface{}{"key_id": "order-key"}, ctxA)
	if w.Code != 200 {
		t.Fatalf("tenant-a create: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ tenant-a created 'order-key'")

	// tenant-b 创建同名 "order-key" → 应成功（不同租户空间）。
	ctxB := auth.WithTenant(auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "b", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}, TenantID: "tenant-b",
	}), "tenant-b")

	w2 := doJSON(t, router, "POST", "/api/v1/keys", map[string]interface{}{"key_id": "order-key"}, ctxB)
	if w2.Code != 200 {
		t.Fatalf("tenant-b create same key name: %d, body=%s", w2.Code, w2.Body.String())
	}
	t.Log("✅ tenant-b created 'order-key' (same name, different tenant)")

	// 验证两个密钥独立存在。
	metaA, _ := mgr.GetActiveKey(context.Background(), "tenant-a:order-key")
	metaB, _ := mgr.GetActiveKey(context.Background(), "tenant-b:order-key")
	if metaA == nil || metaB == nil {
		t.Fatal("both tenant keys should exist")
	}
	if metaA.KeyID == metaB.KeyID {
		t.Fatal("keys should be different (scoped)")
	}
	t.Logf("✅ Keys isolated: %s vs %s", metaA.KeyID, metaB.KeyID)
}

// TestTenantIsolation_BackwardCompat 非多租户模式行为不变。
func TestTenantIsolation_BackwardCompat(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog := newAuditLoggerForTest(t, &auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)

	// 无 TenantID 的 Policy（向后兼容）。
	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
		// TenantID 为空 → 非多租户模式
	})

	// 创建密钥。
	w := doJSON(t, router, "POST", "/api/v1/keys", map[string]interface{}{"key_id": "normal-key"}, ctx)
	if w.Code != 200 {
		t.Fatalf("create: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ Non-tenant create key")

	// 加密。
	enc := doJSON(t, router, "POST", "/api/v1/encrypt",
		map[string]interface{}{"key_id": "normal-key", "plaintext": []byte("test")}, ctx)
	if enc.Code != 200 {
		t.Fatalf("encrypt: %d", enc.Code)
	}
	t.Log("✅ Non-tenant encrypt")

	// 解密。
	dec := doJSON(t, router, "POST", "/api/v1/decrypt",
		map[string]interface{}{"key_id": "normal-key", "ciphertext": parseResp(t, enc)["data"].(map[string]interface{})["ciphertext"]}, ctx)
	if dec.Code != 200 {
		t.Fatalf("decrypt: %d", dec.Code)
	}
	t.Log("✅ Non-tenant decrypt (backward compat)")
}

// TestScopedKeyID 单元测试。
func TestScopedKeyID(t *testing.T) {
	// 有 tenant → 加前缀。
	if got := auth.ScopedKeyID("tenant-a", "key1"); got != "tenant-a:key1" {
		t.Fatalf("got %q, want tenant-a:key1", got)
	}

	// 无 tenant → 原样返回。
	if got := auth.ScopedKeyID("", "key1"); got != "key1" {
		t.Fatalf("got %q, want key1", got)
	}
	t.Log("✅ ScopedKeyID")
}

// TestUnscopedKeyID 单元测试。
func TestUnscopedKeyID(t *testing.T) {
	if got := auth.UnscopedKeyID("tenant-a", "tenant-a:key1"); got != "key1" {
		t.Fatalf("got %q, want key1", got)
	}

	if got := auth.UnscopedKeyID("", "key1"); got != "key1" {
		t.Fatalf("got %q, want key1", got)
	}
	t.Log("✅ UnscopedKeyID")
}

// TestTenantFromContext context 提取测试。
func TestTenantFromContext(t *testing.T) {
	ctx := auth.WithTenant(context.Background(), "test-tenant")
	if got := auth.TenantFromContext(ctx); got != "test-tenant" {
		t.Fatalf("got %q", got)
	}

	// 无 tenant context。
	if got := auth.TenantFromContext(context.Background()); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	t.Log("✅ TenantFromContext")
}

// 辅助：创建 audit logger（与 e2e_full_test.go 共用但避免依赖）。
func newAuditLoggerForTest(t *testing.T, w *bytes.Buffer) audit.Auditor {
	t.Helper()
	// 用 audit.NewAuditLogger（返回 Auditor 接口）。
	log, _ := audit.NewAuditLogger(w)
	t.Cleanup(log.Close)
	return log
}
