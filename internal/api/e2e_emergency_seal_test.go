// Package api - Emergency Seal E2E 测试。
//
// 覆盖：
//   - EmergencySeal 后所有 API 拒绝
//   - EmergencySeal 后 Health 返回 sealed
//   - EmergencySeal 错误 admin token 拒绝
//   - EmergencySeal 后 Shamir 解封被拒绝（需重启）
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestE2E_EmergencySeal_AllAPIRejected EmergencySeal 后所有 API 拒绝。
func TestE2E_EmergencySeal_AllAPIRejected(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetAdminToken("correct-admin-token")

	ctx := context.Background()
	mgr.CreateKey(ctx, "seal-test-key", seal.NewSoftwareKEK(mk), 0)

	// EmergencySeal。
	sealBody := []byte(`{"admin_token":"correct-admin-token","confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", bytes.NewReader(sealBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("EmergencySeal: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ EmergencySeal succeeded")

	// Health 应返回 sealed。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sys/health", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if !bytes.Contains(w.Body.Bytes(), []byte(`"sealed":true`)) {
		t.Fatalf("Health should show sealed=true, body=%s", w.Body.String())
	}
	t.Log("✅ Health shows sealed=true")

	// Encrypt 应拒绝（503）。
	encBody := []byte(`{"key_id":"seal-test-key","plaintext":"dGVzdA=="}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", bytes.NewReader(encBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatalf("Encrypt after seal: expected 503, got %d", w.Code)
	}
	t.Log("✅ Encrypt rejected after seal (503)")

	// CreateKey 应拒绝。
	createBody := []byte(`{"key_id":"new-key"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(createBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatalf("CreateKey after seal: expected 503, got %d", w.Code)
	}
	t.Log("✅ CreateKey rejected after seal (503)")
}

// TestE2E_EmergencySeal_WrongAdminToken 错误 admin token 拒绝。
func TestE2E_EmergencySeal_WrongAdminToken(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetAdminToken("correct-token")

	// 错误 token。
	sealBody := []byte(`{"admin_token":"wrong-token","confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", bytes.NewReader(sealBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("wrong admin token: expected 403, got %d", w.Code)
	}
	t.Log("✅ Wrong admin token rejected (403)")

	// Health 应仍为 unsealed（未封印）。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sys/health", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if bytes.Contains(w.Body.Bytes(), []byte(`"sealed":true`)) {
		t.Fatal("should NOT be sealed with wrong token")
	}
	t.Log("✅ Vault still unsealed with wrong token")
}

// TestE2E_EmergencySeal_NoConfirm 无 confirm 拒绝。
func TestE2E_EmergencySeal_NoConfirm(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetAdminToken("correct-token")

	// confirm=false。
	sealBody := []byte(`{"admin_token":"correct-token","confirm":false}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", bytes.NewReader(sealBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("confirm=false: expected 400, got %d", w.Code)
	}
	t.Log("✅ confirm=false rejected (400)")
}

// TestE2E_EmergencySeal_ShamirRejectedAfterSeal 封印后 Shamir 解封被拒绝。
func TestE2E_EmergencySeal_ShamirRejectedAfterSeal(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetAdminToken("correct-token")

	// EmergencySeal。
	sealBody := []byte(`{"admin_token":"correct-token","confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/panic", bytes.NewReader(sealBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("EmergencySeal: %d", w.Code)
	}
	t.Log("✅ EmergencySeal succeeded")

	// 尝试 ProvideShare → 应被拒绝。
	_, err := vault.ProvideShare([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("ProvideShare should be rejected after EmergencySeal")
	}
	t.Logf("✅ Shamir rejected after EmergencySeal: %v", err)
}

// 确保 auth 引用（避免 import 警告）。
var _ = auth.Policy{}
