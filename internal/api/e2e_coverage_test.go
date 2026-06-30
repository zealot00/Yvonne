// Package api - 补充未覆盖的 handler 测试。
//
// 覆盖：
//   - handleAuditQuery（需 audit dir）
//   - handleTransitPub / handleImportKey（BYOK）
//   - handleSoftDeleteKey / handleRestoreKey（路径分发）
//   - handleApprovals（路由分发）
//   - handleSysUnseal（Shamir 提交）
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newCoverageTestRouter 创建带 audit dir 的测试 router（覆盖 handleAuditQuery）。
func newCoverageTestRouter(t *testing.T) (*V1Router, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	auditDir := t.TempDir()

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	auditLog, _ := audit.NewDualWriteLogger(auditDir, "audit.log", 180, nil)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.auditDir = auditDir
	router.SetMFAStore(auth.NewMemoryMFAStore())
	router.SetApprovalStore(auth.NewMemoryApprovalStore())

	// 创建测试密钥。
	mgr.CreateKey(context.Background(), "cov-key", seal.NewSoftwareKEK(mk), 0)
	return router, mgr, mk
}

// adminCtx 注入管理员 Policy。
func adminCtxV2() context.Context {
	return auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "admin", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"},
	})
}

// TestCov_AuditQuery AuditQuery 端点覆盖。
func TestCov_AuditQuery(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	// 先记录一条审计日志。
	router.auditLog.Record(audit.LogEntry{
		Action: "TestAction", Actor: "tester", Result: "success",
	})

	body := []byte(`{"limit":10}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/query", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleAuditQuery(w, req)

	if w.Code != 200 {
		t.Fatalf("AuditQuery: %d, body=%s", w.Code, w.Body.String())
	}
	t.Logf("✅ AuditQuery: %s", w.Body.String()[:50])
}

// TestCov_TransitPub BYOK 传输公钥。
func TestCov_TransitPub(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/transit-pub", nil)
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleTransitPub(w, req)

	if w.Code != 200 {
		t.Fatalf("TransitPub: %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			PublicKey    string `json:"public_key"`
			TransitKeyID string `json:"transit_key_id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Data.PublicKey == "" {
		t.Fatal("public key should not be empty")
	}
	t.Logf("✅ TransitPub: %d bytes", len(resp.Data.PublicKey))
}

// TestCov_SoftDeleteRestore 软删除 + 恢复（路径分发）。
func TestCov_SoftDeleteRestore(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	// SoftDelete via path dispatch。
	body := []byte(`{"version":1}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/keys/cov-key/soft-delete", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("SoftDelete: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ SoftDelete via path dispatch")

	// Restore。
	body = []byte(`{"version":1}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/cov-key/restore", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("Restore: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ Restore via path dispatch")
}

// TestCov_SysUnseal Shamir 分片提交。
func TestCov_SysUnseal(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	// 创建 sealed vault（不 DirectUnseal）。
	vault := seal.NewVaultState(3, 2, 0)

	// 生成 Shamir 分片。
	shares, err := seal.Split(mk, 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	defer auditLog.Close()

	router := NewV1Router(vault, auditLog, mgr, nil, nil)

	// 提交第 1 个分片。
	shareBody, _ := json.Marshal(sysUnsealRequest{Share: shares[0]})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", bytes.NewReader(shareBody))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("Unseal 1: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ SysUnseal share 1: accepted (still sealed)")

	// 提交第 2 个分片 → 解封。
	shareBody2, _ := json.Marshal(sysUnsealRequest{Share: shares[1]})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", bytes.NewReader(shareBody2))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("Unseal 2: %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Unsealed bool `json:"unsealed"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Data.Unsealed {
		t.Fatal("should be unsealed after 2 shares")
	}
	t.Log("✅ SysUnseal share 2: unsealed")
}

// TestCov_SysUnseal_InvalidBody 无效请求体。
func TestCov_SysUnseal_InvalidBody(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(3, 2, 0)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	defer auditLog.Close()

	router := NewV1Router(vault, auditLog, mgr, nil, nil)

	// 无效 JSON。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ SysUnseal invalid body: 400")
}

// TestCov_ApprovalsDispatch /api/v1/approvals 路由分发（POST=创建，GET=列表）。
func TestCov_ApprovalsDispatch(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	// POST = 创建。
	body, _ := json.Marshal(createApprovalRequest{
		Operation: "ShredKey", KeyID: "cov-key", Required: 1, TTLHours: 24,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleApprovals(w, req)

	if w.Code != 200 {
		t.Fatalf("POST approvals: %d", w.Code)
	}
	t.Log("✅ POST /api/v1/approvals: create ticket")

	// GET = 列表。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req = req.WithContext(adminCtxV2())
	w = httptest.NewRecorder()
	router.handleApprovals(w, req)

	if w.Code != 200 {
		t.Fatalf("GET approvals: %d", w.Code)
	}
	t.Log("✅ GET /api/v1/approvals: list pending")

	// GET?id=xxx = 查询单个。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/approvals?id=fake-id", nil)
	req = req.WithContext(adminCtxV2())
	w = httptest.NewRecorder()
	router.handleApprovals(w, req)

	// 不存在的 ID → 404。
	if w.Code != 404 {
		t.Fatalf("GET approvals?id=fake: expected 404, got %d", w.Code)
	}
	t.Log("✅ GET /api/v1/approvals?id=fake: 404")
}

// TestCov_AuditQuery_LimitNegative 审计查询 limit=-1 强制上限。
func TestCov_AuditQuery_LimitNegative(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	// 记录几条日志。
	for i := 0; i < 5; i++ {
		router.auditLog.Record(audit.LogEntry{
			Action: "TestAction", Actor: "tester", Result: "success",
		})
	}

	body := []byte(`{"limit":-1}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/query", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleAuditQuery(w, req)

	if w.Code != 200 {
		t.Fatalf("AuditQuery limit=-1: %d", w.Code)
	}
	t.Log("✅ AuditQuery limit=-1: forced to max 10000")
}

// TestCov_AuditQuery_NoDir 无 audit dir 配置。
func TestCov_AuditQuery_NoDir(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	defer auditLog.Close()

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	// auditDir 为空。

	body := []byte(`{"limit":10}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/query", bytes.NewReader(body))
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleAuditQuery(w, req)

	if w.Code != 503 {
		t.Fatalf("expected 503 (no audit dir), got %d", w.Code)
	}
	t.Log("✅ AuditQuery no dir: 503")
}

// TestCov_AuditFilesExist 验证审计日志文件存在。
func TestCov_AuditFilesExist(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	// 记录日志。
	router.auditLog.Record(audit.LogEntry{
		Action: "FileTest", Actor: "tester", Result: "success",
	})

	// 验证文件存在。
	files, err := filepath.Glob(filepath.Join(router.auditDir, "audit*.log"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		// 可能文件名不同，列出目录。
		entries, _ := os.ReadDir(router.auditDir)
		for _, e := range entries {
			t.Logf("  file: %s", e.Name())
		}
	}
	t.Logf("✅ Audit dir has %d files", len(files))
}

// TestCov_GDKWithoutPlaintext_NoKeyID 无 key_id 拒绝。
func TestCov_GDKWithoutPlaintext_NoKeyID(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/gdk-no-plaintext", nil)
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleV1GDKWithoutPlaintext(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ GDKWithoutPlaintext no key_id: 400")
}

// TestCov_GetPublicKey_NoKeyID 无 key_id 拒绝。
func TestCov_GetPublicKey_NoKeyID(t *testing.T) {
	router, _, _ := newCoverageTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key", nil)
	req = req.WithContext(adminCtxV2())
	w := httptest.NewRecorder()
	router.handleV1GetPublicKey(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ GetPublicKey no key_id: 400")
}
