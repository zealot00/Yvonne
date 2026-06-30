// Package api - v1.0-v1.3 全功能集成测试。
//
// 覆盖所有 API 端点，带认证 Policy 注入（模拟 Cluster 模式）。
// 补充 v1.2.2 Sign/Verify/ReEncrypt/非对称密钥 + v1.3 MFA/Quorum 的 E2E 覆盖。
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newFullTestRouter 创建带 MFA + Approval store 的完整测试 router。
func newFullTestRouter(t *testing.T) (*V1Router, *lifecycle.Manager, auth.MFAStore, auth.ApprovalStore, *memguard.SecureBuffer) {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetMFAStore(auth.NewMemoryMFAStore())
	router.SetApprovalStore(auth.NewMemoryApprovalStore())
	return router, mgr, router.mfaStore, router.approvalStore, mk
}

// adminPolicyCtx 注入管理员 Policy 的 context（模拟已认证）。
func adminPolicyCtx() context.Context {
	return auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
	})
}

// approverCtx 注入审批者 Policy。
func approverCtx(roleID string) context.Context {
	return auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         roleID,
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
	})
}

// doJSON 发送 JSON 请求，返回响应。
func doJSON(t *testing.T, router *V1Router, method, path string, body interface{}, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyJSON, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(bodyJSON)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// parseResp 解析响应 body 到 map。
func parseResp(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v, body=%s", err, w.Body.String())
	}
	return resp
}

// getBytes 从响应 map 中提取 []byte 字段（JSON []byte 是 base64 string）。
func getBytes(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		decoded, _ := base64.StdEncoding.DecodeString(val)
		return decoded
	case []byte:
		return val
	default:
		return nil
	}
}

// getStr 从响应 map 中提取 string 字段。
func getStr(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	default:
		return ""
	}
}

// doHandler 直接调 handler（绕过 RequireAuth 中间件，Policy 已注入 context）。
func doHandler(t *testing.T, handler http.HandlerFunc, method, path string, body interface{}, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyJSON, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(bodyJSON)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// === v1.2.2 E2E ===

// TestE2E_SignVerify_RSA RSA 签名验签完整 E2E。
func TestE2E_SignVerify_RSA(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	// 创建 RSA 密钥。
	w := doJSON(t, router, http.MethodPost, "/api/v1/keys/asymmetric",
		createAsymmetricKeyRequest{KeyID: "e2e-rsa", KeyType: "rsa"}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("create RSA key: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ E2E CreateAsymmetricKey RSA")

	// 签名。
	data := []byte("e2e sign test")
	w = doJSON(t, router, http.MethodPost, "/api/v1/sign",
		signRequest{KeyID: "e2e-rsa", Data: data}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("sign: %d, body=%s", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	sig := getBytes(resp["data"].(map[string]interface{})["signature"])
	t.Logf("✅ E2E Sign RSA: %d bytes", len(sig))

	// 验签（正确）。
	w = doJSON(t, router, http.MethodPost, "/api/v1/verify",
		verifyRequest{KeyID: "e2e-rsa", Data: data, Signature: sig}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d", w.Code)
	}
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["valid"] != true {
		t.Fatal("verify should be valid")
	}
	t.Log("✅ E2E Verify RSA: valid=true")

	// 验签（篡改数据）。
	w = doJSON(t, router, http.MethodPost, "/api/v1/verify",
		verifyRequest{KeyID: "e2e-rsa", Data: []byte("tampered"), Signature: sig}, adminPolicyCtx())
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["valid"] == true {
		t.Fatal("verify should reject tampered data")
	}
	t.Log("✅ E2E Verify RSA (tampered): valid=false")
}

// TestE2E_SignVerify_ECDSA ECDSA 签名验签完整 E2E。
func TestE2E_SignVerify_ECDSA(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	w := doJSON(t, router, http.MethodPost, "/api/v1/keys/asymmetric",
		createAsymmetricKeyRequest{KeyID: "e2e-ecdsa", KeyType: "ecdsa"}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("create ECDSA: %d", w.Code)
	}
	t.Log("✅ E2E CreateAsymmetricKey ECDSA")

	data := []byte("ecdsa e2e")
	w = doJSON(t, router, http.MethodPost, "/api/v1/sign",
		signRequest{KeyID: "e2e-ecdsa", Data: data}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("sign: %d", w.Code)
	}
	resp := parseResp(t, w)
	sig := getBytes(resp["data"].(map[string]interface{})["signature"])

	w = doJSON(t, router, http.MethodPost, "/api/v1/verify",
		verifyRequest{KeyID: "e2e-ecdsa", Data: data, Signature: sig}, adminPolicyCtx())
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["valid"] != true {
		t.Fatal("ECDSA verify should be valid")
	}
	t.Log("✅ E2E Sign+Verify ECDSA")
}

// TestE2E_ReEncrypt ReEncrypt 完整 E2E（跨密钥 + 解密验证）。
func TestE2E_ReEncrypt(t *testing.T) {
	router, mgr, _, _, mk := newFullTestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)

	// 创建两个对称密钥。
	mgr.CreateKey(ctx, "e2e-src", kek, 0)
	mgr.CreateKey(ctx, "e2e-dst", kek, 0)

	// 加密 src。
	w := doJSON(t, router, http.MethodPost, "/api/v1/encrypt",
		map[string]interface{}{"key_id": "e2e-src", "plaintext": []byte("hello reencrypt")}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("encrypt: %d", w.Code)
	}
	resp := parseResp(t, w)
	encCT := getBytes(resp["data"].(map[string]interface{})["ciphertext"])

	// ReEncrypt: src → dst。
	w = doJSON(t, router, http.MethodPost, "/api/v1/re-encrypt",
		reEncryptRequest{SourceKeyID: "e2e-src", DestKeyID: "e2e-dst", Ciphertext: encCT}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("re-encrypt: %d, body=%s", w.Code, w.Body.String())
	}
	resp = parseResp(t, w)
	reCT := getBytes(resp["data"].(map[string]interface{})["ciphertext"])
	t.Logf("✅ E2E ReEncrypt: %d bytes", len(reCT))

	// 用 dst 解密，验证数据一致。
	w = doJSON(t, router, http.MethodPost, "/api/v1/decrypt",
		map[string]interface{}{"key_id": "e2e-dst", "ciphertext": reCT}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("decrypt after re-encrypt: %d", w.Code)
	}
	resp = parseResp(t, w)
	decPT := getBytes(resp["data"].(map[string]interface{})["plaintext"])
	if string(decPT) != "hello reencrypt" {
		t.Fatalf("decrypt mismatch: got %q, want %q", string(decPT), "hello reencrypt")
	}
	t.Log("✅ E2E ReEncrypt + Decrypt: data integrity verified")
}

// TestE2E_GetPublicKey GetPublicKey 完整 E2E。
func TestE2E_GetPublicKey(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	w := doJSON(t, router, http.MethodPost, "/api/v1/keys/asymmetric",
		createAsymmetricKeyRequest{KeyID: "e2e-pubkey", KeyType: "ecdsa"}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d", w.Code)
	}
	createResp := parseResp(t, w)
	createPub := getBytes(createResp["data"].(map[string]interface{})["public_key"])

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key?key_id=e2e-pubkey", nil)
	req = req.WithContext(adminPolicyCtx())
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetPublicKey: %d", w.Code)
	}
	getResp := parseResp(t, w)
	getPub := getBytes(getResp["data"].(map[string]interface{})["public_key"])

	if string(createPub) != string(getPub) {
		t.Fatal("public key mismatch")
	}
	t.Logf("✅ E2E GetPublicKey: %d bytes, matches creation", len(getPub))
}

// === v1.3 MFA + Quorum E2E ===

// TestE2E_MFA_SetupVerifyDisable MFA 完整 E2E。
// MFA 路由用 RequireAuth 中间件，测试直接调 handler 绕过（Policy 已注入 context）。
func TestE2E_MFA_SetupVerifyDisable(t *testing.T) {
	router, _, mfaStore, _, _ := newFullTestRouter(t)

	// 1. Setup MFA（直接调 handler）。
	setupBody, _ := json.Marshal(mfaSetupRequest{RoleID: "admin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/setup", bytes.NewReader(setupBody))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminPolicyCtx())
	w := httptest.NewRecorder()
	router.handleMFASetup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA setup: %d, body=%s", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	secret := resp["data"].(map[string]interface{})["secret"].(string)
	t.Logf("✅ E2E MFA Setup: secret=%s...", secret[:8])

	// 2. 生成 TOTP code。
	code, _ := auth.GenerateTOTP(secret, time.Now())

	// 3. Verify + 启用。
	verifyBody, _ := json.Marshal(mfaVerifyRequest{RoleID: "admin", Code: code})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(verifyBody))
	req = req.WithContext(adminPolicyCtx())
	w = httptest.NewRecorder()
	router.handleMFAVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA verify: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ E2E MFA Verify: enabled=true")

	state, _ := mfaStore.GetMFAState("admin")
	if !state.Enabled {
		t.Fatal("MFA should be enabled")
	}

	// 4. 禁用。
	code2, _ := auth.GenerateTOTP(secret, time.Now())
	disableBody, _ := json.Marshal(mfaDisableRequest{RoleID: "admin", Code: code2})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(disableBody))
	req = req.WithContext(adminPolicyCtx())
	w = httptest.NewRecorder()
	router.handleMFADisable(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("MFA disable: %d, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ E2E MFA Disable: removed")
}

// TestE2E_MFA_SensitiveOperation 敏感操作 MFA 拦截 E2E。
// 用 mfaMiddleware 包裹 handler 测试拦截逻辑。
func TestE2E_MFA_SensitiveOperation(t *testing.T) {
	router, mgr, mfaStore, _, mk := newFullTestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)
	mgr.CreateKey(ctx, "sensitive-key", kek, 0)

	// Setup + 启用 MFA。
	secret, _ := auth.GenerateTOTPSecret()
	mfaStore.SaveMFAState(&auth.MFAState{
		RoleID:     "admin",
		Secret:     secret,
		Enabled:    true,
		CreatedAt:  time.Now(),
		VerifiedAt: time.Now(),
	})

	mfaPolicyCtx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
		RequireMFA:     true,
	})

	// 构造 mfaMiddleware 包裹的 ShredKey handler。
	handler := router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	// ShredKey 无 MFA code → 401。
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/sensitive-key/shred",
		bytes.NewReader([]byte(`{"version":1}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mfaPolicyCtx)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without MFA code, got %d", w.Code)
	}
	t.Log("✅ E2E ShredKey without MFA: 401")

	// 带 MFA code → 通过。
	code, _ := auth.GenerateTOTP(secret, time.Now())
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/keys/sensitive-key/shred",
		bytes.NewReader([]byte(`{"version":1}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MFA-Code", code)
	req = req.WithContext(mfaPolicyCtx)
	w = httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with MFA code, got %d", w.Code)
	}
	t.Log("✅ E2E ShredKey with MFA: success")
}

// TestE2E_Quorum_2of3_Approval Quorum 2-of-3 审批完整 E2E。
func TestE2E_Quorum_2of3_Approval(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	// 1. 创建 2-of-3 审批 ticket（直接调 handler）。
	w := doHandler(t, router.handleCreateApproval, http.MethodPost, "/api/v1/approvals",
		createApprovalRequest{Operation: "ShredKey", KeyID: "quorum-key", Required: 2, TTLHours: 24},
		adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("create approval: %d, body=%s", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	ticketID := resp["data"].(map[string]interface{})["id"].(string)
	t.Logf("✅ E2E Create Approval: ticket=%s...", ticketID[:8])

	// 2. approver-1 approve。
	w = doHandler(t, router.handleApprove, http.MethodPost, "/api/v1/approvals/approve",
		approveRequest{TicketID: ticketID}, approverCtx("approver-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("approve 1: %d, body=%s", w.Code, w.Body.String())
	}
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["status"] != "pending" {
		t.Fatal("after 1st approve, should still be pending")
	}
	t.Log("✅ E2E Approve 1/2: pending")

	// 3. approver-2 approve → 达成 quorum。
	w = doHandler(t, router.handleApprove, http.MethodPost, "/api/v1/approvals/approve",
		approveRequest{TicketID: ticketID}, approverCtx("approver-2"))
	if w.Code != http.StatusOK {
		t.Fatalf("approve 2: %d", w.Code)
	}
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["status"] != "approved" {
		t.Fatal("after 2nd approve, should be approved")
	}
	t.Log("✅ E2E Approve 2/2: approved")

	// 4. 查询 ticket 状态。
	w = doHandler(t, router.handleGetApproval, http.MethodGet, "/api/v1/approvals?id="+ticketID,
		nil, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("get approval: %d", w.Code)
	}
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["status"] != "approved" {
		t.Fatal("query should show approved")
	}
	t.Log("✅ E2E Query Approval: approved")
}

// TestE2E_Quorum_SelfApproveRejected 防自批准 E2E。
func TestE2E_Quorum_SelfApproveRejected(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	w := doHandler(t, router.handleCreateApproval, http.MethodPost, "/api/v1/approvals",
		createApprovalRequest{Operation: "ShredKey", KeyID: "self-key", Required: 1, TTLHours: 24},
		adminPolicyCtx())
	resp := parseResp(t, w)
	ticketID := resp["data"].(map[string]interface{})["id"].(string)

	w = doHandler(t, router.handleApprove, http.MethodPost, "/api/v1/approvals/approve",
		approveRequest{TicketID: ticketID}, adminPolicyCtx())
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for self-approve, got %d", w.Code)
	}
	t.Log("✅ E2E Self-approve rejected: 403")
}

// TestE2E_Quorum_Reject 审批拒绝 E2E。
func TestE2E_Quorum_Reject(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	w := doHandler(t, router.handleCreateApproval, http.MethodPost, "/api/v1/approvals",
		createApprovalRequest{Operation: "ShredKey", KeyID: "reject-key", Required: 2, TTLHours: 24},
		adminPolicyCtx())
	resp := parseResp(t, w)
	ticketID := resp["data"].(map[string]interface{})["id"].(string)

	w = doHandler(t, router.handleReject, http.MethodPost, "/api/v1/approvals/reject",
		approveRequest{TicketID: ticketID}, approverCtx("approver-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("reject: %d", w.Code)
	}
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["status"] != "rejected" {
		t.Fatal("should be rejected")
	}
	t.Log("✅ E2E Quorum Reject: rejected")
}

// TestE2E_Quorum_ListPending 列出 pending E2E。
func TestE2E_Quorum_ListPending(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	doHandler(t, router.handleCreateApproval, http.MethodPost, "/api/v1/approvals",
		createApprovalRequest{Operation: "ShredKey", KeyID: "k1", Required: 1, TTLHours: 24}, adminPolicyCtx())
	doHandler(t, router.handleCreateApproval, http.MethodPost, "/api/v1/approvals",
		createApprovalRequest{Operation: "ExportKey", KeyID: "k2", Required: 1, TTLHours: 24}, adminPolicyCtx())

	w := doHandler(t, router.handleListApprovals, http.MethodGet, "/api/v1/approvals",
		nil, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	resp := parseResp(t, w)
	count := int(resp["data"].(map[string]interface{})["count"].(float64))
	if count != 2 {
		t.Fatalf("pending count = %d, want 2", count)
	}
	t.Logf("✅ E2E List Pending: %d tickets", count)
}

// === v1.0-v1.2 回归 E2E ===

// TestE2E_FullLifecycle 密钥生命周期完整 E2E。
func TestE2E_FullLifecycle(t *testing.T) {
	router, mgr, _, _, mk := newFullTestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)

	mgr.CreateKey(ctx, "lifecycle-key", kek, 0)
	t.Log("✅ E2E CreateKey")

	w := doJSON(t, router, http.MethodPost, "/api/v1/encrypt",
		map[string]interface{}{"key_id": "lifecycle-key", "plaintext": []byte("v1.0 test")}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("encrypt: %d", w.Code)
	}
	resp := parseResp(t, w)
	ct := getBytes(resp["data"].(map[string]interface{})["ciphertext"])

	w = doJSON(t, router, http.MethodPost, "/api/v1/decrypt",
		map[string]interface{}{"key_id": "lifecycle-key", "ciphertext": ct}, adminPolicyCtx())
	resp = parseResp(t, w)
	pt := getBytes(resp["data"].(map[string]interface{})["plaintext"])
	if string(pt) != "v1.0 test" {
		t.Fatalf("decrypt mismatch: %q", string(pt))
	}
	t.Log("✅ E2E Encrypt + Decrypt")

	w = doJSON(t, router, http.MethodPost, "/api/v1/keys/lifecycle-key/rotate", nil, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d", w.Code)
	}
	t.Log("✅ E2E RotateKey")

	w = doJSON(t, router, http.MethodPost, "/api/v1/decrypt",
		map[string]interface{}{"key_id": "lifecycle-key", "ciphertext": ct}, adminPolicyCtx())
	resp = parseResp(t, w)
	pt = getBytes(resp["data"].(map[string]interface{})["plaintext"])
	if string(pt) != "v1.0 test" {
		t.Fatal("backward compat failed")
	}
	t.Log("✅ E2E Backward compat (v1 after rotate)")
}

// TestE2E_Mac_GenerateVerify HMAC 完整 E2E。
func TestE2E_Mac_GenerateVerify(t *testing.T) {
	router, mgr, _, _, mk := newFullTestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)
	mgr.CreateKey(ctx, "mac-key", kek, 0)

	data := []byte("mac e2e test")

	w := doJSON(t, router, http.MethodPost, "/api/v1/mac/generate",
		signRequest{KeyID: "mac-key", Data: data}, adminPolicyCtx())
	if w.Code != http.StatusOK {
		t.Fatalf("generateMac: %d", w.Code)
	}
	resp := parseResp(t, w)
	mac := getBytes(resp["data"].(map[string]interface{})["mac"])
	t.Logf("✅ E2E GenerateMac: %d bytes", len(mac))

	w = doJSON(t, router, http.MethodPost, "/api/v1/mac/verify",
		verifyMacRequest{KeyID: "mac-key", Data: data, Mac: mac}, adminPolicyCtx())
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["valid"] != true {
		t.Fatal("verify should be valid")
	}
	t.Log("✅ E2E VerifyMac: valid=true")

	w = doJSON(t, router, http.MethodPost, "/api/v1/mac/verify",
		verifyMacRequest{KeyID: "mac-key", Data: []byte("wrong"), Mac: mac}, adminPolicyCtx())
	resp = parseResp(t, w)
	if resp["data"].(map[string]interface{})["valid"] == true {
		t.Fatal("verify should reject wrong data")
	}
	t.Log("✅ E2E VerifyMac (wrong): valid=false")
}

// TestE2E_GDKWithoutPlaintext GDK 无明文 E2E。
func TestE2E_GDKWithoutPlaintext(t *testing.T) {
	router, mgr, _, _, mk := newFullTestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)
	mgr.CreateKey(ctx, "gdk-key", kek, 0)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/gdk-no-plaintext?key_id=gdk-key", nil)
	req = req.WithContext(adminPolicyCtx())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GDK: %d, body=%s", w.Code, w.Body.String())
	}
	resp := parseResp(t, w)
	ct := getBytes(resp["data"].(map[string]interface{})["ciphertext"])
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}
	t.Logf("✅ E2E GDKWithoutPlaintext: %d bytes", len(ct))
}

// TestE2E_CORS 完整 CORS E2E。
func TestE2E_CORS(t *testing.T) {
	router, _, _, _, _ := newFullTestRouter(t)

	// OPTIONS 预检。
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/encrypt", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("OPTIONS: got %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("CORS Allow-Origin missing")
	}
	t.Log("✅ E2E CORS preflight: 204 + headers")

	// POST 实际请求带 Origin。
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sys/health", nil)
	req2.Header.Set("Origin", "http://example.com")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	if w2.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Fatal("CORS actual request missing Allow-Origin")
	}
	t.Log("✅ E2E CORS actual: Allow-Origin present")
}
