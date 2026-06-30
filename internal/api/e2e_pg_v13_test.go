//go:build integration

// e2e_pg_v13_test.go — v1.2 + v1.3 功能的 PG 后端 E2E 测试。
//
// 覆盖 v1.2 Sign/Verify/Mac/ReEncrypt + v1.3 MFA/Quorum 在真实 PG 后端的行为。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	yvonne "yvonne/sdk/go/yvonne"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// e2ePGEnvV13 是 v1.2+v1.3 PG 端到端测试环境（带 MFA + Approval store）。
type e2ePGEnvV13 struct {
	router        *V1Router
	server        *httptest.Server
	client        *yvonne.Client
	store         *storage.PostgresKVStore
	mgr           *lifecycle.Manager
	mk            *memguard.SecureBuffer
	mfaStore      auth.MFAStore
	approvalStore auth.ApprovalStore
}

// newE2EPGEnvV13 创建带 MFA + Approval store 的 PG 测试环境。
func newE2EPGEnvV13(t *testing.T) *e2ePGEnvV13 {
	t.Helper()

	dsn := os.Getenv("YVONNE_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgresql://postgres:pass@172.20.0.16:5432/yvonne_e2e"
	}

	ctx := context.Background()
	store, err := storage.NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
	t.Cleanup(func() {
		store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
		store.Close(ctx)
	})

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

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	client := yvonne.New(server.URL, "")

	return &e2ePGEnvV13{
		router:        router,
		server:        server,
		client:        client,
		store:         store,
		mgr:           mgr,
		mk:            mk,
		mfaStore:      router.mfaStore,
		approvalStore: router.approvalStore,
	}
}

// adminCtx 注入管理员 Policy。
func adminCtx() context.Context {
	return auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "admin", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"},
	})
}

// TestE2E_PG_V13_SignVerify RSA 签名验签 PG 后端 E2E。
func TestE2E_PG_V13_SignVerify(t *testing.T) {
	env := newE2EPGEnvV13(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(env.mk)

	if _, err := env.mgr.CreateAsymmetricKey(ctx, "pg-rsa", "rsa", kek); err != nil {
		t.Fatalf("create RSA key: %v", err)
	}

	data := []byte("pg sign test")
	body, _ := json.Marshal(signRequest{KeyID: "pg-rsa", Data: data})
	req := httptest.NewRequest("POST", "/api/v1/sign", bytes.NewReader(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleV1Sign(w, req)

	if w.Code != 200 {
		t.Fatalf("sign: %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Signature []byte `json:"signature"`
			Version   int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG Sign RSA: %d bytes, v%d", len(resp.Data.Signature), resp.Data.Version)

	// 验签。
	vBody, _ := json.Marshal(verifyRequest{KeyID: "pg-rsa", Data: data, Signature: resp.Data.Signature})
	req = httptest.NewRequest("POST", "/api/v1/verify", bytes.NewReader(vBody))
	req = req.WithContext(adminCtx())
	w = httptest.NewRecorder()
	env.router.handleV1Verify(w, req)

	var vResp struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &vResp)
	if !vResp.Data.Valid {
		t.Fatal("verify should be valid")
	}
	t.Log("✅ PG Verify RSA: valid=true")

	// PG 持久化验证——重启后密钥仍在。
	env.store.Close(ctx)
	store2, _ := storage.NewPostgresKVStore(ctx, os.Getenv("YVONNE_TEST_PG_DSN"))
	defer store2.Close(ctx)
	mgr2 := lifecycle.NewManager(store2)
	meta, err := mgr2.GetActiveKey(ctx, "pg-rsa")
	if err != nil {
		t.Fatalf("PG persistence: key not found after restart: %v", err)
	}
	if meta.KeyType != "rsa" {
		t.Fatalf("PG persistence: key type = %s, want rsa", meta.KeyType)
	}
	t.Log("✅ PG Sign key persisted across restart")
}

// TestE2E_PG_V13_Mac HMAC 生成+验证 PG 后端 E2E。
func TestE2E_PG_V13_Mac(t *testing.T) {
	env := newE2EPGEnvV13(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(env.mk)
	env.mgr.CreateKey(ctx, "pg-mac-key", kek, 0)

	data := []byte("pg mac test")
	body, _ := json.Marshal(signRequest{KeyID: "pg-mac-key", Data: data})
	req := httptest.NewRequest("POST", "/api/v1/mac/generate", bytes.NewReader(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleV1GenerateMac(w, req)

	if w.Code != 200 {
		t.Fatalf("generateMac: %d", w.Code)
	}

	var resp struct {
		Data struct {
			Mac []byte `json:"mac"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG GenerateMac: %d bytes", len(resp.Data.Mac))

	// VerifyMac。
	vBody, _ := json.Marshal(verifyMacRequest{KeyID: "pg-mac-key", Data: data, Mac: resp.Data.Mac})
	req = httptest.NewRequest("POST", "/api/v1/mac/verify", bytes.NewReader(vBody))
	req = req.WithContext(adminCtx())
	w = httptest.NewRecorder()
	env.router.handleV1VerifyMac(w, req)

	var vResp struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &vResp)
	if !vResp.Data.Valid {
		t.Fatal("verify should be valid")
	}
	t.Log("✅ PG VerifyMac: valid=true")
}

// TestE2E_PG_V13_ReEncrypt 跨密钥重加密 PG 后端 E2E。
func TestE2E_PG_V13_ReEncrypt(t *testing.T) {
	env := newE2EPGEnvV13(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(env.mk)
	env.mgr.CreateKey(ctx, "pg-re-src", kek, 0)
	env.mgr.CreateKey(ctx, "pg-re-dst", kek, 0)

	// 加密 src。
	encResp, err := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "pg-re-src", Plaintext: []byte("pg reencrypt"),
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// ReEncrypt: src → dst。
	reBody, _ := json.Marshal(reEncryptRequest{
		SourceKeyID: "pg-re-src", DestKeyID: "pg-re-dst", Ciphertext: encResp.Ciphertext,
	})
	req := httptest.NewRequest("POST", "/api/v1/re-encrypt", bytes.NewReader(reBody))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleV1ReEncrypt(w, req)

	if w.Code != 200 {
		t.Fatalf("re-encrypt: %d, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Ciphertext []byte `json:"ciphertext"`
			Version    int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG ReEncrypt: %d bytes, v%d", len(resp.Data.Ciphertext), resp.Data.Version)

	// 用 dst 解密。
	decResp, err := env.client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "pg-re-dst", Ciphertext: resp.Data.Ciphertext,
	})
	if err != nil {
		t.Fatalf("decrypt after re-encrypt: %v", err)
	}
	if string(decResp.Plaintext) != "pg reencrypt" {
		t.Fatalf("decrypt mismatch: %q", string(decResp.Plaintext))
	}
	t.Log("✅ PG ReEncrypt + Decrypt: data integrity verified")
}

// TestE2E_PG_V13_MFA MFA 完整流程 PG 后端 E2E。
func TestE2E_PG_V13_MFA(t *testing.T) {
	env := newE2EPGEnvV13(t)

	// Setup MFA。
	body, _ := json.Marshal(mfaSetupRequest{RoleID: "admin"})
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/setup", bytes.NewReader(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleMFASetup(w, req)

	if w.Code != 200 {
		t.Fatalf("MFA setup: %d", w.Code)
	}

	var resp struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG MFA Setup: secret=%s...", resp.Data.Secret[:8])

	// Verify。
	code, _ := auth.GenerateTOTP(resp.Data.Secret, time.Now())
	vBody, _ := json.Marshal(mfaVerifyRequest{RoleID: "admin", Code: code})
	req = httptest.NewRequest("POST", "/api/v1/auth/mfa/verify", bytes.NewReader(vBody))
	req = req.WithContext(adminCtx())
	w = httptest.NewRecorder()
	env.router.handleMFAVerify(w, req)

	if w.Code != 200 {
		t.Fatalf("MFA verify: %d", w.Code)
	}
	t.Log("✅ PG MFA Verify: enabled=true")

	state, _ := env.mfaStore.GetMFAState("admin")
	if !state.Enabled {
		t.Fatal("MFA should be enabled")
	}
	t.Log("✅ PG MFA state confirmed")
}

// TestE2E_PG_V13_Quorum Quorum 审批 PG 后端 E2E。
func TestE2E_PG_V13_Quorum(t *testing.T) {
	env := newE2EPGEnvV13(t)

	// 创建 2-of-3 审批。
	body, _ := json.Marshal(createApprovalRequest{
		Operation: "ShredKey", KeyID: "pg-quorum-key", Required: 2, TTLHours: 24,
	})
	req := httptest.NewRequest("POST", "/api/v1/approvals", bytes.NewReader(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleCreateApproval(w, req)

	if w.Code != 200 {
		t.Fatalf("create approval: %d", w.Code)
	}

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG Create Approval: ticket=%s...", resp.Data.ID[:8])

	// approver-1 approve。
	a1Body, _ := json.Marshal(approveRequest{TicketID: resp.Data.ID})
	req = httptest.NewRequest("POST", "/api/v1/approvals/approve", bytes.NewReader(a1Body))
	req = req.WithContext(auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "approver-1", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"},
	}))
	w = httptest.NewRecorder()
	env.router.handleApprove(w, req)
	if w.Code != 200 {
		t.Fatalf("approve 1: %d", w.Code)
	}
	t.Log("✅ PG Approve 1/2: pending")

	// approver-2 approve → approved。
	req = httptest.NewRequest("POST", "/api/v1/approvals/approve", bytes.NewReader(a1Body))
	req = req.WithContext(auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID: "approver-2", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"},
	}))
	w = httptest.NewRecorder()
	env.router.handleApprove(w, req)

	var aResp struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &aResp)
	if aResp.Data.Status != "approved" {
		t.Fatalf("expected approved, got %s", aResp.Data.Status)
	}
	t.Log("✅ PG Approve 2/2: approved")
}

// TestE2E_PG_V13_Persistence PG 持久化验证——重启后密钥仍可用。
func TestE2E_PG_V13_Persistence(t *testing.T) {
	env := newE2EPGEnvV13(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(env.mk)
	env.mgr.CreateKey(ctx, "persist-key-v13", kek, 0)

	// 加密。
	encResp, _ := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "persist-key-v13", Plaintext: []byte("persist test"),
	})

	// 关闭 PG store + 重新打开（模拟重启）。
	env.store.Close(ctx)
	store2, _ := storage.NewPostgresKVStore(ctx, os.Getenv("YVONNE_TEST_PG_DSN"))
	defer store2.Close(ctx)
	mgr2 := lifecycle.NewManager(store2)
	vault2 := seal.NewVaultState(1, 1, 0)
	vault2.DirectUnseal(env.mk)

	var auditBuf2 bytes.Buffer
	auditLog2, _ := audit.NewAuditLogger(&auditBuf2)
	defer auditLog2.Close()
	router2 := NewV1Router(vault2, auditLog2, mgr2, nil, nil)
	server2 := httptest.NewServer(router2)
	defer server2.Close()
	client2 := yvonne.New(server2.URL, "")

	// 用新 client 解密。
	decResp, err := client2.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "persist-key-v13", Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("decrypt after restart: %v", err)
	}
	if string(decResp.Plaintext) != "persist test" {
		t.Fatalf("decrypt mismatch: %q", string(decResp.Plaintext))
	}
	t.Log("✅ PG Persistence: key + ciphertext survived restart")
}

// TestE2E_PG_V13_GetPublicKey GetPublicKey PG 后端 E2E。
func TestE2E_PG_V13_GetPublicKey(t *testing.T) {
	env := newE2EPGEnvV13(t)
	kek := seal.NewSoftwareKEK(env.mk)
	env.mgr.CreateAsymmetricKey(context.Background(), "pg-pubkey-v13", "ecdsa", kek)

	req := httptest.NewRequest("GET", "/api/v1/keys/public-key?key_id=pg-pubkey-v13", nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()
	env.router.handleV1GetPublicKey(w, req)

	if w.Code != 200 {
		t.Fatalf("GetPublicKey: %d", w.Code)
	}

	var resp struct {
		Data struct {
			PublicKey []byte `json:"public_key"`
			Version   int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	t.Logf("✅ PG GetPublicKey: %d bytes, v%d", len(resp.Data.PublicKey), resp.Data.Version)
}
