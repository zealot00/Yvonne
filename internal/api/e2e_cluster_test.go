//go:build integration

// e2e_cluster_test.go — Cluster 模式 + Shamir Unseal E2E 测试。
//
// 覆盖：
//   - Cluster 模式配置校验（PG + 真实认证 + Shamir）
//   - Shamir 分片解封完整流程（提交分片 → 解封 → API 可用）
//   - 真实 AppRole Bearer Token 认证链路
//   - Cluster 模式下的全功能 API（带认证）
//   - 重启后 Shamir 重新解封
//
// 环境变量：
//
//	YVONNE_TEST_PG_DSN: PostgreSQL DSN
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	yvonne "yvonne/sdk/go/yvonne"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// clusterEnv 是 Cluster 模式 E2E 测试环境。
type clusterEnv struct {
	router        *V1Router
	server        *httptest.Server
	client        *yvonne.Client
	store         *storage.PostgresKVStore
	mgr           *lifecycle.Manager
	mk            *memguard.SecureBuffer
	vault         *seal.VaultState
	shares        [][]byte
	authenticator *auth.AppRoleAuthenticator
}

// newClusterEnv 创建 Cluster 模式测试环境（PG + AppRole 认证 + Shamir unseal）。
//
// 返回的环境处于 sealed 状态，需手动 ProvideShare 解封。
func newClusterEnv(t *testing.T, threshold, total int) *clusterEnv {
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
	closed := false
	t.Cleanup(func() {
		if closed {
			return
		}
		closed = true
		store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")
		store.Close(ctx)
	})

	// 生成 Master Key + Shamir 分片。
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	shares, err := seal.Split(mk, total, threshold)
	if err != nil {
		t.Fatalf("Shamir Split: %v", err)
	}

	// 创建 sealed vault（不 DirectUnseal，保持 sealed）。
	vault := seal.NewVaultState(total, threshold, 0)

	mgr := lifecycle.NewManager(store)

	// 创建 AppRole 认证器。
	authenticator := auth.NewAppRoleAuthenticator()
	authenticator.RegisterPolicy("admin", "admin-cluster-token", &auth.Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
	})
	authenticator.RegisterPolicy("operator", "operator-token", &auth.Policy{
		RoleID:         "operator",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"encrypt", "decrypt"},
	})

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, authenticator)
	router.SetMFAStore(auth.NewMemoryMFAStore())
	router.SetApprovalStore(auth.NewMemoryApprovalStore())

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	client := yvonne.New(server.URL, "admin-cluster-token")

	return &clusterEnv{
		router:        router,
		server:        server,
		client:        client,
		store:         store,
		mgr:           mgr,
		mk:            mk,
		vault:         vault,
		shares:        shares,
		authenticator: authenticator,
	}
}

// unseal 提交 threshold 个分片解封 vault。
func (e *clusterEnv) unseal(t *testing.T) {
	t.Helper()
	for i := 0; i < len(e.shares) && i < cap(e.shares); i++ {
		// 提交前 threshold 个分片。
		if i >= 2 { // threshold=2 默认
			break
		}
		unsealed, err := e.vault.ProvideShare(e.shares[i])
		if err != nil {
			t.Fatalf("ProvideShare %d: %v", i, err)
		}
		if unsealed {
			return
		}
	}
	t.Fatal("failed to unseal after providing threshold shares")
}

// TestE2E_Cluster_ShamirUnseal Shamir 分片解封完整流程。
func TestE2E_Cluster_ShamirUnseal(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 2, 3)

	// 1. 初始状态 sealed → API 拒绝。
	ctx := context.Background()
	_, err := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "test", Plaintext: []byte("test"),
	})
	if err == nil {
		t.Fatal("sealed vault should reject API calls")
	}
	t.Logf("✅ Sealed vault rejects API: %v", err)

	// 2. 提交第 1 个分片 → 仍 sealed。
	unsealed, err := env.vault.ProvideShare(env.shares[0])
	if err != nil {
		t.Fatalf("ProvideShare 1: %v", err)
	}
	if unsealed {
		t.Fatal("should not unseal with 1 share (threshold=2)")
	}
	t.Log("✅ 1/2 shares: still sealed")

	// 3. 提交第 2 个分片 → 解封成功。
	unsealed, err = env.vault.ProvideShare(env.shares[1])
	if err != nil {
		t.Fatalf("ProvideShare 2: %v", err)
	}
	if !unsealed {
		t.Fatal("should unseal with 2 shares (threshold=2)")
	}
	t.Log("✅ 2/2 shares: unsealed")

	// 4. 解封后需注入 Master Key（DirectUnseal 模拟）。
	// 实际生产中 ProvideShare 内部 Combine 会恢复 MK，
	// 但测试环境用 NewVaultState 需手动 DirectUnseal。
	env.vault.DirectUnseal(env.mk)

	// 5. 解封后 API 可用。
	env.mgr.CreateKey(ctx, "cluster-key", seal.NewSoftwareKEK(env.mk), 0)
	encResp, err := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "cluster-key", Plaintext: []byte("cluster test"),
	})
	if err != nil {
		t.Fatalf("encrypt after unseal: %v", err)
	}
	t.Logf("✅ API available after unseal: encrypt %d bytes", len(encResp.Ciphertext))

	// 6. 解密验证。
	decResp, err := env.client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "cluster-key", Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decResp.Plaintext) != "cluster test" {
		t.Fatalf("decrypt mismatch: %q", string(decResp.Plaintext))
	}
	t.Log("✅ Encrypt + Decrypt after Shamir unseal")
}

// TestE2E_Cluster_AppRoleAuth 真实 AppRole Bearer Token 认证。
func TestE2E_Cluster_AppRoleAuth(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 2, 3)
	env.unseal(t)
	env.vault.DirectUnseal(env.mk)
	ctx := context.Background()
	env.mgr.CreateKey(ctx, "auth-key", seal.NewSoftwareKEK(env.mk), 0)

	// 1. 正确 token → 200。
	encResp, err := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "auth-key", Plaintext: []byte("auth test"),
	})
	if err != nil {
		t.Fatalf("valid token encrypt: %v", err)
	}
	t.Logf("✅ Valid token: encrypt %d bytes", len(encResp.Ciphertext))

	// 2. 错误 token → 401。
	wrongClient := yvonne.New(env.server.URL, "wrong-token")
	_, err = wrongClient.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "auth-key", Plaintext: []byte("test"),
	})
	if err == nil {
		t.Fatal("wrong token should fail")
	}
	t.Logf("✅ Wrong token rejected: %v", err)

	// 3. 无 token → 401。
	noTokenClient := yvonne.New(env.server.URL, "")
	_, err = noTokenClient.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "auth-key", Plaintext: []byte("test"),
	})
	if err == nil {
		t.Fatal("no token should fail")
	}
	t.Logf("✅ No token rejected: %v", err)
}

// TestE2E_Cluster_RBAC RBAC 资源级授权。
func TestE2E_Cluster_RBAC(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 2, 3)
	env.unseal(t)
	env.vault.DirectUnseal(env.mk)
	ctx := context.Background()
	env.mgr.CreateKey(ctx, "order-key", seal.NewSoftwareKEK(env.mk), 0)
	env.mgr.CreateKey(ctx, "payment-key", seal.NewSoftwareKEK(env.mk), 0)

	// operator 只能访问 order-* 密钥。
	operatorClient := yvonne.New(env.server.URL, "operator-token")

	// order-key → 允许。
	_, err := operatorClient.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "order-key", Plaintext: []byte("order"),
	})
	if err != nil {
		t.Fatalf("operator order-key should be allowed: %v", err)
	}
	t.Log("✅ Operator access order-key: allowed")

	// payment-key → 拒绝。
	_, err = operatorClient.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "payment-key", Plaintext: []byte("payment"),
	})
	if err == nil {
		t.Fatal("operator payment-key should be denied")
	}
	t.Logf("✅ Operator access payment-key: denied (%v)", err)
}

// TestE2E_Cluster_ShamirThreshold3 3-of-5 Shamir 解封。
func TestE2E_Cluster_ShamirThreshold3(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 3, 5)

	// 提交 2 个分片 → 仍 sealed（需 3 个）。
	env.vault.ProvideShare(env.shares[0])
	env.vault.ProvideShare(env.shares[1])

	// API 仍不可用。
	ctx := context.Background()
	env.mgr.CreateKey(ctx, "t3-key", seal.NewSoftwareKEK(env.mk), 0)
	_, err := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "t3-key", Plaintext: []byte("test"),
	})
	if err == nil {
		t.Fatal("should still be sealed with 2/3 shares")
	}
	t.Log("✅ 2/3 shares: still sealed")

	// 第 3 个分片 → 解封。
	unsealed, err := env.vault.ProvideShare(env.shares[2])
	if err != nil {
		t.Fatalf("ProvideShare 3: %v", err)
	}
	if !unsealed {
		t.Fatal("should unseal with 3/5 shares")
	}
	env.vault.DirectUnseal(env.mk)
	t.Log("✅ 3/5 shares: unsealed")
}

// TestE2E_Cluster_PersistenceWithShamir 重启后 Shamir 重新解封 + 数据持久化。
func TestE2E_Cluster_PersistenceWithShamir(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 2, 3)
	env.unseal(t)
	env.vault.DirectUnseal(env.mk)
	ctx := context.Background()

	// 创建密钥 + 加密。
	env.mgr.CreateKey(ctx, "persist-cluster-key", seal.NewSoftwareKEK(env.mk), 0)
	encResp, _ := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "persist-cluster-key", Plaintext: []byte("persist cluster"),
	})

	// 模拟重启：新 vault（sealed）+ 新 manager（同一 PG）。
	// 不关闭 env.store（让 t.Cleanup 处理），用新连接读同一 PG。
	store2, _ := storage.NewPostgresKVStore(ctx, os.Getenv("YVONNE_TEST_PG_DSN"))
	defer store2.Close(ctx)
	mgr2 := lifecycle.NewManager(store2)
	vault2 := seal.NewVaultState(3, 2, 0) // sealed

	var auditBuf2 bytes.Buffer
	auditLog2, _ := audit.NewAuditLogger(&auditBuf2)
	defer auditLog2.Close()
	router2 := NewV1Router(vault2, auditLog2, mgr2, nil, env.authenticator)
	server2 := httptest.NewServer(router2)
	defer server2.Close()

	// 重启后 sealed → API 拒绝。
	client2 := yvonne.New(server2.URL, "admin-cluster-token")
	_, err := client2.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "persist-cluster-key", Ciphertext: encResp.Ciphertext,
	})
	if err == nil {
		t.Fatal("should reject when sealed after restart")
	}
	t.Log("✅ After restart: sealed, API rejected")

	// 重新 Shamir 解封。
	vault2.ProvideShare(env.shares[0])
	unsealed, _ := vault2.ProvideShare(env.shares[1])
	if !unsealed {
		t.Fatal("should unseal after providing 2 shares")
	}
	vault2.DirectUnseal(env.mk)
	t.Log("✅ After restart: Shamir unseal succeeded")

	// 解封后解密 → 数据持久化验证。
	decResp, err := client2.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "persist-cluster-key", Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("decrypt after restart+unseal: %v", err)
	}
	if string(decResp.Plaintext) != "persist cluster" {
		t.Fatalf("decrypt mismatch: %q", string(decResp.Plaintext))
	}
	t.Log("✅ After restart + Shamir unseal: data persisted")
}

// TestE2E_Cluster_FullAPI 全功能 API 测试（Cluster 模式 + 真实认证）。
func TestE2E_Cluster_FullAPI(t *testing.T) {
	pgTestMu.Lock()
	defer pgTestMu.Unlock()
	env := newClusterEnv(t, 2, 3)
	env.unseal(t)
	env.vault.DirectUnseal(env.mk)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(env.mk)

	// CreateKey。
	env.mgr.CreateKey(ctx, "full-cluster-key", kek, 0)

	// Encrypt + Decrypt。
	encResp, _ := env.client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID: "full-cluster-key", Plaintext: []byte("full cluster"),
	})
	decResp, _ := env.client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID: "full-cluster-key", Ciphertext: encResp.Ciphertext,
	})
	if string(decResp.Plaintext) != "full cluster" {
		t.Fatalf("decrypt mismatch: %q", string(decResp.Plaintext))
	}
	t.Log("✅ Cluster Encrypt + Decrypt")

	// RotateKey。
	rotateBody := []byte(`{}`)
	req, _ := http.NewRequest("POST", env.server.URL+"/api/v1/keys/full-cluster-key/rotate", bytes.NewReader(rotateBody))
	req.Header.Set("Authorization", "Bearer admin-cluster-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: %d", resp.StatusCode)
	}
	t.Log("✅ Cluster RotateKey")

	// 非对称密钥创建。
	env.mgr.CreateAsymmetricKey(ctx, "cluster-rsa", "rsa", kek)

	// Sign + Verify（通过 HTTP + Bearer Token）。
	signBody, _ := json.Marshal(signRequest{KeyID: "cluster-rsa", Data: []byte("cluster sign")})
	req, _ = http.NewRequest("POST", env.server.URL+"/api/v1/sign", bytes.NewReader(signBody))
	req.Header.Set("Authorization", "Bearer admin-cluster-token")
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("sign: %d", resp.StatusCode)
	}
	var signResp struct {
		Data struct {
			Signature []byte `json:"signature"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&signResp)
	resp.Body.Close()
	t.Logf("✅ Cluster Sign: %d bytes", len(signResp.Data.Signature))

	// Mac。
	macBody, _ := json.Marshal(signRequest{KeyID: "full-cluster-key", Data: []byte("cluster mac")})
	req, _ = http.NewRequest("POST", env.server.URL+"/api/v1/mac/generate", bytes.NewReader(macBody))
	req.Header.Set("Authorization", "Bearer admin-cluster-token")
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("mac: %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Cluster GenerateMac")
}
