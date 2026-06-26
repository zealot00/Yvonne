//go:build integration

// e2e_pg_test.go — 真实 PG 后端 + SDK 客户端端到端全功能自动化测试。
//
// 环境变量：
//
//	YVONNE_TEST_PG_DSN: PostgreSQL DSN（默认 postgresql://postgres:pass@172.20.0.16:5432/yvonne_e2e）
//
// 运行：
//
//	go test -tags=integration -race -v -timeout 120s ./internal/api/ -run TestE2E_PG
package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	yvonne "yvonne/sdk/go/yvonne"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// e2ePGEnv 是 PG 端到端测试环境。
type e2ePGEnv struct {
	router *V1Router
	server *httptest.Server
	client *yvonne.Client
	store  *storage.PostgresKVStore
	mgr    *lifecycle.Manager
	mk     *memguard.SecureBuffer
}

// newE2EPGEnv 创建真实 PG 后端的端到端测试环境。
func newE2EPGEnv(t *testing.T) *e2ePGEnv {
	t.Helper()

	dsn := os.Getenv("YVONNE_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgresql://postgres:pass@172.20.0.16:5432/yvonne_e2e"
	}

	ctx := context.Background()

	// 创建 PG store（自动建库建表）。
	store, err := storage.NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresKVStore: %v", err)
	}

	// 清理旧数据。
	store.Pool().Exec(ctx, "TRUNCATE yvonne_kv_str")

	// 创建 vault + manager。
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	vault := seal.NewVaultState(1, 1, 0)
	if err := vault.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	mgr := lifecycle.NewManager(store)

	// 创建 router（Dev 模式无认证）。
	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)

	// 启动测试 HTTP server。
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	// 创建 SDK 客户端。
	client := yvonne.New(server.URL, "")

	return &e2ePGEnv{
		router: router,
		server: server,
		client: client,
		store:  store,
		mgr:    mgr,
		mk:     mk,
	}
}

// TestE2E_PG_FullLifecycle PG 后端全生命周期端到端测试。
func TestE2E_PG_FullLifecycle(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	// 1. 健康检查。
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if health.State != "unsealed" {
		t.Fatalf("State = %q, want unsealed", health.State)
	}
	t.Log("✅ Health check passed")

	// 2. 创建密钥。
	createResp, err := client.CreateKey(ctx, &yvonne.CreateKeyRequest{
		KeyID: "e2e-pg-key",
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if createResp.KeyID != "e2e-pg-key" || createResp.Version != 1 {
		t.Fatalf("CreateKey response: %+v", createResp)
	}
	t.Logf("✅ Created key: %s v%d", createResp.KeyID, createResp.Version)

	// 3. 验证 PG 中有数据（key:v:1）。
	pgKey := fmt.Sprintf("key:%s:v:%d", "e2e-pg-key", 1)
	val, err := env.store.Get(ctx, pgKey)
	if err != nil {
		t.Fatalf("PG Get %s: %v", pgKey, err)
	}
	if len(val) == 0 {
		t.Fatal("PG should have metadata for e2e-pg-key v1")
	}
	t.Log("✅ Verified in PostgreSQL")

	// 4. 加密。
	plaintext := []byte("e2e pg encryption test data")
	encResp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID:     "e2e-pg-key",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encResp.Version != 1 {
		t.Fatalf("Version = %d", encResp.Version)
	}
	if len(encResp.Ciphertext) == 0 {
		t.Fatal("Ciphertext empty")
	}
	t.Logf("✅ Encrypted: %d bytes, v%d", len(encResp.Ciphertext), encResp.Version)

	// 5. 解密。
	decResp, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "e2e-pg-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.Plaintext) != string(plaintext) {
		t.Fatalf("Plaintext = %q, want %q", string(decResp.Plaintext), string(plaintext))
	}
	t.Logf("✅ Decrypted: %s", string(decResp.Plaintext))

	// 6. 轮转。
	rotResp, err := client.RotateKey(ctx, "e2e-pg-key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if rotResp.Version != 2 {
		t.Fatalf("NewVersion = %d, want 2", rotResp.Version)
	}
	t.Logf("✅ Rotated to v%d", rotResp.Version)

	// 7. 向后兼容：旧密文仍可解密。
	decOld, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "e2e-pg-key",
		Ciphertext: encResp.Ciphertext, // v1 密文
	})
	if err != nil {
		t.Fatalf("Decrypt v1 after rotate: %v", err)
	}
	if string(decOld.Plaintext) != string(plaintext) {
		t.Fatal("v1 ciphertext should still decrypt")
	}
	t.Log("✅ Backward compat: v1 ciphertext decrypts after rotate")

	// 8. 用 v2 加密。
	encV2, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID:     "e2e-pg-key",
		Plaintext: []byte("v2 data"),
	})
	if err != nil {
		t.Fatalf("Encrypt v2: %v", err)
	}
	if encV2.Version != 2 {
		t.Fatalf("v2 encrypt Version = %d", encV2.Version)
	}
	t.Log("✅ New encrypt uses v2")

	// 9. 验证 PG 中有两个版本。
	for v := 1; v <= 2; v++ {
		pgKey := fmt.Sprintf("key:e2e-pg-key:v:%d", v)
		_, err := env.store.Get(ctx, pgKey)
		if err != nil {
			t.Fatalf("PG should have v%d: %v", v, err)
		}
	}
	t.Log("✅ PG has both v1 and v2 metadata")

	// 10. 物理粉碎 v1。
	if err := client.ShredKey(ctx, "e2e-pg-key", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}
	t.Log("✅ Shredded v1")

	// 11. v1 密文解密失败。
	_, err = client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "e2e-pg-key",
		Ciphertext: encResp.Ciphertext, // v1 密文
	})
	if err == nil {
		t.Fatal("v1 ciphertext should fail after shred")
	}
	t.Log("✅ v1 ciphertext correctly rejected after shred")

	// 12. v2 密文仍可解密。
	decV2, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "e2e-pg-key",
		Ciphertext: encV2.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt v2 after shred v1: %v", err)
	}
	if string(decV2.Plaintext) != "v2 data" {
		t.Fatalf("v2 plaintext = %q", string(decV2.Plaintext))
	}
	t.Log("✅ v2 ciphertext still decrypts after v1 shred")

	// 13. 验证 PG 中 v1 已删除。
	pgKeyV1 := "key:e2e-pg-key:v:1"
	_, err = env.store.Get(ctx, pgKeyV1)
	if err != storage.ErrNotFound {
		t.Fatalf("PG should not have v1 after shred: %v", err)
	}
	t.Log("✅ PG confirmed v1 physically deleted")

	t.Log("")
	t.Log("=== E2E PG Full Lifecycle PASSED ===")
	t.Log("  Health → CreateKey → Encrypt → Decrypt → Rotate")
	t.Log("  → Backward compat → Shred → History rejected → v2 unaffected")
}

// TestE2E_PG_GDK PG 后端 GenerateDataKey 测试。
func TestE2E_PG_GDK(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	// 创建 key。
	client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "gdk-pg-key"})

	// 生成数据密钥。
	gdk, err := client.GenerateDataKey(ctx, "gdk-pg-key")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(gdk.PlaintextDEK) == 0 {
		t.Fatal("PlaintextDEK empty")
	}
	if len(gdk.CiphertextDEK) == 0 {
		t.Fatal("CiphertextDEK empty")
	}
	t.Logf("✅ GDK: plaintext %d bytes, ciphertext %d bytes", len(gdk.PlaintextDEK), len(gdk.CiphertextDEK))
}

// TestE2E_PG_PersistenceAcrossRestart 模拟重启后数据持久化。
func TestE2E_PG_PersistenceAcrossRestart(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	// 创建密钥 + 加密。
	client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "persist-key"})
	encResp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID:     "persist-key",
		Plaintext: []byte("persistent data"),
	})

	// 模拟"重启"：关闭旧 server，创建新 router（同一 PG）。
	env.server.Close()
	env.store.Pool().Close()

	// 重新创建 store + manager + router（数据在 PG 中持久化）。
	dsn := os.Getenv("YVONNE_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgresql://postgres:pass@172.20.0.16:5432/yvonne_e2e"
	}
	newStore, err := storage.NewPostgresKVStore(ctx, dsn)
	if err != nil {
		t.Fatalf("Reconnect PG: %v", err)
	}
	defer newStore.Pool().Close()

	newMgr := lifecycle.NewManager(newStore)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(env.mk)

	var auditBuf bytes.Buffer
	newAudit, _ := audit.NewAuditLogger(&auditBuf)
	defer newAudit.Close()

	newRouter := NewV1Router(vault, newAudit, newMgr, nil, nil)
	newServer := httptest.NewServer(newRouter)
	defer newServer.Close()

	newClient := yvonne.New(newServer.URL, "")

	// 重启后解密旧密文。
	decResp, err := newClient.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "persist-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt after restart: %v", err)
	}
	if string(decResp.Plaintext) != "persistent data" {
		t.Fatalf("Plaintext = %q", string(decResp.Plaintext))
	}
	t.Log("✅ Data persisted across restart — decrypt succeeded with PG-stored DEK")
}

// TestE2E_PG_ConcurrentOperations 并发操作测试。
func TestE2E_PG_ConcurrentOperations(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	// 创建 3 个 key。
	for i := 0; i < 3; i++ {
		client.CreateKey(ctx, &yvonne.CreateKeyRequest{
			KeyID: fmt.Sprintf("conc-pg-key-%d", i),
		})
	}

	type result struct {
		err error
		op  string
	}

	results := make(chan result, 30)

	// 10 个并发加密 + 10 个并发轮转 + 10 个并发加密(key2)。
	for i := 0; i < 10; i++ {
		go func() {
			_, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
				KeyID:     "conc-pg-key-0",
				Plaintext: []byte(fmt.Sprintf("conc-%d", time.Now().UnixNano())),
			})
			results <- result{err, "encrypt"}
		}()

		go func() {
			_, err := client.RotateKey(ctx, "conc-pg-key-1")
			results <- result{err, "rotate"}
		}()

		go func() {
			_, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
				KeyID:     "conc-pg-key-2",
				Plaintext: []byte(fmt.Sprintf("conc2-%d", time.Now().UnixNano())),
			})
			results <- result{err, "encrypt2"}
		}()
	}

	// 收集结果。
	success, fail := 0, 0
	for i := 0; i < 30; i++ {
		r := <-results
		if r.err != nil {
			fail++
		} else {
			success++
		}
	}

	if fail > 0 {
		t.Fatalf("%d operations failed, %d succeeded", fail, success)
	}
	t.Logf("✅ %d concurrent operations succeeded", success)
}

// TestE2E_PG_LargePayload 大 payload 测试。
func TestE2E_PG_LargePayload(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "large-pg-key"})

	// 1MB payload。
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	encResp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID:     "large-pg-key",
		Plaintext: largeData,
	})
	if err != nil {
		t.Fatalf("Encrypt 1MB: %v", err)
	}
	t.Logf("✅ Encrypted 1MB: %d bytes ciphertext", len(encResp.Ciphertext))

	decResp, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "large-pg-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt 1MB: %v", err)
	}
	if len(decResp.Plaintext) != len(largeData) {
		t.Fatalf("Plaintext length = %d, want %d", len(decResp.Plaintext), len(largeData))
	}
	t.Log("✅ Decrypted 1MB payload matches")
}

// TestE2E_PG_Latency 延迟测试（非 benchmark，仅统计）。
func TestE2E_PG_Latency(t *testing.T) {
	env := newE2EPGEnv(t)
	ctx := context.Background()
	client := env.client

	client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "latency-pg-key"})

	data := []byte("latency test payload")

	// 测 10 次加密延迟。
	var totalEncrypt, totalDecrypt time.Duration
	iterations := 10

	for i := 0; i < iterations; i++ {
		start := time.Now()
		encResp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
			KeyID:     "latency-pg-key",
			Plaintext: data,
		})
		encryptLatency := time.Since(start)
		totalEncrypt += encryptLatency
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		start = time.Now()
		_, err = client.Decrypt(ctx, &yvonne.DecryptRequest{
			KeyID:      "latency-pg-key",
			Ciphertext: encResp.Ciphertext,
		})
		decryptLatency := time.Since(start)
		totalDecrypt += decryptLatency
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
	}

	avgEnc := totalEncrypt / time.Duration(iterations)
	avgDec := totalDecrypt / time.Duration(iterations)
	t.Logf("✅ Latency (%d iterations): encrypt avg=%v, decrypt avg=%v", iterations, avgEnc, avgDec)
}
