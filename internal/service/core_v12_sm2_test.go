//go:build gmsm

// v1.2.2 SM2 签名/验签测试（gmsm 构建标签）。
package service

import (
	"bytes"
	"context"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestSign_Verify_SM2 SM2 签名 + 验签往返。
func TestSign_Verify_SM2(t *testing.T) {
	// 自建完整环境（与 newSignTestCore 一致，但创建 SM2 密钥）。
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)
	kek := seal.NewSoftwareKEK(mk)

	if _, err := mgr.CreateAsymmetricKey(context.Background(), "sm2-key", "sm2", kek); err != nil {
		t.Fatalf("create SM2 key: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)
	core := NewCore(mgr, vault, auditLog)

	ctx := context.Background()
	data := []byte("hello SM2 signing")

	// 1. 签名。
	result, err := core.Sign(ctx, "sm2-key", data, nil)
	if err != nil {
		t.Fatalf("Sign SM2: %v", err)
	}
	t.Logf("✅ SM2 Sign: %d bytes signature", len(result.Signature))

	// 2. 验签（正确）。
	verifyResult, err := core.Verify(ctx, "sm2-key", data, result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify SM2: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("SM2 signature should be valid")
	}
	t.Log("✅ SM2 Verify: valid=true")

	// 3. 验签（篡改数据）。
	wrongResult, err := core.Verify(ctx, "sm2-key", []byte("wrong"), result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify SM2 wrong: %v", err)
	}
	if wrongResult.Valid {
		t.Fatal("SM2 should reject tampered data")
	}
	t.Log("✅ SM2 Verify (tampered): valid=false")
}
