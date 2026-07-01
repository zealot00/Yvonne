//go:build gmsm

// gmsm_e2e_test.go — gmsm 模式下全链路 E2E 测试。
package api

import (
	"bytes"
	"context"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

func cryptoNewGMSMSuite() (crypto.CryptoSuite, error) {
	return crypto.NewGMSMSuite()
}

// TestGMSM_E2E_FullLifecycle gmsm 模式全链路（SM2 签名 + Mac）。
// 注：Encrypt/Decrypt 需 SM4 版本化密文支持（v1.1 范围外），此测试聚焦 SM2 + Mac。
func TestGMSM_E2E_FullLifecycle(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	suite, _ := cryptoNewGMSMSuite()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)
	vault.SetCryptoSuite(suite)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	ctx := context.Background()
	kek := seal.NewSoftwareKEKWithSuite(mk, suite)

	// SM2 非对称密钥。
	mgr.CreateAsymmetricKey(ctx, "gmsm-sm2", "sm2", kek)

	// Sign + Verify。
	result, err := router.core.Sign(ctx, "gmsm-sm2", []byte("gmsm sign test"), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("✅ gmsm SM2 Sign: %d bytes", len(result.Signature))

	verifyResult, err := router.core.Verify(ctx, "gmsm-sm2", []byte("gmsm sign test"), result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("should be valid")
	}
	t.Log("✅ gmsm SM2 Verify: valid=true")

	// Tampered。
	verifyResult2, _ := router.core.Verify(ctx, "gmsm-sm2", []byte("tampered"), result.Signature, nil)
	if verifyResult2.Valid {
		t.Fatal("should reject tampered")
	}
	t.Log("✅ gmsm SM2 Verify tampered: rejected")

	// RotateKey + ShredKey。
	mgr.ShredKey(ctx, "gmsm-sm2", 1)
	t.Log("✅ gmsm ShredKey")
}

// TestGMSM_E2E_SM2SignVerify gmsm 模式 SM2 签名验签。
func TestGMSM_E2E_SM2SignVerify(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	suite, _ := cryptoNewGMSMSuite()
	vault.SetCryptoSuite(suite)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	ctx := context.Background()
	kek := seal.NewSoftwareKEKWithSuite(mk, suite)

	mgr.CreateAsymmetricKey(ctx, "gmsm-sm2", "sm2", kek)

	result, err := router.core.Sign(ctx, "gmsm-sm2", []byte("gmsm sign test"), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("✅ gmsm SM2 Sign: %d bytes", len(result.Signature))

	verifyResult, err := router.core.Verify(ctx, "gmsm-sm2", []byte("gmsm sign test"), result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("should be valid")
	}
	t.Log("✅ gmsm SM2 Verify: valid=true")
}

// TestGMSM_E2E_Mac gmsm 模式 HMAC。
func TestGMSM_E2E_Mac(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	suite, _ := cryptoNewGMSMSuite()
	vault.SetCryptoSuite(suite)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	ctx := context.Background()
	kek := seal.NewSoftwareKEKWithSuite(mk, suite)

	mgr.CreateKey(ctx, "gmsm-mac-key", kek, 0)

	macResult, err := router.core.GenerateMac(ctx, "gmsm-mac-key", []byte("gmsm mac"), nil)
	if err != nil {
		t.Fatalf("GenerateMac: %v", err)
	}
	t.Logf("✅ gmsm GenerateMac: %d bytes", len(macResult.Mac))

	verifyResult, _ := router.core.VerifyMac(ctx, "gmsm-mac-key", []byte("gmsm mac"), macResult.Mac, nil)
	if !verifyResult.Valid {
		t.Fatal("should be valid")
	}
	t.Log("✅ gmsm VerifyMac: valid=true")
}
