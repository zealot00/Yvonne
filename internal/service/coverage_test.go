// Package service - 补充覆盖测试（ClearCache + GenerateMac + VerifyMac + GDKWithoutPlaintext + ReEncrypt）。
package service

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

// newCovTestCore 创建测试 Core + 密钥。
func newCovTestCore(t *testing.T) (*Core, *lifecycle.Manager, *memguard.SecureBuffer) {
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

	core := NewCore(mgr, vault, auditLog)

	// 创建对称密钥。
	kek := seal.NewSoftwareKEK(mk)
	mgr.CreateKey(context.Background(), "cov-sym", kek, 0)
	mgr.CreateKey(context.Background(), "cov-sym2", kek, 0)
	// 创建非对称密钥。
	mgr.CreateAsymmetricKey(context.Background(), "cov-rsa", "rsa", kek)

	return core, mgr, mk
}

// TestServiceCov_ClearCache ClearCache。
func TestServiceCov_ClearCache(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	core.ClearCache() // 应不 panic
	t.Log("✅ ClearCache")
}

// TestServiceCov_GenerateMac GenerateMac service 层。
func TestServiceCov_GenerateMac(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()
	data := []byte("mac service test")

	result, err := core.GenerateMac(ctx, "cov-sym", data, nil)
	if err != nil {
		t.Fatalf("GenerateMac: %v", err)
	}
	if len(result.Mac) == 0 {
		t.Fatal("mac should not be empty")
	}
	t.Logf("✅ service.GenerateMac: %d bytes", len(result.Mac))
}

// TestServiceCov_VerifyMac VerifyMac service 层。
func TestServiceCov_VerifyMac(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()
	data := []byte("verify mac test")

	// 先生成。
	macResult, _ := core.GenerateMac(ctx, "cov-sym", data, nil)

	// 验证。
	verifyResult, err := core.VerifyMac(ctx, "cov-sym", data, macResult.Mac, nil)
	if err != nil {
		t.Fatalf("VerifyMac: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("should be valid")
	}
	t.Log("✅ service.VerifyMac: valid=true")

	// 错误数据。
	wrongResult, _ := core.VerifyMac(ctx, "cov-sym", []byte("wrong"), macResult.Mac, nil)
	if wrongResult.Valid {
		t.Fatal("should be invalid for wrong data")
	}
	t.Log("✅ service.VerifyMac wrong: valid=false")
}

// TestServiceCov_GDKWithoutPlaintext GenerateDataKeyWithoutPlaintext。
func TestServiceCov_GDKWithoutPlaintext(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	ct, err := core.GenerateDataKeyWithoutPlaintext(ctx, "cov-sym", nil)
	if err != nil {
		t.Fatalf("GDKWithoutPlaintext: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}
	t.Logf("✅ service.GDKWithoutPlaintext: %d bytes", len(ct))
}

// TestServiceCov_ReEncrypt ReEncrypt service 层。
func TestServiceCov_ReEncrypt(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	// 加密 src。
	encResult, _ := core.Encrypt(ctx, "cov-sym", []byte("reencrypt test"), nil)

	// ReEncrypt: cov-sym → cov-sym2。
	reResult, err := core.ReEncrypt(ctx, "cov-sym", encResult.Ciphertext, "cov-sym2", nil)
	if err != nil {
		t.Fatalf("ReEncrypt: %v", err)
	}
	if len(reResult.Ciphertext) == 0 {
		t.Fatal("ciphertext should not be empty")
	}
	t.Logf("✅ service.ReEncrypt: %d bytes", len(reResult.Ciphertext))

	// 解密验证数据一致。
	decResult, _ := core.Decrypt(ctx, "cov-sym2", reResult.Ciphertext, nil)
	decResult.Plaintext.WithKey(func(d []byte) error {
		if string(d) != "reencrypt test" {
			t.Fatalf("decrypt mismatch: %q", string(d))
		}
		return nil
	})
	decResult.Plaintext.Wipe()
	t.Log("✅ service.ReEncrypt + Decrypt: data integrity verified")
}

// TestServiceCov_GetPublicKey GetPublicKey service 层。
func TestServiceCov_GetPublicKey(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	pub, version, err := core.GetPublicKey(ctx, "cov-rsa", nil)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if len(pub) == 0 {
		t.Fatal("public key should not be empty")
	}
	if version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
	t.Logf("✅ service.GetPublicKey: %d bytes", len(pub))
}

// TestServiceCov_DisableKey DisableKey service 层。
func TestServiceCov_DisableKey(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	err := core.DisableKey(ctx, "cov-sym", nil)
	if err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	t.Log("✅ service.DisableKey")
}

// TestServiceCov_EnableKey EnableKey service 层。
func TestServiceCov_EnableKey(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	// 先 Disable。
	core.DisableKey(ctx, "cov-sym", nil)
	// 再 Enable。
	err := core.EnableKey(ctx, "cov-sym", 1, nil)
	if err != nil {
		t.Fatalf("EnableKey: %v", err)
	}
	t.Log("✅ service.EnableKey")
}

// TestServiceCov_CancelKeyDeletion CancelKeyDeletion。
func TestServiceCov_CancelKeyDeletion(t *testing.T) {
	core, _, _ := newCovTestCore(t)
	ctx := context.Background()

	core.DisableKey(ctx, "cov-sym", nil)
	err := core.CancelKeyDeletion(ctx, "cov-sym", 1, nil)
	if err != nil {
		t.Fatalf("CancelKeyDeletion: %v", err)
	}
	t.Log("✅ service.CancelKeyDeletion")
}

// 确保 auth 引用。
var _ = auth.Policy{}
