// v1.2.2 service 层 Sign/Verify 单元测试。
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newSignTestCore 创建测试 Core + 已注册的密钥。
func newSignTestCore(t *testing.T) (*Core, *lifecycle.Manager) {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)
	kek := seal.NewSoftwareKEK(mk)

	// 创建 RSA 密钥。
	if _, err := mgr.CreateAsymmetricKey(context.Background(), "rsa-key", "rsa", kek); err != nil {
		t.Fatalf("create RSA key: %v", err)
	}
	// 创建 ECDSA 密钥。
	if _, err := mgr.CreateAsymmetricKey(context.Background(), "ecdsa-key", "ecdsa", kek); err != nil {
		t.Fatalf("create ECDSA key: %v", err)
	}
	// 创建对称密钥（用于错误路径测试）。
	if _, _, err := mgr.CreateKey(context.Background(), "sym-key", kek, 0); err != nil {
		t.Fatalf("create symmetric key: %v", err)
	}

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	core := NewCore(mgr, vault, auditLog)
	return core, mgr
}

// TestSign_Verify_RSA RSA 签名 + 验签往返。
func TestSign_Verify_RSA(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()
	data := []byte("hello RSA signing")

	// 1. 签名。
	result, err := core.Sign(ctx, "rsa-key", data, nil)
	if err != nil {
		t.Fatalf("Sign RSA: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Fatal("signature should not be empty")
	}
	t.Logf("✅ RSA Sign: %d bytes signature, v%d", len(result.Signature), result.Version)

	// 2. 验签（正确数据）。
	verifyResult, err := core.Verify(ctx, "rsa-key", data, result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify RSA: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("RSA signature should be valid")
	}
	t.Log("✅ RSA Verify: valid=true")

	// 3. 验签（篡改数据）。
	wrongData := []byte("tampered data")
	wrongResult, err := core.Verify(ctx, "rsa-key", wrongData, result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify RSA wrong data: %v", err)
	}
	if wrongResult.Valid {
		t.Fatal("RSA signature should be invalid for tampered data")
	}
	t.Log("✅ RSA Verify (tampered): valid=false")
}

// TestSign_Verify_ECDSA ECDSA 签名 + 验签往返。
func TestSign_Verify_ECDSA(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()
	data := []byte("hello ECDSA signing")

	// 1. 签名。
	result, err := core.Sign(ctx, "ecdsa-key", data, nil)
	if err != nil {
		t.Fatalf("Sign ECDSA: %v", err)
	}
	t.Logf("✅ ECDSA Sign: %d bytes signature", len(result.Signature))

	// 2. 验签（正确）。
	verifyResult, err := core.Verify(ctx, "ecdsa-key", data, result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify ECDSA: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("ECDSA signature should be valid")
	}
	t.Log("✅ ECDSA Verify: valid=true")

	// 3. 验签（错误签名）。
	fakeSig := make([]byte, 64)
	wrongResult, err := core.Verify(ctx, "ecdsa-key", data, fakeSig, nil)
	if err != nil {
		t.Fatalf("Verify ECDSA wrong sig: %v", err)
	}
	if wrongResult.Valid {
		t.Fatal("ECDSA should reject fake signature")
	}
	t.Log("✅ ECDSA Verify (fake sig): valid=false")
}

// TestSign_SymmetricKeyRejected 对称密钥签名被拒绝。
func TestSign_SymmetricKeyRejected(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()

	_, err := core.Sign(ctx, "sym-key", []byte("test"), nil)
	if err == nil {
		t.Fatal("Sign with symmetric key should fail")
	}
	t.Logf("✅ Symmetric key sign rejected: %v", err)
}

// TestSign_NonexistentKey 不存在的密钥。
func TestSign_NonexistentKey(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()

	_, err := core.Sign(ctx, "nonexistent", []byte("test"), nil)
	if err == nil {
		t.Fatal("Sign with nonexistent key should fail")
	}
	t.Log("✅ Nonexistent key sign rejected")
}

// TestSign_EmptyData 空数据签名。
func TestSign_EmptyData(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()

	// 空数据应能签名（SHA256 of empty is valid）。
	result, err := core.Sign(ctx, "rsa-key", []byte{}, nil)
	if err != nil {
		t.Fatalf("Sign empty data should succeed: %v", err)
	}

	// 验签也应通过。
	verifyResult, err := core.Verify(ctx, "rsa-key", []byte{}, result.Signature, nil)
	if err != nil {
		t.Fatalf("Verify empty data: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatal("empty data signature should be valid")
	}
	t.Log("✅ Empty data sign + verify passed")
}

// TestSign_DigestConsistency 验证服务端用 SHA-256 哈希。
func TestSign_DigestConsistency(t *testing.T) {
	core, _ := newSignTestCore(t)
	ctx := context.Background()
	data := []byte("digest test")

	result, err := core.Sign(ctx, "ecdsa-key", data, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// 手动验证：用 crypto 包直接验签，确认 digest = SHA256(data)。
	mgr := core.manager
	meta, _ := mgr.GetActiveKey(ctx, "ecdsa-key")

	// 解析公钥。
	pubKey, err := crypto.ParsePublicKeyFromPEM(meta.PublicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	digest := sha256.Sum256(data)
	if err := crypto.Verify(pubKey, digest[:], result.Signature); err != nil {
		t.Fatalf("manual verify with SHA256 digest failed: %v", err)
	}
	t.Log("✅ Digest consistency: service uses SHA-256")
}
