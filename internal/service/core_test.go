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

// newTestCore 创建测试用 Core 实例。
func newTestCore(t *testing.T) (*Core, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	vault := seal.NewVaultState(1, 1, 0)
	if err := vault.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	var buf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&buf)
	t.Cleanup(auditLog.Close)

	core := NewManager(mgr, vault, auditLog)
	return core, mgr, mk
}

// TestCore_EncryptDecrypt 往返测试。
func TestCore_EncryptDecrypt(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	// 创建 key（直接用 manager 绕过 Core 的授权）。
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	plaintext := []byte("hello service core")

	// Encrypt（nil policy = Dev 模式放行）。
	encResult, err := core.Encrypt(ctx, "test-key", plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encResult.Version != 1 {
		t.Fatalf("version = %d, want 1", encResult.Version)
	}
	if len(encResult.Ciphertext) == 0 {
		t.Fatal("ciphertext empty")
	}

	// Decrypt。
	decResult, err := core.Decrypt(ctx, "test-key", encResult.Ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	defer decResult.Plaintext.Wipe()

	var got []byte
	_ = decResult.Plaintext.WithKey(func(d []byte) error {
		got = make([]byte, len(d))
		copy(got, d)
		return nil
	})
	defer func() {
		for i := range got {
			got[i] = 0
		}
	}()

	if !bytes.Equal(plaintext, got) {
		t.Fatal("plaintext mismatch")
	}
}

// TestCore_SealedRefused Sealed 状态下操作被拒。
func TestCore_SealedRefused(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	// 不解封直接操作。
	_, err := core.Encrypt(ctx, "any-key", []byte("x"), nil)
	if err == nil {
		t.Fatal("Encrypt on sealed vault should fail")
	}
}

// TestCore_AuthorizeDenied Policy 拒绝。
func TestCore_AuthorizeDenied(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "secret-key", seal.NewSoftwareKEK(mk), 0)

	// Policy 只允许 "allowed-key"。
	policy := &auth.Policy{
		RoleID:         "test-role",
		AllowedKeys:    []string{"allowed-key"},
		AllowedActions: []string{"Encrypt"},
	}

	_, err := core.Encrypt(ctx, "secret-key", []byte("x"), policy)
	if err == nil {
		t.Fatal("Encrypt with denied key should fail")
	}
}
