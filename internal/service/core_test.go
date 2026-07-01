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

// mockAlerter 记录告警事件（Bug-6 测试）。
type mockAlerter struct {
	alerts []struct {
		operation string
		resource  string
		desc      string
	}
}

func (m *mockAlerter) Alert(ctx context.Context, operation, resource, desc string) error {
	m.alerts = append(m.alerts, struct {
		operation string
		resource  string
		desc      string
	}{operation, resource, desc})
	return nil
}

// TestCore_KEKFailureTriggersAlert Bug-6: KEK 解密失败触发 CRITICAL 告警。
// 用一个会失败的 KEK 包装解密，验证 alerter 被调用。
func TestCore_KEKFailureTriggersAlert(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	// 注入 mock alerter。
	al := &mockAlerter{}
	core.SetAlerter(al)

	// 用 core 的 vault master key 创建密钥（保证加密能成功）。
	kek := seal.NewSoftwareKEK(mk)
	_, _, err := mgr.CreateKey(ctx, "alert-test-key", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 用一个不同的 MasterKey 创建另一个 vault（模拟 HSM 离线/MasterKey 损坏）。
	wrongMK, _ := memguard.NewSecureBufferFromRandom(32)
	defer wrongMK.Wipe()

	wrongVault := seal.NewVaultState(1, 1, 0)
	if err := wrongVault.DirectUnseal(wrongMK); err != nil {
		t.Fatalf("DirectUnseal wrong: %v", err)
	}
	wrongCore := NewCore(mgr, wrongVault, nil)
	wrongCore.SetAlerter(al)

	// 先用正确 KEK 加密。
	encResult, err := core.Encrypt(ctx, "alert-test-key", []byte("test"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 用错误 KEK 的 Core 解密 → KEK.UnwrapDEK 失败 → 触发告警。
	_, err = wrongCore.Decrypt(ctx, "alert-test-key", encResult.Ciphertext, nil)
	if err == nil {
		t.Fatal("Decrypt with wrong KEK should fail")
	}

	// 验证告警被触发。
	if len(al.alerts) == 0 {
		t.Fatal("Bug-6: KEK unwrap failure should trigger alert")
	}
	last := al.alerts[len(al.alerts)-1]
	if last.operation != "KEKUnwrapFailure" {
		t.Fatalf("Bug-6: expected operation KEKUnwrapFailure, got %s", last.operation)
	}
	if last.resource != "alert-test-key" {
		t.Fatalf("Bug-6: expected resource alert-test-key, got %s", last.resource)
	}
	t.Logf("✅ Bug-6: KEK unwrap failure triggered alert: op=%s resource=%s", last.operation, last.resource)
}

// TestCore_NoopAlerterDefault Bug-6: 默认无 alerter 不 panic。
func TestCore_NoopAlerterDefault(t *testing.T) {
	core, _, _ := newTestCore(t)
	// 不调用 SetAlerter，默认 noopAlerter。

	// 验证 SetAlerter(nil) 不会 panic。
	core.SetAlerter(nil)

	// alerter 字段应不为 nil（noopAlerter）。
	if core.alerter == nil {
		t.Fatal("alerter should default to noopAlerter, not nil")
	}
	t.Log("✅ Bug-6: default noopAlerter works")
}
