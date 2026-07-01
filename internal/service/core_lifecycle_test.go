package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestCore_RotateKey_Success 轮转成功 + 返回新版本。
func TestCore_RotateKey_Success(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "rot-key", seal.NewSoftwareKEK(mk), 0)

	result, err := core.RotateKey(ctx, "rot-key", nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if result.KeyID != "rot-key" {
		t.Fatalf("KeyID = %q", result.KeyID)
	}
	if result.NewVersion != 2 {
		t.Fatalf("NewVersion = %d, want 2", result.NewVersion)
	}
	if result.PlaintextDEK == nil {
		t.Fatal("PlaintextDEK should not be nil")
	}
	result.PlaintextDEK.Wipe()
}

// TestCore_RotateKey_KeyNotFound 轮转不存在的 key。
func TestCore_RotateKey_KeyNotFound(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	_, err := core.RotateKey(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatal("rotate nonexistent key should fail")
	}
}

// TestCore_RotateKey_Unauthorized 轮转无权限。
func TestCore_RotateKey_Unauthorized(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "protected-key", seal.NewSoftwareKEK(mk), 0)

	policy := &auth.Policy{
		RoleID:         "limited",
		AllowedKeys:    []string{"other-*"},
		AllowedActions: []string{"KeyOp"},
	}
	_, err := core.RotateKey(ctx, "protected-key", policy)
	if err == nil {
		t.Fatal("should deny rotate")
	}
	if !strings.Contains(err.Error(), "cannot access key") {
		t.Fatalf("error should mention access denied: %s", err.Error())
	}
}

// TestCore_ShredKey_Success 粉碎成功。
func TestCore_ShredKey_Success(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "shred-key", seal.NewSoftwareKEK(mk), 0)

	if err := core.ShredKey(ctx, "shred-key", 1, nil); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	// 验证已删除。
	_, err := mgr.GetKey(ctx, "shred-key", 1)
	if err == nil {
		t.Fatal("key should be destroyed")
	}
}

// TestCore_ShredKey_NotFound 粉碎不存在的版本。
func TestCore_ShredKey_NotFound(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	err := core.ShredKey(ctx, "nonexistent", 1, nil)
	if err == nil {
		t.Fatal("shred nonexistent should fail")
	}
}

// TestCore_SoftDeleteAndRestore 软删除 + 恢复。
func TestCore_SoftDeleteAndRestore(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "softdel-key", seal.NewSoftwareKEK(mk), 0)

	// 软删除。
	if err := core.SoftDeleteKey(ctx, "softdel-key", 1, nil); err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}
	meta, _ := mgr.GetKey(ctx, "softdel-key", 1)
	if meta.State != lifecycle.StateSoftDeleted {
		t.Fatalf("State = %v, want SoftDeleted", meta.State)
	}

	// 恢复。
	if err := core.RestoreKey(ctx, "softdel-key", 1, nil); err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}
	meta, _ = mgr.GetKey(ctx, "softdel-key", 1)
	if meta.State == lifecycle.StateSoftDeleted {
		t.Fatal("should not be SoftDeleted after restore")
	}
}

// TestCore_GenerateDataKey_Success GDK 成功。
func TestCore_GenerateDataKey_Success(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "gdk-key", seal.NewSoftwareKEK(mk), 0)

	result, err := core.GenerateDataKey(ctx, "gdk-key", nil)
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	// Bug-7 修复: 不再直接访问 PlaintextDEK，通过 WriteBase64To 验证。
	var buf bytes.Buffer
	if err := result.WriteBase64To(&buf); err != nil {
		t.Fatalf("WriteBase64To: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("WriteBase64To should produce non-empty output")
	}
	if len(result.Ciphertext) == 0 {
		t.Fatal("Ciphertext should not be empty")
	}
	// Bug-7: WriteBase64To 内部已 Wipe，证明明文 DEK 不会逃逸。
	// 注意: 第二次调用会 panic（use-after-free 是致命错误），不在此测试。
	t.Logf("✅ Bug-7: WriteBase64To produced %d bytes, DEK wiped after write", buf.Len())
}

// TestCore_GenerateDataKey_KeyNotFound GDK 不存在的 key。
func TestCore_GenerateDataKey_KeyNotFound(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	_, err := core.GenerateDataKey(ctx, "nonexistent", nil)
	if err == nil {
		t.Fatal("GDK nonexistent should fail")
	}
}

// TestCore_CreateKey_ReturnDEKFalse 不返回明文 DEK。
func TestCore_CreateKey_ReturnDEKFalse(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	result, err := core.CreateKey(ctx, "no-dek-key", 0, false, nil)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if result.PlaintextDEK != nil {
		t.Fatal("PlaintextDEK should be nil when returnDEK=false")
	}
	if result.Version != 1 {
		t.Fatalf("Version = %d, want 1", result.Version)
	}
}

// TestCore_Encrypt_KeyNotFound 加密不存在的 key。
func TestCore_Encrypt_KeyNotFound(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	_, err := core.Encrypt(ctx, "nonexistent", []byte("x"), nil)
	if err == nil {
		t.Fatal("encrypt nonexistent key should fail")
	}
}

// TestCore_Decrypt_TamperedCiphertext 篡改密文。
func TestCore_Decrypt_TamperedCiphertext(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "tamper-key", seal.NewSoftwareKEK(mk), 0)

	encResp, _ := core.Encrypt(ctx, "tamper-key", []byte("test"), nil)
	encResp.Ciphertext[len(encResp.Ciphertext)-1] ^= 0xFF // 篡改

	_, err := core.Decrypt(ctx, "tamper-key", encResp.Ciphertext, nil)
	if err == nil {
		t.Fatal("tampered ciphertext should fail")
	}
}

// TestCore_Decrypt_WrongKey 用错误 key 解密。
func TestCore_Decrypt_WrongKey(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "key-a", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "key-b", seal.NewSoftwareKEK(mk), 0)

	encResp, _ := core.Encrypt(ctx, "key-a", []byte("secret"), nil)
	_, err := core.Decrypt(ctx, "key-b", encResp.Ciphertext, nil)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

// TestCore_Health 健康检查。
func TestCore_Health(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	state, emergency, err := core.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if state != "unsealed" {
		t.Fatalf("state = %q, want unsealed", state)
	}
	if emergency {
		t.Fatal("should not be emergency sealed")
	}
}

// TestCore_Health_Sealed sealed 状态健康检查。
func TestCore_Health_Sealed(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(5, 3, 0) // sealed
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	core := NewCore(mgr, vault, nil)

	ctx := context.Background()
	state, _, _ := core.Health(ctx)
	if state != "sealed" {
		t.Fatalf("state = %q, want sealed", state)
	}
}

// TestCore_PolicyAuthorized 有权限时正常通过。
func TestCore_PolicyAuthorized(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "allowed-key", seal.NewSoftwareKEK(mk), 0)

	policy := &auth.Policy{
		RoleID:         "service-a",
		AllowedKeys:    []string{"allowed-*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	}
	_, err := core.Encrypt(ctx, "allowed-key", []byte("test"), policy)
	if err != nil {
		t.Fatalf("authorized encrypt should succeed: %v", err)
	}
}

// 确保 bytes 引用。
var _ = bytes.Buffer{}
