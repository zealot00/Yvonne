package lifecycle

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
)

// TestSoftDeleteKey_Success 验证软删除标记状态。
func TestSoftDeleteKey_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, err := mgr.CreateKey(ctx, "soft-del-test", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if err := mgr.SoftDeleteKey(ctx, "soft-del-test", 1); err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}

	meta, err := mgr.GetKey(ctx, "soft-del-test", 1)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if meta.State != StateSoftDeleted {
		t.Fatalf("State = %v, want SoftDeleted", meta.State)
	}
	if meta.DeletedAt.IsZero() {
		t.Fatal("DeletedAt should be set")
	}
	// EncryptedMaterial 应仍存在（未物理删除）。
	if len(meta.EncryptedMaterial) == 0 {
		t.Fatal("EncryptedMaterial should still exist after soft delete")
	}
}

// TestSoftDeleteKey_Idempotent 验证重复软删除幂等。
func TestSoftDeleteKey_Idempotent(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "idempotent-test", mk, 0)
	_ = mgr.SoftDeleteKey(ctx, "idempotent-test", 1)
	// 再次软删除应幂等返回 nil。
	if err := mgr.SoftDeleteKey(ctx, "idempotent-test", 1); err != nil {
		t.Fatalf("second SoftDeleteKey should be idempotent: %v", err)
	}
}

// TestSoftDeleteKey_DestroyedRejected 验证已物理粉碎的不可软删除。
func TestSoftDeleteKey_DestroyedRejected(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "destroyed-test", mk, 0)
	_ = mgr.ShredKey(ctx, "destroyed-test", 1)

	// ShredKey 物理删除了行，SoftDeleteKey 应返回 not found error。
	err := mgr.SoftDeleteKey(ctx, "destroyed-test", 1)
	if err == nil {
		t.Fatal("SoftDeleteKey after shred should fail")
	}
}

// TestRestoreKey_Success 验证从回收站恢复。
func TestRestoreKey_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "restore-test", mk, 0)
	_ = mgr.SoftDeleteKey(ctx, "restore-test", 1)

	// 恢复。
	if err := mgr.RestoreKey(ctx, "restore-test", 1); err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}

	meta, _ := mgr.GetKey(ctx, "restore-test", 1)
	if meta.State != StateDeactivated {
		t.Fatalf("State = %v, want Deactivated", meta.State)
	}
	if !meta.DeletedAt.IsZero() {
		t.Fatal("DeletedAt should be cleared after restore")
	}
}

// TestRestoreKey_NotSoftDeleted 验证非软删除状态幂等返回。
func TestRestoreKey_NotSoftDeleted(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "active-restore", mk, 0)
	// Active 状态恢复应幂等返回 nil。
	if err := mgr.RestoreKey(ctx, "active-restore", 1); err != nil {
		t.Fatalf("RestoreKey on Active should be idempotent: %v", err)
	}
}

// TestRestoreKey_DestroyedRejected 验证已物理粉碎的不可恢复。
func TestRestoreKey_DestroyedRejected(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "restore-destroyed", mk, 0)
	_ = mgr.ShredKey(ctx, "restore-destroyed", 1)

	// ShredKey 物理删除了行，RestoreKey 应返回 not found error。
	err := mgr.RestoreKey(ctx, "restore-destroyed", 1)
	if err == nil {
		t.Fatal("RestoreKey after shred should fail")
	}
}

// TestSoftDeleted_CanDecrypt 验证软删除后仍可解密。
func TestSoftDeleted_CanDecrypt(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "decrypt-after-softdel", mk, 0)
	_ = mgr.SoftDeleteKey(ctx, "decrypt-after-softdel", 1)

	// GetKeyForDecrypt 应成功（SoftDeleted 允许解密）。
	meta, err := mgr.GetKeyForDecrypt(ctx, "decrypt-after-softdel", 1)
	if err != nil {
		t.Fatalf("GetKeyForDecrypt after soft delete: %v", err)
	}
	if meta.State != StateSoftDeleted {
		t.Fatalf("State = %v, want SoftDeleted", meta.State)
	}
}

// TestSoftDeleted_CannotEncrypt 验证软删除后不可加密。
func TestSoftDeleted_CannotEncrypt(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "encrypt-after-softdel", mk, 0)
	_ = mgr.SoftDeleteKey(ctx, "encrypt-after-softdel", 1)

	// 轮转后 V1 是 Deactivated，GetActiveKey 应返回 V2。
	_, _, _ = mgr.RotateKey(ctx, "encrypt-after-softdel", mk)

	// 软删除 V2 后，GetActiveKey 应失败（无 Active 版本）。
	_ = mgr.SoftDeleteKey(ctx, "encrypt-after-softdel", 2)
	_, err := mgr.GetActiveKey(ctx, "encrypt-after-softdel")
	if err == nil {
		t.Fatal("GetActiveKey should fail when all versions are SoftDeleted")
	}
}

// TestSoftDeleteThenShred 验证软删除后仍可物理粉碎。
func TestSoftDeleteThenShred(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "soft-then-shred", mk, 0)
	_ = mgr.SoftDeleteKey(ctx, "soft-then-shred", 1)

	// 物理粉碎。
	if err := mgr.ShredKey(ctx, "soft-then-shred", 1); err != nil {
		t.Fatalf("ShredKey after soft delete: %v", err)
	}

	// 验证已物理删除。
	_, err := mgr.GetKey(ctx, "soft-then-shred", 1)
	if err == nil {
		t.Fatal("GetKey should fail after shred")
	}
}

// TestFullSoftDeleteRestoreShredLifecycle 完整生命周期。
func TestFullSoftDeleteRestoreShredLifecycle(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()
	keyID := "lifecycle-test"

	// 1. 创建 V1。
	_, _, _ = mgr.CreateKey(ctx, keyID, mk, 0)

	// 2. 软删除 V1。
	if err := mgr.SoftDeleteKey(ctx, keyID, 1); err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}

	// 3. 恢复 V1。
	if err := mgr.RestoreKey(ctx, keyID, 1); err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}

	// 4. 验证状态为 Deactivated。
	meta, _ := mgr.GetKey(ctx, keyID, 1)
	if meta.State != StateDeactivated {
		t.Fatalf("State = %v, want Deactivated", meta.State)
	}

	// 5. 物理粉碎 V1。
	if err := mgr.ShredKey(ctx, keyID, 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	// 6. 验证不可恢复（行已物理删除）。
	err := mgr.RestoreKey(ctx, keyID, 1)
	if err == nil {
		t.Fatal("RestoreKey after shred should fail")
	}
}

// 确保 memguard 包被引用。
var _ = memguard.NewSecureBuffer
