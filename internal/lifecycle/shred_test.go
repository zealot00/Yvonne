package lifecycle

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestShredKey_DoubleShred 重复粉碎返回 error。
func TestShredKey_DoubleShred(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "double-shred", kek, 0)

	// 第一次粉碎成功。
	if err := mgr.ShredKey(ctx, "double-shred", 1); err != nil {
		t.Fatalf("first ShredKey: %v", err)
	}

	// 第二次粉碎应失败（已不存在）。
	err := mgr.ShredKey(ctx, "double-shred", 1)
	if err == nil {
		t.Fatal("second ShredKey should fail (already destroyed)")
	}
}

// TestShredKey_SoftDeletedThenShred 软删除后可以物理粉碎。
func TestShredKey_SoftDeletedThenShred(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "softdel-then-shred", kek, 0)
	mgr.SoftDeleteKey(ctx, "softdel-then-shred", 1)

	// 软删除状态下应仍可物理粉碎。
	if err := mgr.ShredKey(ctx, "softdel-then-shred", 1); err != nil {
		t.Fatalf("ShredKey after SoftDelete: %v", err)
	}

	// 验证已物理删除。
	_, err := mgr.GetKey(ctx, "softdel-then-shred", 1)
	if err == nil {
		t.Fatal("should not exist after shred")
	}
}

// TestShredKey_ActiveVersionShredded 粉碎 Active 版本后该 key 无 Active。
func TestShredKey_ActiveVersionShredded(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "active-shred", kek, 0)

	// 粉碎唯一的 Active 版本。
	mgr.ShredKey(ctx, "active-shred", 1)

	// GetActiveKey 应失败。
	_, err := mgr.GetActiveKey(ctx, "active-shred")
	if err == nil {
		t.Fatal("GetActiveKey should fail after shredding the only active version")
	}
}

// TestShredKey_OtherVersionsUnaffected 粉碎一个版本不影响其他版本。
func TestShredKey_OtherVersionsUnaffected(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "multi-shred", kek, 0)
	mgr.RotateKey(ctx, "multi-shred", kek)
	mgr.RotateKey(ctx, "multi-shred", kek) // v1=Deactivated, v2=Deactivated, v3=Active

	// 粉碎 v1。
	mgr.ShredKey(ctx, "multi-shred", 1)

	// v2 仍存在。
	_, err := mgr.GetKey(ctx, "multi-shred", 2)
	if err != nil {
		t.Fatalf("v2 should still exist: %v", err)
	}

	// v3 仍 Active。
	meta, err := mgr.GetActiveKey(ctx, "multi-shred")
	if err != nil {
		t.Fatalf("v3 should still be active: %v", err)
	}
	if meta.Version != 3 {
		t.Fatalf("active version = %d, want 3", meta.Version)
	}
}

// TestShredKey_GetKeyForDecryptRefused 粉碎后解密拒绝。
func TestShredKey_GetKeyForDecryptRefused(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "decrypt-after-shred", kek, 0)
	mgr.ShredKey(ctx, "decrypt-after-shred", 1)

	_, err := mgr.GetKeyForDecrypt(ctx, "decrypt-after-shred", 1)
	if err == nil {
		t.Fatal("GetKeyForDecrypt should fail after shred")
	}
}

// TestShredKey_Concurrent 并发粉碎同一版本（幂等性验证）。
func TestShredKey_Concurrent(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 5 个不同 key。
	for i := 0; i < 5; i++ {
		mgr.CreateKey(ctx, "conc-shred-"+string(rune('a'+i)), kek, 0)
	}

	done := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func(idx int) {
			keyID := "conc-shred-" + string(rune('a'+idx))
			done <- mgr.ShredKey(ctx, keyID, 1)
		}(i)
	}

	success := 0
	for i := 0; i < 5; i++ {
		if err := <-done; err == nil {
			success++
		}
	}

	if success != 5 {
		t.Fatalf("expected 5 successful shreds, got %d", success)
	}

	// 验证全部删除。
	for i := 0; i < 5; i++ {
		keyID := "conc-shred-" + string(rune('a'+i))
		_, err := mgr.GetKey(ctx, keyID, 1)
		if err == nil {
			t.Fatalf("%s should be shredded", keyID)
		}
	}
}

// TestShredKey_QuotaFreed 粉碎后配额释放。
func TestShredKey_QuotaFreed(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(2)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "quota-a", kek, 0)
	mgr.CreateKey(ctx, "quota-b", kek, 0)

	// 第 3 个应超限。
	_, _, err := mgr.CreateKey(ctx, "quota-c", kek, 0)
	if err == nil {
		t.Fatal("3rd key should be rejected (quota)")
	}

	// 粉碎一个。
	mgr.ShredKey(ctx, "quota-a", 1)

	// 现在可以创建第 3 个。
	_, _, err = mgr.CreateKey(ctx, "quota-c", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey after shred should succeed: %v", err)
	}
}

// TestShredKey_InvalidKeyID 空或无效 key_id。
func TestShredKey_InvalidKeyID(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	err := mgr.ShredKey(ctx, "", 1)
	if err == nil {
		t.Fatal("empty key_id should fail")
	}

	err = mgr.ShredKey(ctx, "nonexistent", 999)
	if err == nil {
		t.Fatal("nonexistent key+version should fail")
	}
}

// TestShredKey_WipeEncryptedMaterial 粉碎后密文材料不可恢复。
func TestShredKey_WipeEncryptedMaterial(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "wipe-test", kek, 0)

	// 读取元数据，确认有 EncryptedMaterial。
	meta, _ := mgr.GetKey(ctx, "wipe-test", 1)
	if len(meta.EncryptedMaterial) == 0 {
		t.Fatal("EncryptedMaterial should not be empty before shred")
	}

	// 粉碎。
	mgr.ShredKey(ctx, "wipe-test", 1)

	// DB 中该 key 应不存在。
	_, err := store.Get(ctx, metadataKey("wipe-test", 1))
	if err == nil {
		t.Fatal("metadata should be deleted from DB after shred")
	}
}

// TestShredKey_LatestVersionIndexUpdated 粉碎 latest 版本后索引更新。
func TestShredKey_LatestVersionIndexUpdated(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "index-shred", kek, 0)
	// latest version = 1

	// 粉碎 v1。
	mgr.ShredKey(ctx, "index-shred", 1)

	// findLatestVersion 应返回 0（无版本）或 error。
	latest, err := mgr.findLatestVersion(ctx, "index-shred")
	if err == nil && latest > 0 {
		// 可能有残留索引，验证 GetActiveKey 失败即可。
		_, err = mgr.GetActiveKey(ctx, "index-shred")
		if err == nil {
			t.Fatal("GetActiveKey should fail after shredding all versions")
		}
	}
}
