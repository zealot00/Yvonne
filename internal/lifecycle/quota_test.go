package lifecycle

import (
	"context"
	"errors"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestQuota_CreateKeyWithinLimit 验证配额内创建成功。
func TestQuota_CreateKeyWithinLimit(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(5)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 5 个 Key，全部应成功。
	for i := 0; i < 5; i++ {
		keyID := "key-" + string(rune('a'+i))
		_, _, err := mgr.CreateKey(ctx, keyID, kek, 0)
		if err != nil {
			t.Fatalf("CreateKey %d (%s): %v", i, keyID, err)
		}
	}
}

// TestQuota_CreateKeyExceedsLimit 验证超限返回 ErrQuotaExceeded。
func TestQuota_CreateKeyExceedsLimit(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(5)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 5 个 Key。
	for i := 0; i < 5; i++ {
		keyID := "key-" + string(rune('a'+i))
		_, _, err := mgr.CreateKey(ctx, keyID, kek, 0)
		if err != nil {
			t.Fatalf("CreateKey %d: %v", i, err)
		}
	}

	// 第 6 个应失败。
	_, _, err := mgr.CreateKey(ctx, "key-overflow", kek, 0)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

// TestQuota_UnlimitedByDefault 验证默认不限制。
func TestQuota_UnlimitedByDefault(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	// 不调 SetMaxGlobalKeys → 默认 0 = 不限制

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		keyID := "key-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		_, _, err := mgr.CreateKey(ctx, keyID, kek, 0)
		if err != nil {
			t.Fatalf("CreateKey %d: %v", i, err)
		}
	}
}

// TestQuota_RotateDoesNotConsumeQuota 验证轮转不消耗配额。
func TestQuota_RotateDoesNotConsumeQuota(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(2)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 2 个 Key（达上限）。
	mgr.CreateKey(ctx, "key-a", kek, 0)
	mgr.CreateKey(ctx, "key-b", kek, 0)

	// 轮转 key-a（不应消耗配额）。
	_, _, err := mgr.RotateKey(ctx, "key-a", kek)
	if err != nil {
		t.Fatalf("RotateKey should not consume quota: %v", err)
	}

	// 再轮转 key-b。
	_, _, err = mgr.RotateKey(ctx, "key-b", kek)
	if err != nil {
		t.Fatalf("RotateKey b: %v", err)
	}
}

// TestQuota_ShredFreesQuota 验证删除后配额释放。
func TestQuota_ShredFreesQuota(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(2)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 2 个 Key（达上限）。
	mgr.CreateKey(ctx, "key-a", kek, 0)
	mgr.CreateKey(ctx, "key-b", kek, 0)

	// 第 3 个应失败。
	_, _, err := mgr.CreateKey(ctx, "key-c", kek, 0)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota exceeded: %v", err)
	}

	// 删除 key-a。
	if err := mgr.ShredKey(ctx, "key-a", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	// 现在应能创建 key-c。
	_, _, err = mgr.CreateKey(ctx, "key-c", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey after shred should succeed: %v", err)
	}
}

// TestQuota_SoftDeleteDoesNotFreeQuota 验证软删除不释放配额。
func TestQuota_SoftDeleteDoesNotFreeQuota(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(2)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "key-a", kek, 0)
	mgr.CreateKey(ctx, "key-b", kek, 0)

	// 软删除 key-a。
	mgr.SoftDeleteKey(ctx, "key-a", 1)

	// 第 3 个应仍失败（软删除不释放配额）。
	_, _, err := mgr.CreateKey(ctx, "key-c", kek, 0)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("soft-deleted key should still occupy quota: %v", err)
	}
}

// TestQuota_ExactLimit 验证刚好配额边界。
func TestQuota_ExactLimit(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(1)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 1 个（达上限）。
	_, _, err := mgr.CreateKey(ctx, "key-only", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey 1: %v", err)
	}

	// 第 2 个应失败。
	_, _, err = mgr.CreateKey(ctx, "key-overflow", kek, 0)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota exceeded: %v", err)
	}
}

// TestQuota_ZeroMeansUnlimited 验证 SetMaxGlobalKeys(0) 取消限制。
func TestQuota_ZeroMeansUnlimited(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mgr.SetMaxGlobalKeys(2)

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "key-a", kek, 0)
	mgr.CreateKey(ctx, "key-b", kek, 0)

	// 取消限制。
	mgr.SetMaxGlobalKeys(0)

	// 应能继续创建。
	_, _, err := mgr.CreateKey(ctx, "key-c", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey after quota removal: %v", err)
	}
}
