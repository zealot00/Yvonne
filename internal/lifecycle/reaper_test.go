package lifecycle

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestReapExpiredSoftDeletes_PhysicalDestroy 验证过期软删除密钥被物理粉碎。
func TestReapExpiredSoftDeletes_PhysicalDestroy(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 创建密钥。
	_, _, _ = mgr.CreateKey(ctx, "reap-test", mk)

	// 软删除。
	if err := mgr.SoftDeleteKey(ctx, "reap-test", 1); err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}

	// 手动篡改 DeletedAt 为 100 天前（模拟过期）。
	meta, _ := mgr.GetKey(ctx, "reap-test", 1)
	meta.DeletedAt = time.Now().UTC().Add(-100 * 24 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// 验证 StillExists。
	_, err := mgr.GetKey(ctx, "reap-test", 1)
	if err != nil {
		t.Fatalf("key should exist before reap: %v", err)
	}

	// 执行 reaper（TTL=90 天，DeletedAt 100 天前，应被清除）。
	reaped := []string{}
	mgr.ReapNow(90*24*time.Hour, func(keyID string, version int) {
		reaped = append(reaped, keyID)
	})

	// 验证已被物理删除。
	_, err = mgr.GetKey(ctx, "reap-test", 1)
	if err == nil {
		t.Fatal("key should be physically destroyed after reap")
	}

	// 验证 onReaped 回调被调用。
	if len(reaped) != 1 || reaped[0] != "reap-test" {
		t.Fatalf("reaped = %v, want [reap-test]", reaped)
	}
}

// TestReapExpiredSoftDeletes_NotExpiredKept 验证未过期的软删除密钥被保留。
func TestReapExpiredSoftDeletes_NotExpiredKept(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "keep-test", mk)
	_ = mgr.SoftDeleteKey(ctx, "keep-test", 1)

	// DeletedAt 刚才设置（未过期）。

	// 执行 reaper（TTL=90 天）。
	mgr.ReapNow(90*24*time.Hour, nil)

	// 验证仍存在（SoftDeleted 状态）。
	meta, err := mgr.GetKey(ctx, "keep-test", 1)
	if err != nil {
		t.Fatalf("key should still exist: %v", err)
	}
	if meta.State != StateSoftDeleted {
		t.Fatalf("State = %v, want SoftDeleted", meta.State)
	}
}

// TestReapExpiredSoftDeletes_ActiveNotTouched 验证 Active 密钥不被 reaper 触碰。
func TestReapExpiredSoftDeletes_ActiveNotTouched(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "active-reap-test", mk)
	// 不软删除，保持 Active。

	mgr.ReapNow(90*24*time.Hour, nil)

	// 验证仍存在且 Active。
	meta, err := mgr.GetKey(ctx, "active-reap-test", 1)
	if err != nil {
		t.Fatalf("key should exist: %v", err)
	}
	if meta.State != StateActive {
		t.Fatalf("State = %v, want Active", meta.State)
	}
}

// TestReapExpiredSoftDeletes_MixedKeys 验证混合场景：
// 过期的被清除，未过期的保留，Active 的不动。
func TestReapExpiredSoftDeletes_MixedKeys(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// key-expired: 软删除 + 100 天前。
	_, _, _ = mgr.CreateKey(ctx, "key-expired", mk)
	_ = mgr.SoftDeleteKey(ctx, "key-expired", 1)
	meta, _ := mgr.GetKey(ctx, "key-expired", 1)
	meta.DeletedAt = time.Now().UTC().Add(-100 * 24 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// key-recent: 软删除 + 刚才。
	_, _, _ = mgr.CreateKey(ctx, "key-recent", mk)
	_ = mgr.SoftDeleteKey(ctx, "key-recent", 1)

	// key-active: Active。
	_, _, _ = mgr.CreateKey(ctx, "key-active", mk)

	// 执行 reaper。
	reaped := []string{}
	mgr.ReapNow(90*24*time.Hour, func(keyID string, version int) {
		reaped = append(reaped, keyID)
	})

	// 验证 key-expired 被清除。
	_, err := mgr.GetKey(ctx, "key-expired", 1)
	if err == nil {
		t.Fatal("key-expired should be reaped")
	}

	// 验证 key-recent 保留。
	meta, err = mgr.GetKey(ctx, "key-recent", 1)
	if err != nil {
		t.Fatal("key-recent should still exist")
	}
	if meta.State != StateSoftDeleted {
		t.Fatalf("key-recent State = %v, want SoftDeleted", meta.State)
	}

	// 验证 key-active 不动。
	meta, err = mgr.GetKey(ctx, "key-active", 1)
	if err != nil {
		t.Fatal("key-active should exist")
	}
	if meta.State != StateActive {
		t.Fatalf("key-active State = %v, want Active", meta.State)
	}

	// 验证只 reaped 了 1 个。
	if len(reaped) != 1 || reaped[0] != "key-expired" {
		t.Fatalf("reaped = %v, want [key-expired]", reaped)
	}
}

// TestScanPrefix_MemoryStore 验证 MemoryStore 的 ScanPrefix 实现。
func TestScanPrefix_MemoryStore(t *testing.T) {
	_, store := newTestManager(t)
	ctx := context.Background()

	// 写入几个 key。
	store.Put(ctx, "key:a:v:1", []byte("a1"))
	store.Put(ctx, "key:b:v:1", []byte("b1"))
	store.Put(ctx, "other:data", []byte("other"))

	// 扫描 "key:" 前缀。
	result, err := store.ScanPrefix(ctx, "key:")
	if err != nil {
		t.Fatalf("ScanPrefix: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
	if string(result["key:a:v:1"]) != "a1" {
		t.Fatal("missing key:a:v:1")
	}
}

// saveMetaDirect 直接写入元数据到 store（绕过 lifecycle 方法，用于测试篡改 DeletedAt）。
func saveMetaDirect(t *testing.T, mgr *Manager, meta KeyMetadata) {
	t.Helper()
	ctx := context.Background()

	// 先失效缓存，确保下次读取从 store 加载。
	mgr.cache.invalidate(meta.KeyID)

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	key := metadataKey(meta.KeyID, meta.Version)
	if err := mgr.store.Put(ctx, key, data); err != nil {
		t.Fatalf("put: %v", err)
	}
}
