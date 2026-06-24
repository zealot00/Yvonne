package lifecycle

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// mockNotifier 记录被通知的 keyID，用于测试。
type mockNotifier struct {
	notified []string
}

func (m *mockNotifier) NotifyInvalidation(keyID string) error {
	m.notified = append(m.notified, keyID)
	return nil
}

// TestCache_PutGet 验证缓存读写。
func TestCache_PutGet(t *testing.T) {
	c := newDekCache()
	meta := &KeyMetadata{KeyID: "test", Version: 1, State: StateActive}

	c.put("key:test:v:1", meta)
	got, ok := c.get("key:test:v:1")
	if !ok {
		t.Fatal("cache miss after put")
	}
	if got.KeyID != "test" {
		t.Fatalf("got KeyID = %q", got.KeyID)
	}
	if c.size() != 1 {
		t.Fatalf("size = %d, want 1", c.size())
	}
}

// TestCache_Invalidate 验证按 keyID 失效。
func TestCache_Invalidate(t *testing.T) {
	c := newDekCache()
	c.put("key:order:v:1", &KeyMetadata{KeyID: "order", Version: 1})
	c.put("key:order:v:2", &KeyMetadata{KeyID: "order", Version: 2})
	c.put("key:payment:v:1", &KeyMetadata{KeyID: "payment", Version: 1})

	c.invalidate("order")

	if c.size() != 1 {
		t.Fatalf("after invalidate order: size = %d, want 1", c.size())
	}
	if _, ok := c.get("key:payment:v:1"); !ok {
		t.Fatal("payment should still be cached")
	}
}

// TestCache_Clear 验证清空整个缓存。
func TestCache_Clear(t *testing.T) {
	c := newDekCache()
	c.put("key:a:v:1", &KeyMetadata{})
	c.put("key:b:v:1", &KeyMetadata{})
	c.clear()
	if c.size() != 0 {
		t.Fatalf("after clear: size = %d, want 0", c.size())
	}
}

// TestManager_GetKey_CacheHit 验证 GetKey 缓存命中。
func TestManager_GetKey_CacheHit(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	// 创建密钥。
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	_, _, err := mgr.CreateKey(ctx, "cache-test", mk)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 第一次 GetKey（缓存未命中，查 DB + 写缓存）。
	_, err = mgr.GetKey(ctx, "cache-test", 1)
	if err != nil {
		t.Fatalf("GetKey first: %v", err)
	}
	if mgr.cache.size() != 1 {
		t.Fatalf("cache size = %d, want 1", mgr.cache.size())
	}

	// 第二次 GetKey（缓存命中，不查 DB）。
	_, err = mgr.GetKey(ctx, "cache-test", 1)
	if err != nil {
		t.Fatalf("GetKey second: %v", err)
	}
}

// TestManager_RotateKey_InvalidatesCache 验证 Rotate 后缓存被失效。
func TestManager_RotateKey_InvalidatesCache(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建 + 预热缓存。
	_, _, _ = mgr.CreateKey(ctx, "rotate-cache-test", mk)
	_, _ = mgr.GetKey(ctx, "rotate-cache-test", 1)
	if mgr.cache.size() != 1 {
		t.Fatalf("cache size = %d, want 1 before rotate", mgr.cache.size())
	}

	// Rotate 应失效缓存。
	_, _, err := mgr.RotateKey(ctx, "rotate-cache-test", mk)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if mgr.cache.size() != 0 {
		t.Fatalf("cache size = %d, want 0 after rotate", mgr.cache.size())
	}
}

// TestManager_ShredKey_InvalidatesCache 验证 Shred 后缓存被失效。
func TestManager_ShredKey_InvalidatesCache(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "shred-cache-test", mk)
	_, _ = mgr.GetKey(ctx, "shred-cache-test", 1)
	if mgr.cache.size() != 1 {
		t.Fatalf("cache size = %d, want 1 before shred", mgr.cache.size())
	}

	if err := mgr.ShredKey(ctx, "shred-cache-test", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}
	if mgr.cache.size() != 0 {
		t.Fatalf("cache size = %d, want 0 after shred", mgr.cache.size())
	}
}

// TestManager_RotateKey_TriggersNotifier 验证 Rotate 后调用 notifier。
func TestManager_RotateKey_TriggersNotifier(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	notif := &mockNotifier{}
	mgr.SetNotifier(notif)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "notify-test", mk)
	_, _, err := mgr.RotateKey(ctx, "notify-test", mk)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if len(notif.notified) != 1 {
		t.Fatalf("notified count = %d, want 1", len(notif.notified))
	}
	if notif.notified[0] != "notify-test" {
		t.Fatalf("notified keyID = %q, want notify-test", notif.notified[0])
	}
}

// TestManager_ShredKey_TriggersNotifier 验证 Shred 后调用 notifier。
func TestManager_ShredKey_TriggersNotifier(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	notif := &mockNotifier{}
	mgr.SetNotifier(notif)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	_, _, _ = mgr.CreateKey(ctx, "notify-shred", mk)
	err := mgr.ShredKey(ctx, "notify-shred", 1)
	if err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	if len(notif.notified) != 1 {
		t.Fatalf("notified count = %d, want 1", len(notif.notified))
	}
}

// TestManager_InvalidateCache_PublicAPI 验证公开 API。
func TestManager_InvalidateCache_PublicAPI(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	_, _, _ = mgr.CreateKey(ctx, "public-invalidate", mk)
	_, _ = mgr.GetKey(ctx, "public-invalidate", 1)

	mgr.InvalidateCache("public-invalidate")
	if mgr.cache.size() != 0 {
		t.Fatal("InvalidateCache should clear entry")
	}
}

// TestManager_ClearCache_PublicAPI 验证断线重连后的 ClearCache。
func TestManager_ClearCache_PublicAPI(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	_, _, _ = mgr.CreateKey(ctx, "key-a", mk)
	_, _, _ = mgr.CreateKey(ctx, "key-b", mk)
	_, _ = mgr.GetKey(ctx, "key-a", 1)
	_, _ = mgr.GetKey(ctx, "key-b", 1)

	if mgr.cache.size() != 2 {
		t.Fatalf("cache size = %d, want 2", mgr.cache.size())
	}

	mgr.ClearCache()
	if mgr.cache.size() != 0 {
		t.Fatal("ClearCache should clear all entries")
	}
}
