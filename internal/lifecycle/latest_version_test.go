package lifecycle

import (
	"context"
	"encoding/json"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestLatestVersionIndex_CreateAndLookup 验证 CreateKey 写入 latest 版本索引。
func TestLatestVersionIndex_CreateAndLookup(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 key-a。
	mgr.CreateKey(ctx, "key-a", kek, 0)

	// 索引应存在且值为 1。
	data, err := store.Get(ctx, latestVersionMetadataKey("key-a"))
	if err != nil {
		t.Fatalf("latest version index not found: %v", err)
	}
	var v int
	if err := jsonUnmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v != 1 {
		t.Fatalf("latest version = %d, want 1", v)
	}
}

// TestLatestVersionIndex_RotateUpdates 验证 RotateKey 更新索引。
func TestLatestVersionIndex_RotateUpdates(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "key-rot", kek, 0)
	mgr.RotateKey(ctx, "key-rot", kek)
	mgr.RotateKey(ctx, "key-rot", kek)

	// 索引应为 3。
	data, _ := store.Get(ctx, latestVersionMetadataKey("key-rot"))
	var v int
	jsonUnmarshal(data, &v)
	if v != 3 {
		t.Fatalf("latest version after 2 rotates = %d, want 3", v)
	}
}

// TestLatestVersionIndex_FallbackScan 验证无索引时回退到扫描。
func TestLatestVersionIndex_FallbackScan(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 手动写入 3 个版本元数据，但不写索引（模拟旧数据）。
	for v := 1; v <= 3; v++ {
		meta := KeyMetadata{
			KeyID:             "legacy-key",
			Version:           v,
			State:             StateActive,
			EncryptedMaterial: []byte("fake"),
			KEKType:           "software",
		}
		data, _ := jsonMarshal(meta)
		store.Put(ctx, metadataKey("legacy-key", v), data)
	}
	_ = kek // 避免 unused 警告（此处测试不用 kek）。

	// findLatestVersion 应回退到扫描，返回 3。
	v, err := mgr.findLatestVersion(ctx, "legacy-key")
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}
	if v != 3 {
		t.Fatalf("latest version = %d, want 3 (scan fallback)", v)
	}
}

// TestLatestVersionIndex_O1AfterIndex 验证索引后 O(1) 查询。
func TestLatestVersionIndex_O1AfterIndex(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	// 创建 + 多次轮转。
	mgr.CreateKey(ctx, "fast-key", kek, 0)
	for i := 0; i < 10; i++ {
		mgr.RotateKey(ctx, "fast-key", kek)
	}

	// 索引应为 11。
	data, _ := store.Get(ctx, latestVersionMetadataKey("fast-key"))
	var v int
	jsonUnmarshal(data, &v)
	if v != 11 {
		t.Fatalf("index = %d, want 11", v)
	}

	// findLatestVersion 应通过索引 O(1) 返回 11。
	got, err := mgr.findLatestVersion(ctx, "fast-key")
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}
	if got != 11 {
		t.Fatalf("findLatestVersion = %d, want 11", got)
	}
}

// jsonUnmarshal 和 jsonMarshal 是测试辅助（直接用 encoding/json）。
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
