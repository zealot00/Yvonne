package lifecycle

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestListKeyIDs_Empty 空库返回空列表。
func TestListKeyIDs_Empty(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	keys, err := mgr.ListKeyIDs(ctx)
	if err != nil {
		t.Fatalf("ListKeyIDs: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

// TestListKeyIDs_SingleKey 单个 key 返回 1 个。
func TestListKeyIDs_SingleKey(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "key-a", kek, 0)

	keys, err := mgr.ListKeyIDs(ctx)
	if err != nil {
		t.Fatalf("ListKeyIDs: %v", err)
	}
	if len(keys) != 1 || keys[0] != "key-a" {
		t.Fatalf("expected [key-a], got %v", keys)
	}
}

// TestListKeyIDs_MultipleKeys 多个 key 去重。
func TestListKeyIDs_MultipleKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "key-a", kek, 0)
	mgr.CreateKey(ctx, "key-b", kek, 0)
	mgr.CreateKey(ctx, "key-c", kek, 0)

	keys, err := mgr.ListKeyIDs(ctx)
	if err != nil {
		t.Fatalf("ListKeyIDs: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d: %v", len(keys), keys)
	}
}

// TestListKeyIDs_DeduplicatesVersions 同一 key 多版本只返回一次。
func TestListKeyIDs_DeduplicatesVersions(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "multi-key", kek, 0)
	mgr.RotateKey(ctx, "multi-key", kek)
	mgr.RotateKey(ctx, "multi-key", kek) // 3 versions

	keys, err := mgr.ListKeyIDs(ctx)
	if err != nil {
		t.Fatalf("ListKeyIDs: %v", err)
	}
	if len(keys) != 1 || keys[0] != "multi-key" {
		t.Fatalf("expected [multi-key], got %v", keys)
	}
}

// TestListKeyIDs_ExcludesLatestIndex meta:latest: 索引不应出现。
func TestListKeyIDs_ExcludesLatestIndex(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	ctx := context.Background()

	mgr.CreateKey(ctx, "indexed-key", kek, 0)

	keys, _ := mgr.ListKeyIDs(ctx)
	for _, k := range keys {
		if k == "latest:indexed-key" || k == "indexed-key" {
			continue
		}
		t.Fatalf("unexpected key in list: %s", k)
	}
}
