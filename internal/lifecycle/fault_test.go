package lifecycle

import (
	"context"
	"errors"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// faultStore 是一个模拟错误的 KVStore，用于测试错误路径。
type faultStore struct {
	getErr    error
	putErr    error
	deleteErr error
	data      map[string][]byte
}

func newFaultStore() *faultStore {
	return &faultStore{data: make(map[string][]byte)}
}

func (f *faultStore) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	f.data[key] = cp
	return nil
}

func (f *faultStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *faultStore) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.data, key)
	return nil
}

func (f *faultStore) WithTx(ctx context.Context, fn func(txStore storage.KVStore) error) error {
	return fn(f)
}

// TestCreateKey_SaveMetadataFail 验证 saveMetadata 失败时擦除明文 DEK。
func TestCreateKey_SaveMetadataFail(t *testing.T) {
	store := newFaultStore()
	store.putErr = errors.New("simulated put error")
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	_, _, err := mgr.CreateKey(context.Background(), "fail-key", mk, 0)
	if err == nil {
		t.Fatal("CreateKey with failing store should fail")
	}
}

// TestRotateKey_SaveMetadataFail 验证 Rotate 遇到 store 错误时回滚。
func TestRotateKey_SaveMetadataFail(t *testing.T) {
	store := newFaultStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 先正常创建。
	_, _, err := mgr.CreateKey(ctx, "rotate-fail-key", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 设 Put 错误，Rotate 应失败。
	store.putErr = errors.New("simulated put error on rotate")
	_, _, err = mgr.RotateKey(ctx, "rotate-fail-key", mk)
	if err == nil {
		t.Fatal("RotateKey with failing store should fail")
	}
}

// TestShredKey_GetFail 验证 Shred 遇到 Get 错误时报错。
func TestShredKey_GetFail(t *testing.T) {
	store := newFaultStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	_, _, err := mgr.CreateKey(ctx, "shred-get-fail", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	store.getErr = errors.New("simulated get error")
	err = mgr.ShredKey(ctx, "shred-get-fail", 1)
	if err == nil {
		t.Fatal("ShredKey with failing Get should fail")
	}
}

// TestShredKey_DeleteFail 验证 Shred 遇到 Delete 错误时报错。
func TestShredKey_DeleteFail(t *testing.T) {
	store := newFaultStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	_, _, err := mgr.CreateKey(ctx, "shred-del-fail", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	store.deleteErr = errors.New("simulated delete error")
	err = mgr.ShredKey(ctx, "shred-del-fail", 1)
	if err == nil {
		t.Fatal("ShredKey with failing Delete should fail")
	}
}

// TestFindLatestVersion_GetError 验证 findLatestVersion 遇到非 ErrNotFound 错误时传播。
func TestFindLatestVersion_GetError(t *testing.T) {
	store := newFaultStore()
	store.getErr = errors.New("persistent get error")
	mgr := NewManager(store)

	_, err := mgr.findLatestVersion(context.Background(), "any-key")
	if err == nil {
		t.Fatal("findLatestVersion with persistent Get error should fail")
	}
}
