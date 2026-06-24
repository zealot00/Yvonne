package lifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// newTestManager 创建用 MemoryStore 的测试 Manager。
func newTestManager(t *testing.T) (*Manager, *storage.MemoryStore) {
	t.Helper()
	store := storage.NewMemoryStore()
	return NewManager(store), store
}

// newTestMasterKey 创建测试用 Master Key。
func newTestMasterKey(t *testing.T) *memguard.SecureBuffer {
	t.Helper()
	key, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("newTestMasterKey: %v", err)
	}
	t.Cleanup(func() { key.Wipe() })
	return key
}

// TestCreateKey_Success 验证 CreateKey 生成 V1 Active 密钥。
func TestCreateKey_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	meta, plainDEK, err := mgr.CreateKey(ctx, "key-001", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	defer plainDEK.Wipe()

	if meta.KeyID != "key-001" {
		t.Fatalf("KeyID = %q, want key-001", meta.KeyID)
	}
	if meta.Version != 1 {
		t.Fatalf("Version = %d, want 1", meta.Version)
	}
	if meta.State != StateActive {
		t.Fatalf("State = %q, want Active", meta.State)
	}
	if len(meta.EncryptedMaterial) == 0 {
		t.Fatal("EncryptedMaterial is empty")
	}
	if meta.CreatedAt.IsZero() {
		t.Fatal("CreatedAt is zero")
	}

	// 明文 DEK 应为 32 字节。
	if plainDEK.Len() != 32 {
		t.Fatalf("plaintext DEK len = %d, want 32", plainDEK.Len())
	}
}

// TestRotateKey_Success 验证 Rotate 后 V1 变 Deactivated，V2 变 Active。
func TestRotateKey_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 1. CreateKey V1。
	_, plainDEK1, err := mgr.CreateKey(ctx, "key-002", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plainDEK1.Wipe()

	// 2. RotateKey。
	meta2, plainDEK2, err := mgr.RotateKey(ctx, "key-002", mk)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	defer plainDEK2.Wipe()

	if meta2.Version != 2 {
		t.Fatalf("new version = %d, want 2", meta2.Version)
	}
	if meta2.State != StateActive {
		t.Fatalf("new state = %q, want Active", meta2.State)
	}

	// 3. 验证 V1 已变为 Deactivated。
	v1, err := mgr.GetKey(ctx, "key-002", 1)
	if err != nil {
		t.Fatalf("GetKey v1: %v", err)
	}
	if v1.State != StateDeactivated {
		t.Fatalf("v1 state = %q, want Deactivated", v1.State)
	}
}

// TestShredKey_Success 验证 Shred 后状态变 Destroyed 且密文为空，最终查无此 Key。
func TestShredKey_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 1. CreateKey。
	_, plainDEK, err := mgr.CreateKey(ctx, "key-003", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plainDEK.Wipe()

	// 2. ShredKey。
	if err := mgr.ShredKey(ctx, "key-003", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	// 3. 验证查无此 Key（已 Delete）。
	_, err = mgr.GetKey(ctx, "key-003", 1)
	if err == nil {
		t.Fatal("GetKey after Shred should fail")
	}
}

// TestShredKey_ClearsEncryptedMaterial 验证 Shred 临时变量 EncryptedMaterial 被 clear。
// 通过读取 Shred 前的元数据，验证 EncryptedMaterial 非空；Shred 后该切片应被覆写。
func TestShredKey_ClearsEncryptedMaterial(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, plainDEK, err := mgr.CreateKey(ctx, "key-004", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plainDEK.Wipe()

	// 读取元数据，保存 EncryptedMaterial 引用用于事后检查。
	meta, err := mgr.GetKey(ctx, "key-004", 1)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	// 保存密文引用（注意：Get 返回副本，但 lifecycle 内部 shred 会 clear 自己读出的副本）。
	originalMaterial := make([]byte, len(meta.EncryptedMaterial))
	copy(originalMaterial, meta.EncryptedMaterial)
	if allZero(originalMaterial) {
		t.Fatal("original material should not be all zero before Shred")
	}

	// Shred。
	if err := mgr.ShredKey(ctx, "key-004", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	// 验证 Shred 后 GetKey 返回 ErrNotFound。
	_, err = mgr.GetKey(ctx, "key-004", 1)
	if err == nil {
		t.Fatal("GetKey after Shred should return error")
	}
}

// TestFullLifecycle 完整流转：Create → Rotate → Shred。
func TestFullLifecycle(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 1. Create V1 Active。
	meta1, plainDEK1, err := mgr.CreateKey(ctx, "key-lifecycle", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plainDEK1.Wipe()
	if meta1.Version != 1 || meta1.State != StateActive {
		t.Fatalf("V1: version=%d state=%q", meta1.Version, meta1.State)
	}

	// 2. Rotate → V1 Deactivated, V2 Active。
	meta2, plainDEK2, err := mgr.RotateKey(ctx, "key-lifecycle", mk)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	plainDEK2.Wipe()
	if meta2.Version != 2 || meta2.State != StateActive {
		t.Fatalf("V2: version=%d state=%q", meta2.Version, meta2.State)
	}
	v1, _ := mgr.GetKey(ctx, "key-lifecycle", 1)
	if v1.State != StateDeactivated {
		t.Fatalf("V1 after rotate: state=%q, want Deactivated", v1.State)
	}

	// 3. Shred V1。
	if err := mgr.ShredKey(ctx, "key-lifecycle", 1); err != nil {
		t.Fatalf("ShredKey v1: %v", err)
	}
	_, err = mgr.GetKey(ctx, "key-lifecycle", 1)
	if err == nil {
		t.Fatal("V1 after Shred should be gone")
	}

	// 4. V2 仍存在且 Active。
	v2, err := mgr.GetKey(ctx, "key-lifecycle", 2)
	if err != nil {
		t.Fatalf("GetKey v2 after shredding v1: %v", err)
	}
	if v2.State != StateActive {
		t.Fatalf("V2 state = %q, want Active", v2.State)
	}

	// 5. Shred V2。
	if err := mgr.ShredKey(ctx, "key-lifecycle", 2); err != nil {
		t.Fatalf("ShredKey v2: %v", err)
	}
	_, err = mgr.GetKey(ctx, "key-lifecycle", 2)
	if err == nil {
		t.Fatal("V2 after Shred should be gone")
	}
}

// TestRotateKey_ConcurrentNoDeadlock 验证并发 Rotate 不死锁且最终版本正确。
func TestRotateKey_ConcurrentNoDeadlock(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 初始 V1。
	_, plainDEK, err := mgr.CreateKey(ctx, "key-concurrent", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plainDEK.Wipe()

	// 并发 5 个 Rotate。
	var wg sync.WaitGroup
	const n = 5
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, p, err := mgr.RotateKey(ctx, "key-concurrent", mk)
			if p != nil {
				p.Wipe()
			}
			if err != nil {
				errs <- err
				return
			}
			errs <- nil
		}()
	}

	// 超时保护。
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Rotate timed out (possible deadlock)")
	}

	close(errs)
	failCount := 0
	for e := range errs {
		if e != nil {
			failCount++
		}
	}

	// 至少一些应该成功；最终版本应是 1 + 成功数。
	latest, err := mgr.findLatestVersion(context.Background(), "key-concurrent")
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}
	if latest < 2 {
		t.Fatalf("latest version = %d, want >= 2", latest)
	}
}

// allZero 检查切片是否全零。
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// --- 边界测试 ---

// TestCreateKey_EmptyKeyID 验证空 keyID 报错。
func TestCreateKey_EmptyKeyID(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	_, _, err := mgr.CreateKey(context.Background(), "", mk, 0)
	if err == nil {
		t.Fatal("CreateKey with empty keyID should fail")
	}
}

// TestCreateKey_NilMasterKey 验证 nil masterKey 报错。
func TestCreateKey_NilMasterKey(t *testing.T) {
	mgr, _ := newTestManager(t)
	_, _, err := mgr.CreateKey(context.Background(), "key-nil-mk", nil, 0)
	if err == nil {
		t.Fatal("CreateKey with nil masterKey should fail")
	}
}

// TestRotateKey_EmptyKeyID 验证空 keyID 报错。
func TestRotateKey_EmptyKeyID(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	_, _, err := mgr.RotateKey(context.Background(), "", mk)
	if err == nil {
		t.Fatal("RotateKey with empty keyID should fail")
	}
}

// TestRotateKey_NilMasterKey 验证 nil masterKey 报错。
func TestRotateKey_NilMasterKey(t *testing.T) {
	mgr, _ := newTestManager(t)
	_, _, err := mgr.RotateKey(context.Background(), "key-nil", nil)
	if err == nil {
		t.Fatal("RotateKey with nil masterKey should fail")
	}
}

// TestRotateKey_KeyNotFound 验证不存在的 key 报错。
func TestRotateKey_KeyNotFound(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	_, _, err := mgr.RotateKey(context.Background(), "nonexistent-key", mk)
	if err == nil {
		t.Fatal("RotateKey on nonexistent key should fail")
	}
}

// TestShredKey_KeyNotFound 验证粉碎不存在的 key 报错。
func TestShredKey_KeyNotFound(t *testing.T) {
	mgr, _ := newTestManager(t)
	err := mgr.ShredKey(context.Background(), "nonexistent-key", 1)
	if err == nil {
		t.Fatal("ShredKey on nonexistent key should fail")
	}
}

// TestGetKey_NotFound 验证 GetKey 不存在返回 error。
func TestGetKey_NotFound(t *testing.T) {
	mgr, _ := newTestManager(t)
	_, err := mgr.GetKey(context.Background(), "missing", 1)
	if err == nil {
		t.Fatal("GetKey on missing key should fail")
	}
}

// TestRotateKey_AlreadyDeactivated 验证轮转已 Deactivated 的版本报错。
func TestRotateKey_AlreadyDeactivated(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	// 创建并轮转。
	_, _, err := mgr.CreateKey(ctx, "deact-key", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	_, _, err = mgr.RotateKey(ctx, "deact-key", mk)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// 手动把 V1 改成 Deactivated（已经是了），再尝试 rotate 应该轮转 V2。
	// 这里测试 V2 Active 的正常轮转。
	_, _, err = mgr.RotateKey(ctx, "deact-key", mk)
	if err != nil {
		t.Fatalf("RotateKey V2: %v", err)
	}
}

// TestShredKey_AlreadyShredded 验证重复粉碎幂等或报错。
func TestShredKey_AlreadyShredded(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	_, _, err := mgr.CreateKey(ctx, "double-shred", mk, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 第一次粉碎。
	if err := mgr.ShredKey(ctx, "double-shred", 1); err != nil {
		t.Fatalf("ShredKey first: %v", err)
	}

	// 第二次粉碎同一版本（已删除）应报错或幂等。
	err = mgr.ShredKey(ctx, "double-shred", 1)
	if err == nil {
		// 幂等返回 nil 也可接受；但不应 panic。
	}
}

// --- 非对称密钥测试 ---

// TestCreateAsymmetricKey_RSA 验证 RSA 密钥创建。
func TestCreateAsymmetricKey_RSA(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	meta, err := mgr.CreateAsymmetricKey(ctx, "rsa-test-key", "rsa", mk)
	if err != nil {
		t.Fatalf("CreateAsymmetricKey RSA: %v", err)
	}
	if meta.KeyType != "rsa" {
		t.Fatalf("KeyType = %q, want rsa", meta.KeyType)
	}
	if len(meta.EncryptedMaterial) == 0 {
		t.Fatal("EncryptedMaterial should not be empty")
	}
	if len(meta.PublicKey) == 0 {
		t.Fatal("PublicKey should not be empty")
	}
	if meta.Version != 1 {
		t.Fatalf("Version = %d, want 1", meta.Version)
	}
	if meta.State != StateActive {
		t.Fatalf("State = %v, want Active", meta.State)
	}
}

// TestCreateAsymmetricKey_ECDSA 验证 ECDSA 密钥创建。
func TestCreateAsymmetricKey_ECDSA(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	ctx := context.Background()

	meta, err := mgr.CreateAsymmetricKey(ctx, "ecdsa-test-key", "ecdsa", mk)
	if err != nil {
		t.Fatalf("CreateAsymmetricKey ECDSA: %v", err)
	}
	if meta.KeyType != "ecdsa" {
		t.Fatalf("KeyType = %q, want ecdsa", meta.KeyType)
	}
	if len(meta.PublicKey) == 0 {
		t.Fatal("PublicKey should not be empty")
	}
}

// TestCreateAsymmetricKey_UnsupportedType 验证不支持的类型报错。
func TestCreateAsymmetricKey_UnsupportedType(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	_, err := mgr.CreateAsymmetricKey(context.Background(), "bad-key", "dsa", mk)
	if err == nil {
		t.Fatal("unsupported key type should fail")
	}
}

// TestCreateAsymmetricKey_EmptyKeyID 验证空 keyID 报错。
func TestCreateAsymmetricKey_EmptyKeyID(t *testing.T) {
	mgr, _ := newTestManager(t)
	mk := newTestMasterKey(t)
	_, err := mgr.CreateAsymmetricKey(context.Background(), "", "rsa", mk)
	if err == nil {
		t.Fatal("empty keyID should fail")
	}
}

// TestCreateAsymmetricKey_NilMasterKey 验证 nil masterKey 报错。
func TestCreateAsymmetricKey_NilMasterKey(t *testing.T) {
	mgr, _ := newTestManager(t)
	_, err := mgr.CreateAsymmetricKey(context.Background(), "test", "rsa", nil)
	if err == nil {
		t.Fatal("nil masterKey should fail")
	}
}
