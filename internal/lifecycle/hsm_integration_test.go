//go:build integration

// HSM + 国密套件集成测试。
//
// 验证：
//  1. HSM 模式全链路：create → encrypt → decrypt → rotate → shred
//  2. HSM KEKType 标注正确
//  3. HSM 紧急封印后操作拒绝
//  4. Software KEK 与 HSM KEK 隔离（跨 KEK 解密失败）
package lifecycle

import (
	"context"
	"testing"
	"time"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// 时间辅助常量（避免直接 import time 的未使用警告）。
var (
	timeNowUTC = func() time.Time { return time.Now().UTC() }
	timeHour   = time.Hour
)

// newHSMKEK 创建测试用 HSM KEK（MockHSMBackend）。
func newHSMKEK(t *testing.T) (seal.KEK, *seal.MockHSMBackend) {
	t.Helper()
	backend, err := seal.NewMockHSMBackend()
	if err != nil {
		t.Fatalf("NewMockHSMBackend: %v", err)
	}
	t.Cleanup(backend.Close)
	return seal.NewHSMKEK(backend), backend
}

// newSoftwareKEK 创建测试用软件 KEK。
func newSoftwareKEK(t *testing.T) seal.KEK {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	return seal.NewSoftwareKEK(mk)
}

// === HSM 全链路测试 ===

// TestHSM_CreateAndDecrypt 验证 HSM 模式下创建密钥并解密往返。
func TestHSM_CreateAndDecrypt(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	// 1. 创建密钥。
	meta, plainDEK, err := mgr.CreateKey(ctx, "hsm-key-001", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	defer plainDEK.Wipe()

	// 2. 验证 KEKType 标注。
	if meta.KEKType != "hsm" {
		t.Fatalf("KEKType = %q, want hsm", meta.KEKType)
	}

	// 3. 用 KEK 解密 EncryptedMaterial，应得到原始 DEK。
	decryptedDEK, err := kek.UnwrapDEK(meta.EncryptedMaterial)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer decryptedDEK.Wipe()

	// 4. 验证解密的 DEK 与原始一致。
	var origDEK, gotDEK []byte
	_ = plainDEK.WithKey(func(d []byte) error { origDEK = make([]byte, len(d)); copy(origDEK, d); return nil })
	_ = decryptedDEK.WithKey(func(d []byte) error { gotDEK = make([]byte, len(d)); copy(gotDEK, d); return nil })
	defer func() {
		for i := range origDEK {
			origDEK[i] = 0
		}
		for i := range gotDEK {
			gotDEK[i] = 0
		}
	}()

	if string(origDEK) != string(gotDEK) {
		t.Fatal("HSM DEK round-trip mismatch")
	}
}

// TestHSM_EncryptDecryptBusinessData 验证 HSM 模式下加密/解密业务数据。
func TestHSM_EncryptDecryptBusinessData(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	// 创建密钥。
	meta, _, err := mgr.CreateKey(ctx, "hsm-business", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 用 KEK 解出 DEK。
	storedDEK, err := kek.UnwrapDEK(meta.EncryptedMaterial)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer storedDEK.Wipe()

	// 用 DEK 加密业务数据。
	plaintext := []byte("sensitive business data")
	ciphertext, err := crypto.EncryptVersioned(storedDEK, uint32(meta.Version), plaintext)
	if err != nil {
		t.Fatalf("EncryptVersioned: %v", err)
	}

	// 用 DEK 解密业务数据。
	decryptedSB, _, err := crypto.DecryptVersioned(storedDEK, ciphertext)
	if err != nil {
		t.Fatalf("DecryptVersioned: %v", err)
	}
	defer decryptedSB.Wipe()

	var got []byte
	_ = decryptedSB.WithKey(func(d []byte) error { got = make([]byte, len(d)); copy(got, d); return nil })
	defer func() {
		for i := range got {
			got[i] = 0
		}
	}()

	if string(got) != string(plaintext) {
		t.Fatal("business data round-trip mismatch")
	}
}

// TestHSM_RotateKey 验证 HSM 模式下轮转密钥。
func TestHSM_RotateKey(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	// 创建 V1。
	meta1, _, err := mgr.CreateKey(ctx, "hsm-rotate", kek, 0)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if meta1.KEKType != "hsm" {
		t.Fatalf("V1 KEKType = %q", meta1.KEKType)
	}

	// 轮转到 V2。
	meta2, _, err := mgr.RotateKey(ctx, "hsm-rotate", kek)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if meta2.Version != 2 {
		t.Fatalf("V2 version = %d", meta2.Version)
	}
	if meta2.KEKType != "hsm" {
		t.Fatalf("V2 KEKType = %q", meta2.KEKType)
	}

	// V1 应为 Deactivated。
	v1, _ := mgr.GetKey(ctx, "hsm-rotate", 1)
	if v1.State != StateDeactivated {
		t.Fatalf("V1 state = %v", v1.State)
	}

	// V2 应为 Active。
	v2, _ := mgr.GetKey(ctx, "hsm-rotate", 2)
	if v2.State != StateActive {
		t.Fatalf("V2 state = %v", v2.State)
	}
}

// TestHSM_GenerateDataKey 验证 HSM 模式下 GDK。
func TestHSM_GenerateDataKey(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	mgr.CreateKey(ctx, "hsm-gdk", kek, 0)

	plainDEK, ciphertext, err := mgr.GenerateDataKey(ctx, "hsm-gdk", kek)
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	defer plainDEK.Wipe()

	if len(ciphertext) < 16 {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}

	// 验证密文含版本前缀。
	version := uint32(ciphertext[0])<<24 | uint32(ciphertext[1])<<16 | uint32(ciphertext[2])<<8 | uint32(ciphertext[3])
	if version != 1 {
		t.Fatalf("GDK version = %d, want 1", version)
	}
}

// TestHSM_ImportKey 验证 HSM 模式下 BYOK 导入。
func TestHSM_ImportKey(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	tm := NewTransitKeyManager()
	ctx := context.Background()

	// 生成传输密钥。
	pub, err := tm.GenerateTransitKey()
	if err != nil {
		t.Fatalf("GenerateTransitKey: %v", err)
	}

	// 用传输公钥加密外部 DEK。
	externalDEK := make([]byte, 32)
	for i := range externalDEK {
		externalDEK[i] = byte(i + 1)
	}
	wrapped := wrapWithPub(t, pub.PublicKey, externalDEK)

	// 导入。
	meta, err := mgr.ImportKey(ctx, "hsm-imported", pub.KeyID, wrapped, tm, kek)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if meta.KEKType != "hsm" {
		t.Fatalf("KEKType = %q, want hsm", meta.KEKType)
	}

	// 验证导入的 DEK 可用 KEK 解密。
	decrypted, err := kek.UnwrapDEK(meta.EncryptedMaterial)
	if err != nil {
		t.Fatalf("UnwrapDEK imported: %v", err)
	}
	defer decrypted.Wipe()

	var got []byte
	_ = decrypted.WithKey(func(d []byte) error { got = make([]byte, len(d)); copy(got, d); return nil })
	defer func() {
		for i := range got {
			got[i] = 0
		}
	}()

	if string(got) != string(externalDEK) {
		t.Fatal("imported DEK mismatch")
	}
}

// TestHSM_SoftDeleteAndRestore 验证 HSM 模式下软删除+恢复。
func TestHSM_SoftDeleteAndRestore(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	mgr.CreateKey(ctx, "hsm-softdel", kek, 0)

	// 软删除。
	if err := mgr.SoftDeleteKey(ctx, "hsm-softdel", 1); err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}
	meta, _ := mgr.GetKey(ctx, "hsm-softdel", 1)
	if meta.State != StateSoftDeleted {
		t.Fatalf("State = %v", meta.State)
	}

	// 恢复。
	if err := mgr.RestoreKey(ctx, "hsm-softdel", 1); err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}
	meta, _ = mgr.GetKey(ctx, "hsm-softdel", 1)
	if meta.State != StateDeactivated {
		t.Fatalf("State after restore = %v", meta.State)
	}
}

// TestHSM_ShredKey 验证 HSM 模式下物理粉碎。
func TestHSM_ShredKey(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	kek, _ := newHSMKEK(t)
	ctx := context.Background()

	mgr.CreateKey(ctx, "hsm-shred", kek, 0)

	if err := mgr.ShredKey(ctx, "hsm-shred", 1); err != nil {
		t.Fatalf("ShredKey: %v", err)
	}

	_, err := mgr.GetKey(ctx, "hsm-shred", 1)
	if err == nil {
		t.Fatal("key should be destroyed")
	}
}

// === KEK 隔离测试 ===

// TestKEKIsolation_SoftwareCannotUnwrapHSM 验证软件 KEK 无法解密 HSM 加密的 DEK。
func TestKEKIsolation_SoftwareCannotUnwrapHSM(t *testing.T) {
	hsmKEK, _ := newHSMKEK(t)
	swKEK := newSoftwareKEK(t)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	// HSM 加密。
	ct, err := hsmKEK.WrapDEK(plainDEK)
	if err != nil {
		t.Fatalf("HSM WrapDEK: %v", err)
	}

	// 软件 KEK 解密应失败。
	_, err = swKEK.UnwrapDEK(ct)
	if err == nil {
		t.Fatal("software KEK should not unwrap HSM-encrypted DEK")
	}
}

// TestKEKIsolation_HSMCannotUnwrapSoftware 验证 HSM KEK 无法解密软件加密的 DEK。
func TestKEKIsolation_HSMCannotUnwrapSoftware(t *testing.T) {
	hsmKEK, _ := newHSMKEK(t)
	swKEK := newSoftwareKEK(t)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	// 软件加密。
	ct, err := swKEK.WrapDEK(plainDEK)
	if err != nil {
		t.Fatalf("SW WrapDEK: %v", err)
	}

	// HSM KEK 解密应失败。
	_, err = hsmKEK.UnwrapDEK(ct)
	if err == nil {
		t.Fatal("HSM KEK should not unwrap software-encrypted DEK")
	}
}

// TestKEKIsolation_TypeCheck 验证 KEK Type 方法。
func TestKEKIsolation_TypeCheck(t *testing.T) {
	hsmKEK, _ := newHSMKEK(t)
	swKEK := newSoftwareKEK(t)

	if hsmKEK.Type() != seal.KEKTypeHSM {
		t.Fatalf("HSM KEK Type = %v", hsmKEK.Type())
	}
	if swKEK.Type() != seal.KEKTypeSoftware {
		t.Fatalf("SW KEK Type = %v", swKEK.Type())
	}
}

// === HSM Unsealer 集成测试 ===

// TestHSMUnsealer_FullLifecycle 验证 HSMUnsealer 完整生命周期。
func TestHSMUnsealer_FullLifecycle(t *testing.T) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()

	unsealer := seal.NewHSMUnsealer(backend)

	// Unsealed 状态下 KEKRef 可用。
	called := false
	err := unsealer.KEKRef(func(kek seal.KEK) error {
		called = true
		if kek.Type() != seal.KEKTypeHSM {
			t.Fatalf("Type = %v", kek.Type())
		}
		// 验证 KEK 可用。
		plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
		defer plainDEK.Wipe()
		ct, e := kek.WrapDEK(plainDEK)
		if e != nil {
			return e
		}
		_, e = kek.UnwrapDEK(ct)
		return e
	})
	if err != nil {
		t.Fatalf("KEKRef: %v", err)
	}
	if !called {
		t.Fatal("KEKRef action not called")
	}

	// Seal 后 KEKRef 失败。
	unsealer.Seal(context.Background())
	err = unsealer.KEKRef(func(kek seal.KEK) error {
		t.Fatal("should not be called when sealed")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail when sealed")
	}

	// MasterKeyRef 始终返回 error（HSM 不暴露明文 CMK）。
	err = unsealer.MasterKeyRef(func(key *memguard.SecureBuffer) error {
		t.Fatal("MasterKeyRef should not expose key in HSM mode")
		return nil
	})
	if err == nil {
		t.Fatal("MasterKeyRef should fail in HSM mode")
	}
}

// === 并发测试 ===

// TestHSM_ConcurrentWrapUnwrap 验证 HSM KEK 并发安全。
func TestHSM_ConcurrentWrapUnwrap(t *testing.T) {
	kek, _ := newHSMKEK(t)

	done := make(chan error, 20)
	for i := 0; i < 10; i++ {
		go func() {
			plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
			defer plainDEK.Wipe()
			ct, e := kek.WrapDEK(plainDEK)
			if e != nil {
				done <- e
				return
			}
			_, e = kek.UnwrapDEK(ct)
			done <- e
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent error: %v", err)
		}
	}
}

// === RotationDaemon HSM 模式测试 ===

// TestRotationDaemon_HSMMode 验证 HSM 模式下自动轮转守护进程。
func TestRotationDaemon_HSMMode(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)

	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	hsmUnsealer := seal.NewHSMUnsealer(backend)

	ctx := context.Background()

	// 创建密钥，设置已过期的 NextRotationAt。
	mgr.CreateKey(ctx, "hsm-daemon-test", seal.NewHSMKEK(backend), 1)
	meta, _ := mgr.GetKey(ctx, "hsm-daemon-test", 1)
	meta.NextRotationAt = timeNowUTC().Add(-1 * timeHour)
	saveMetaDirect(t, mgr, *meta)
	mgr.cache.invalidate("hsm-daemon-test")

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, hsmUnsealer, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	if auditCount != 1 {
		t.Fatalf("expected 1 rotation, got %d", auditCount)
	}

	// 验证轮转到 V2。
	latest, _ := mgr.findLatestVersion(ctx, "hsm-daemon-test")
	if latest != 2 {
		t.Fatalf("expected v2, got v%d", latest)
	}

	// 验证 V2 KEKType 为 hsm。
	v2, _ := mgr.GetKey(ctx, "hsm-daemon-test", 2)
	if v2.KEKType != "hsm" {
		t.Fatalf("V2 KEKType = %q, want hsm", v2.KEKType)
	}
}
