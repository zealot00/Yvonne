package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// newTestStore 创建测试用 MemoryStore。
func newTestStore(t *testing.T) storage.KVStore {
	return storage.NewMemoryStore()
}

// TestTransitKey_GenerateAndUnwrap 验证生成传输密钥+解密往返。
func TestTransitKey_GenerateAndUnwrap(t *testing.T) {
	tm := NewTransitKeyManager()

	pub, err := tm.GenerateTransitKey()
	if err != nil {
		t.Fatalf("GenerateTransitKey: %v", err)
	}
	if pub.PublicKey == "" || pub.KeyID == "" {
		t.Fatal("public key or key_id empty")
	}

	// 解析公钥并加密 32 字节 DEK。
	rsaPub := parsePubPEM(t, pub.PublicKey)
	originalDEK := make([]byte, 32)
	for i := range originalDEK {
		originalDEK[i] = byte(i)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, originalDEK, nil)
	if err != nil {
		t.Fatalf("RSA encrypt: %v", err)
	}

	// 解密验证。
	decrypted, err := tm.UnwrapWithTransitKey(pub.KeyID, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(decrypted) != 32 {
		t.Fatalf("decrypted len = %d", len(decrypted))
	}
	for i, b := range decrypted {
		if b != byte(i) {
			t.Fatalf("byte %d: got %d, want %d", i, b, i)
		}
	}
}

// TestTransitKey_BurnAfterReading 验证解密后私钥被销毁。
func TestTransitKey_BurnAfterReading(t *testing.T) {
	tm := NewTransitKeyManager()
	pub, _ := tm.GenerateTransitKey()

	wrapped := wrapWithPub(t, pub.PublicKey, []byte("test"))

	_, err := tm.UnwrapWithTransitKey(pub.KeyID, wrapped)
	if err != nil {
		t.Fatalf("first unwrap: %v", err)
	}

	_, err = tm.UnwrapWithTransitKey(pub.KeyID, wrapped)
	if err == nil {
		t.Fatal("second unwrap should fail (burn after reading)")
	}
}

// TestTransitKey_NotFound 验证不存在的 keyID 报错。
func TestTransitKey_NotFound(t *testing.T) {
	tm := NewTransitKeyManager()
	_, err := tm.UnwrapWithTransitKey("nonexistent", []byte("x"))
	if err == nil {
		t.Fatal("should fail for nonexistent key")
	}
}

// TestImportKey_FullFlow 验证完整 BYOK 导入流程。
func TestImportKey_FullFlow(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	tm := NewTransitKeyManager()
	ctx := context.Background()

	// 1. 生成传输密钥。
	pub, err := tm.GenerateTransitKey()
	if err != nil {
		t.Fatalf("GenerateTransitKey: %v", err)
	}

	// 2. 用公钥加密外部 DEK。
	externalDEK := make([]byte, 32)
	for i := range externalDEK {
		externalDEK[i] = byte(i + 1)
	}
	wrapped := wrapWithPub(t, pub.PublicKey, externalDEK)

	// 3. 导入。
	meta, err := mgr.ImportKey(ctx, "imported-key", pub.KeyID, wrapped, tm, mk)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if meta.KeyID != "imported-key" {
		t.Fatalf("KeyID = %q", meta.KeyID)
	}
	if meta.Version != 1 {
		t.Fatalf("Version = %d", meta.Version)
	}
	if meta.State != StateActive {
		t.Fatalf("State = %v", meta.State)
	}

	// 4. 验证导入的密钥可用于解密（用 CMK 解密 EncryptedMaterial）。
	decrypted, err := crypto.DecryptGCM(mk, meta.EncryptedMaterial)
	if err != nil {
		t.Fatalf("decrypt imported DEK: %v", err)
	}
	defer decrypted.Wipe()

	var got []byte
	_ = decrypted.WithKey(func(d []byte) error {
		got = make([]byte, len(d))
		copy(got, d)
		return nil
	})
	if string(got) != string(externalDEK) {
		t.Fatal("imported DEK mismatch")
	}
}

// TestTransitKey_CleanupExpired 验证过期清理。
func TestTransitKey_CleanupExpired(t *testing.T) {
	tm := NewTransitKeyManager()
	pub, _ := tm.GenerateTransitKey()

	// 手动设置过期。
	tm.mu.Lock()
	if entry, ok := tm.keys[pub.KeyID]; ok {
		entry.expiresAt = time.Now().UTC().Add(-1 * time.Hour)
	}
	tm.mu.Unlock()

	tm.CleanupExpired()

	tm.mu.RLock()
	_, exists := tm.keys[pub.KeyID]
	tm.mu.RUnlock()
	if exists {
		t.Fatal("expired key should be cleaned up")
	}
}

// --- 辅助函数 ---

func parsePubPEM(t *testing.T, pubPEM string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("decode PEM failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("not RSA public key")
	}
	return rsaPub
}

func wrapWithPub(t *testing.T, pubPEM string, data []byte) []byte {
	t.Helper()
	pub := parsePubPEM(t, pubPEM)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		t.Fatalf("RSA encrypt: %v", err)
	}
	return wrapped
}

// 确保 fmt 被引用。
var _ = fmt.Sprintf
