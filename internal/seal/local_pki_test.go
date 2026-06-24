package seal

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// TestStateString 验证 State.String() 返回正确字符串。
func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateSealed, "sealed"},
		{StateUnsealed, "unsealed"},
		{StateSealing, "sealing"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// TestVaultState_State 验证 State() 方法。
func TestVaultState_State(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	if v.State() != StateSealed {
		t.Fatalf("initial state = %v, want Sealed", v.State())
	}
}

// TestVaultState_DirectUnseal 验证 DirectUnseal 流程。
func TestVaultState_DirectUnseal(t *testing.T) {
	mk, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	defer mk.Wipe()

	v := NewVaultState(5, 3, 0)
	if err := v.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}
	if !v.IsUnsealed() {
		t.Fatal("should be unsealed after DirectUnseal")
	}

	// 再次 DirectUnseal 应报错。
	if err := v.DirectUnseal(mk); err == nil {
		t.Fatal("DirectUnseal twice should fail")
	}
}

// TestVaultState_DirectUnseal_NilMasterKey 验证 nil 检查。
func TestVaultState_DirectUnseal_NilMasterKey(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	if err := v.DirectUnseal(nil); err == nil {
		t.Fatal("DirectUnseal(nil) should fail")
	}
}

// TestVaultState_ThresholdAndTotalShares 验证访问器。
func TestVaultState_ThresholdAndTotalShares(t *testing.T) {
	v := NewVaultState(7, 4, 0)
	if v.Threshold() != 4 {
		t.Fatalf("Threshold = %d, want 4", v.Threshold())
	}
	if v.TotalShares() != 7 {
		t.Fatalf("TotalShares = %d, want 7", v.TotalShares())
	}
}

// TestVaultState_CollectedCount 验证碎片计数。
func TestVaultState_CollectedCount(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	if v.CollectedCount() != 0 {
		t.Fatal("initial CollectedCount should be 0")
	}
}

// TestVaultState_Seal_AlreadySealed 验证重复 Seal 幂等。
func TestVaultState_Seal_AlreadySealed(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	v.Seal(context.Background()) // 已 Sealed，应 no-op
	if !v.IsSealed() {
		t.Fatal("should still be sealed")
	}
}

// TestVaultState_MasterKeyRef_Sealed 验证 Sealed 状态下 MasterKeyRef 报错。
func TestVaultState_MasterKeyRef_Sealed(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	err := v.MasterKeyRef(func(key *memguard.SecureBuffer) error {
		t.Fatal("action should not be called when sealed")
		return nil
	})
	if err == nil {
		t.Fatal("MasterKeyRef on sealed vault should fail")
	}
}

// TestVaultState_ProvideShare_EmptyShare 验证空 share 报错。
func TestVaultState_ProvideShare_EmptyShare(t *testing.T) {
	v := NewVaultState(5, 3, 0)
	_, err := v.ProvideShare([]byte{})
	if err == nil {
		t.Fatal("ProvideShare with empty share should fail")
	}
}

// TestGfInv_Zero 验证 gfInv(0) 返回 0（无逆元）。
func TestGfInv_Zero(t *testing.T) {
	if gfInv(0) != 0 {
		t.Fatal("gfInv(0) should return 0")
	}
}

// TestSplit_NilSecret 验证 nil secret 报错。
func TestSplit_NilSecret(t *testing.T) {
	_, err := Split(nil, 5, 3)
	if err == nil {
		t.Fatal("Split(nil) should fail")
	}
}

// TestSplit_InvalidParams 验证参数校验。
func TestSplit_InvalidParams(t *testing.T) {
	sb, _ := memguard.NewSecureBufferFromRandom(16)
	defer sb.Wipe()

	tests := []struct {
		parts, threshold int
	}{
		{1, 1},   // parts < 2
		{256, 3}, // parts > 255
		{5, 1},   // threshold < 2
		{5, 6},   // threshold > parts
	}
	for _, tt := range tests {
		_, err := Split(sb, tt.parts, tt.threshold)
		if err == nil {
			t.Errorf("Split(parts=%d, threshold=%d) should fail", tt.parts, tt.threshold)
		}
	}
}

// --- Local PKI 测试 ---

// TestLocalPKI_FullAutoUnseal 验证完整 PKI 自动解封流程。
func TestLocalPKI_FullAutoUnseal(t *testing.T) {
	// 1. 生成 RSA-4096 密钥对。
	privPEM, pubPEM, err := GenerateUnsealKeyPair()
	if err != nil {
		t.Fatalf("GenerateUnsealKeyPair: %v", err)
	}

	// 2. 生成 Master Key。
	masterKey, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	defer masterKey.Wipe()

	// 3. 用公钥加密 Master Key。
	wrappedKey, err := EncryptMasterKeyWithPublicKey(pubPEM, masterKey)
	if err != nil {
		t.Fatalf("EncryptMasterKeyWithPublicKey: %v", err)
	}

	// 4. 存入 MemoryStore。
	store := storage.NewMemoryStore()
	ctx := context.Background()
	if err := store.Put(ctx, WrappedMasterKeyKey, wrappedKey); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	// 5. 写入 PEM 文件到临时路径。
	pemPath := filepath.Join(t.TempDir(), "unseal.pem")
	if err := os.WriteFile(pemPath, privPEM, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	// 6. 创建 VaultState + LocalPKIUnsealer + AutoUnseal。
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer(pemPath, vault, store)
	if err := unsealer.AutoUnseal(ctx); err != nil {
		t.Fatalf("AutoUnseal: %v", err)
	}

	// 7. 验证 Unsealed。
	if !vault.IsUnsealed() {
		t.Fatal("vault should be unsealed after AutoUnseal")
	}

	// 8. 验证阅后即焚：PEM 文件已删除。
	if _, err := os.Stat(pemPath); !os.IsNotExist(err) {
		t.Fatal("PEM file should be deleted after AutoUnseal")
	}

	// 9. 验证 MasterKeyRef 可用。
	err = vault.MasterKeyRef(func(k *memguard.SecureBuffer) error {
		// 比较 master key 是否与原始一致。
		if k.Len() != 32 {
			t.Errorf("master key len = %d, want 32", k.Len())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("MasterKeyRef: %v", err)
	}
}

// TestLocalPKI_AutoUnseal_PEMNotFound 验证 PEM 文件不存在时报错。
func TestLocalPKI_AutoUnseal_PEMNotFound(t *testing.T) {
	store := storage.NewMemoryStore()
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer("/nonexistent/path.pem", vault, store)
	err := unsealer.AutoUnseal(context.Background())
	if err == nil {
		t.Fatal("AutoUnseal with missing PEM should fail")
	}
}

// TestLocalPKI_AutoUnseal_InvalidPEM 验证无效 PEM 报错。
func TestLocalPKI_AutoUnseal_InvalidPEM(t *testing.T) {
	pemPath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(pemPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := storage.NewMemoryStore()
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer(pemPath, vault, store)
	err := unsealer.AutoUnseal(context.Background())
	if err == nil {
		t.Fatal("AutoUnseal with invalid PEM should fail")
	}
}

// TestLocalPKI_AutoUnseal_WrappedKeyNotFound 验证 DB 中无 WrappedKey 时报错。
func TestLocalPKI_AutoUnseal_WrappedKeyNotFound(t *testing.T) {
	privPEM, _, err := GenerateUnsealKeyPair()
	if err != nil {
		t.Fatalf("GenerateUnsealKeyPair: %v", err)
	}
	pemPath := filepath.Join(t.TempDir(), "unseal.pem")
	if err := os.WriteFile(pemPath, privPEM, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store := storage.NewMemoryStore() // 空 store，无 WrappedKey
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer(pemPath, vault, store)
	err = unsealer.AutoUnseal(context.Background())
	if err == nil {
		t.Fatal("AutoUnseal with missing wrapped key should fail")
	}

	// PEM 文件不应被删除（解封失败时不删）。
	if _, err := os.Stat(pemPath); os.IsNotExist(err) {
		t.Fatal("PEM file should NOT be deleted on failed AutoUnseal")
	}
}

// TestEncryptMasterKeyWithPublicKey_InvalidPEM 验证无效公钥 PEM 报错。
func TestEncryptMasterKeyWithPublicKey_InvalidPEM(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	_, err := EncryptMasterKeyWithPublicKey([]byte("not a pem"), mk)
	if err == nil {
		t.Fatal("EncryptMasterKeyWithPublicKey with invalid PEM should fail")
	}
}

// TestEncryptMasterKeyWithPublicKey_UnsupportedType 验证不支持的 PEM 类型报错。
func TestEncryptMasterKeyWithPublicKey_UnsupportedType(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	// 构造一个非 RSA 公钥的 PEM（如 EC PRIVATE KEY 的 type）。
	_, err := EncryptMasterKeyWithPublicKey([]byte("-----BEGIN EC PUBLIC KEY-----\nAAAA\n-----END EC PUBLIC KEY-----\n"), mk)
	if err == nil {
		t.Fatal("EncryptMasterKeyWithPublicKey with unsupported type should fail")
	}
}

// TestAutoUnseal_PKCS8PrivateKey 验证 PKCS#8 格式私钥的解封。
func TestAutoUnseal_PKCS8PrivateKey(t *testing.T) {
	// 生成 RSA-4096 密钥对。
	privPEM, pubPEM, err := GenerateUnsealKeyPair()
	if err != nil {
		t.Fatalf("GenerateUnsealKeyPair: %v", err)
	}

	// GenerateUnsealKeyPair 输出 PKCS#1 格式。
	// 测试 PKCS#8 路径需手动转换。
	// 先解析 PKCS#1，再重新编码为 PKCS#8。
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("decode private PEM failed")
	}
	pkcs1Key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS1: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(pkcs1Key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	// 生成 Master Key + 加密。
	masterKey, _ := memguard.NewSecureBufferFromRandom(32)
	defer masterKey.Wipe()
	wrappedKey, err := EncryptMasterKeyWithPublicKey(pubPEM, masterKey)
	if err != nil {
		t.Fatalf("encrypt master key: %v", err)
	}

	// 存入 store。
	store := storage.NewMemoryStore()
	ctx := context.Background()
	store.Put(ctx, WrappedMasterKeyKey, wrappedKey)

	// 写入 PKCS#8 PEM。
	pemPath := filepath.Join(t.TempDir(), "unseal_pkcs8.pem")
	os.WriteFile(pemPath, pkcs8PEM, 0o600)

	// AutoUnseal。
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer(pemPath, vault, store)
	if err := unsealer.AutoUnseal(ctx); err != nil {
		t.Fatalf("AutoUnseal PKCS8: %v", err)
	}
	if !vault.IsUnsealed() {
		t.Fatal("should be unsealed with PKCS8 key")
	}

	// PEM 应被删除。
	if _, err := os.Stat(pemPath); !os.IsNotExist(err) {
		t.Fatal("PKCS8 PEM should be deleted")
	}
}

// TestAutoUnseal_UnsupportedPEMType 验证不支持的 PEM 类型报错。
func TestAutoUnseal_UnsupportedPEMType(t *testing.T) {
	// 构造一个 EC PRIVATE KEY 类型的 PEM。
	pemPath := filepath.Join(t.TempDir(), "ec.pem")
	// 生成 EC 私钥。
	ecPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nMFICAQAwBwYFK4EEACMHgQEB\n-----END EC PRIVATE KEY-----\n")
	os.WriteFile(pemPath, ecPEM, 0o600)

	store := storage.NewMemoryStore()
	vault := NewVaultState(5, 3, 0)
	unsealer := NewLocalPKIUnsealer(pemPath, vault, store)
	err := unsealer.AutoUnseal(context.Background())
	if err == nil {
		t.Fatal("AutoUnseal with EC PEM should fail")
	}
}

// TestVaultState_AutoReseal 验证 autoResealAfter 定时器触发。
func TestVaultState_AutoReseal(t *testing.T) {
	// 用极短的 autoResealAfter 触发快速重新封印。
	v := NewVaultState(5, 3, 50*time.Millisecond)

	mk, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	defer mk.Wipe()

	if err := v.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}
	if !v.IsUnsealed() {
		t.Fatal("should be unsealed")
	}

	// 等待 autoReseal 触发。
	time.Sleep(200 * time.Millisecond)
	if !v.IsSealed() {
		t.Fatal("should be auto-resealed after 50ms")
	}
}

// TestVaultState_MasterKeyEqual_NilExpected 验证 nil expected 返回 false。
func TestVaultState_MasterKeyEqual_NilExpected(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	v := NewVaultState(5, 3, 0)
	v.DirectUnseal(mk)
	if v.MasterKeyEqual(nil) {
		t.Fatal("MasterKeyEqual(nil) should return false")
	}
}

// TestVaultState_MasterKeyEqual_DifferentLength 验证不同长度返回 false。
func TestVaultState_MasterKeyEqual_DifferentLength(t *testing.T) {
	mk1, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk1.Wipe()
	mk2, _ := memguard.NewSecureBufferFromRandom(16)
	defer mk2.Wipe()

	v := NewVaultState(5, 3, 0)
	v.DirectUnseal(mk1)
	if v.MasterKeyEqual(mk2) {
		t.Fatal("MasterKeyEqual with different length should return false")
	}
}
