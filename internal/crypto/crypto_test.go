package crypto

import (
	"bytes"
	"errors"
	"testing"

	"yvonne/internal/memguard"
)

// helper: 构造一个 32 字节的随机 SecureBuffer 作为测试密钥。
func newTestKey(t *testing.T) *memguard.SecureBuffer {
	t.Helper()
	key, err := memguard.NewSecureBufferFromRandom(gcmKeySize)
	if err != nil {
		t.Fatalf("newTestKey: %v", err)
	}
	t.Cleanup(func() { key.Wipe() })
	return key
}

// TestEncryptDecryptRoundTrip 验证加密后再解密能还原原始明文。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ciphertext, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}

	// 密文必须比明文长（Nonce 12 + Tag 16 = 至少 28 字节开销）。
	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("ciphertext too short: len=%d, plaintext=%d", len(ciphertext), len(plaintext))
	}

	// 密文不应等于明文（粗略防误用）。
	if bytes.Equal(ciphertext[gcmNonceSize:], plaintext) {
		t.Fatal("ciphertext body equals plaintext; encryption may be broken")
	}

	decrypted, err := DecryptGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptGCM: %v", err)
	}
	defer decrypted.Wipe()

	var got []byte
	if err := decrypted.WithKey(func(secret []byte) error {
		got = append(got, secret...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}

	// 清理临时明文拷贝。
	for i := range got {
		got[i] = 0
	}
}

// TestDecryptTamperedCiphertext 防篡改测试：修改密文区任意一字节，
// 解密必须报错且不返回任何明文（SecureBuffer 为 nil）。
func TestDecryptTamperedCiphertext(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("sensitive payload 0123456789")

	ciphertext, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}

	// 复制一份并篡改密文区（Nonce 之后）的某个字节。
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// 翻转密文区最后一字节（位于 AuthTag 内）。
	tampered[len(tampered)-1] ^= 0xff

	sb, err := DecryptGCM(key, tampered)
	if err == nil {
		if sb != nil {
			sb.Wipe()
		}
		t.Fatal("DecryptGCM on tampered ciphertext: expected error, got nil")
	}
	if sb != nil {
		sb.Wipe()
		t.Fatal("DecryptGCM on tampered ciphertext: returned non-nil SecureBuffer (plaintext leak)")
	}
}

// TestDecryptTamperedNonce 防篡改测试：修改 Nonce 的某字节，
// 解密必须报错且不返回任何明文。
func TestDecryptTamperedNonce(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("another secret payload")

	ciphertext, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// 翻转 Nonce 首字节。
	tampered[0] ^= 0xff

	sb, err := DecryptGCM(key, tampered)
	if err == nil {
		if sb != nil {
			sb.Wipe()
		}
		t.Fatal("DecryptGCM on tampered nonce: expected error, got nil")
	}
	if sb != nil {
		sb.Wipe()
		t.Fatal("DecryptGCM on tampered nonce: returned non-nil SecureBuffer (plaintext leak)")
	}
}

// TestDecryptWrongKey 验证用错误密钥解密必然失败，且不返回明文。
func TestDecryptWrongKey(t *testing.T) {
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	plaintext := []byte("data encrypted under key1")

	ciphertext, err := EncryptGCM(key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}

	sb, err := DecryptGCM(key2, ciphertext)
	if err == nil {
		if sb != nil {
			sb.Wipe()
		}
		t.Fatal("DecryptGCM with wrong key: expected error, got nil")
	}
	if sb != nil {
		sb.Wipe()
		t.Fatal("DecryptGCM with wrong key: returned non-nil SecureBuffer (plaintext leak)")
	}
}

// TestDecryptShortCiphertext 验证短于 Nonce 长度的输入直接报错。
func TestDecryptShortCiphertext(t *testing.T) {
	key := newTestKey(t)
	short := []byte{0x01, 0x02, 0x03}

	sb, err := DecryptGCM(key, short)
	if err == nil {
		if sb != nil {
			sb.Wipe()
		}
		t.Fatal("DecryptGCM on short input: expected error, got nil")
	}
	if sb != nil {
		sb.Wipe()
		t.Fatal("DecryptGCM on short input: returned non-nil SecureBuffer")
	}
}

// TestGenerateDataKey 验证 GenerateDataKey 流程：
//   - 明文 DEK 为 32 字节
//   - 密文 DEK 可被同一 masterKey 解密回相同明文
//   - 两次生成的 DEK 不相同
func TestGenerateDataKey(t *testing.T) {
	masterKey, err := memguard.NewSecureBufferFromRandom(gcmKeySize)
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	defer masterKey.Wipe()

	// 第一次生成。
	ptDEK1, ctDEK1, err := GenerateDataKey(masterKey)
	if err != nil {
		t.Fatalf("GenerateDataKey #1: %v", err)
	}
	defer ptDEK1.Wipe()

	if ptDEK1.IsDestroyed() {
		t.Fatal("plaintext DEK #1 already destroyed")
	}
	var dek1 []byte
	if err := ptDEK1.WithKey(func(secret []byte) error {
		dek1 = append(dek1, secret...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey #1: %v", err)
	}
	defer func() {
		for i := range dek1 {
			dek1[i] = 0
		}
	}()

	if len(dek1) != dekSize {
		t.Fatalf("DEK size = %d, want %d", len(dek1), dekSize)
	}

	// 密文 DEK 用 masterKey 解密应还原相同明文。
	decrypted, err := DecryptGCM(masterKey, ctDEK1)
	if err != nil {
		t.Fatalf("decrypt encryptedDEK #1: %v", err)
	}
	defer decrypted.Wipe()

	var dek1Dec []byte
	if err := decrypted.WithKey(func(secret []byte) error {
		dek1Dec = append(dek1Dec, secret...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey decrypted: %v", err)
	}
	defer func() {
		for i := range dek1Dec {
			dek1Dec[i] = 0
		}
	}()

	if !bytes.Equal(dek1, dek1Dec) {
		t.Fatal("decrypted DEK does not match original plaintext DEK")
	}

	// 第二次生成应得到不同的 DEK。
	ptDEK2, _, err := GenerateDataKey(masterKey)
	if err != nil {
		t.Fatalf("GenerateDataKey #2: %v", err)
	}
	defer ptDEK2.Wipe()

	var dek2 []byte
	if err := ptDEK2.WithKey(func(secret []byte) error {
		dek2 = append(dek2, secret...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey #2: %v", err)
	}
	defer func() {
		for i := range dek2 {
			dek2[i] = 0
		}
	}()

	if bytes.Equal(dek1, dek2) {
		t.Fatal("two consecutive DEKs are identical; CSPRNG may be broken")
	}
}

// TestGenerateDataKeyNilMasterKey 验证 nil masterKey 返回错误且无明文残留。
func TestGenerateDataKeyNilMasterKey(t *testing.T) {
	ptDEK, ctDEK, err := GenerateDataKey(nil)
	if err == nil {
		if ptDEK != nil {
			ptDEK.Wipe()
		}
		t.Fatal("GenerateDataKey(nil) expected error, got nil")
	}
	if ptDEK != nil {
		ptDEK.Wipe()
		t.Fatal("GenerateDataKey(nil) returned non-nil plaintextDEK")
	}
	if ctDEK != nil {
		t.Fatal("GenerateDataKey(nil) returned non-nil encryptedDEK")
	}
}

// TestEncryptGCM_InvalidKeySize 验证非 32 字节密钥报错。
func TestEncryptGCM_InvalidKeySize(t *testing.T) {
	// 16 字节密钥（AES-128），不是 AES-256。
	shortKey, err := memguard.NewSecureBufferFromRandom(16)
	if err != nil {
		t.Fatalf("short key: %v", err)
	}
	defer shortKey.Wipe()

	_, err = EncryptGCM(shortKey, []byte("test"))
	if err == nil {
		t.Fatal("EncryptGCM with 16-byte key should fail")
	}
}

// TestDecryptGCM_InvalidKeySize 验证非 32 字节密钥报错。
func TestDecryptGCM_InvalidKeySize(t *testing.T) {
	shortKey, err := memguard.NewSecureBufferFromRandom(16)
	if err != nil {
		t.Fatalf("short key: %v", err)
	}
	defer shortKey.Wipe()

	_, err = DecryptGCM(shortKey, []byte("01234567890123456789012345678901"))
	if err == nil {
		t.Fatal("DecryptGCM with 16-byte key should fail")
	}
}

// TestEncryptGCM_NonceGenerationFailure 不易触发（CSPRNG 失败），跳过。
// 但可以验证 EncryptGCM 的多次调用产生不同密文（Nonce 随机性）。
func TestEncryptGCM_DifferentNonceEachCall(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("same input")

	ct1, _ := EncryptGCM(key, plaintext)
	ct2, _ := EncryptGCM(key, plaintext)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertext (random nonce)")
	}
}

// TestEncryptGCM_LargePlaintext 验证大块明文加解密。
func TestEncryptGCM_LargePlaintext(t *testing.T) {
	key := newTestKey(t)
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ct, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM large: %v", err)
	}
	sb, err := DecryptGCM(key, ct)
	if err != nil {
		t.Fatalf("DecryptGCM large: %v", err)
	}
	defer sb.Wipe()

	var got []byte
	_ = sb.WithKey(func(s []byte) error { got = append(got, s...); return nil })
	if !bytes.Equal(got, plaintext) {
		t.Fatal("large plaintext round-trip mismatch")
	}
}

// TestGenerateDataKey_NilMasterKey 验证 nil masterKey 报错。
func TestGenerateDataKey_NilMasterKey(t *testing.T) {
	_, _, err := GenerateDataKey(nil)
	if err == nil {
		t.Fatal("GenerateDataKey(nil) should fail")
	}
}

// 确保 errors 包被使用（用于未来的错误断言扩展）。
var _ = errors.New
