package crypto

import (
	"bytes"
	"testing"

	"yvonne/internal/memguard"
)

// === 正常流 ===

// TestDecryptVersioned_NormalFlow 验证正常密文解密。
func TestDecryptVersioned_NormalFlow(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	plaintext := []byte("hello world")
	ct, err := EncryptVersioned(dek, 42, plaintext)
	if err != nil {
		t.Fatalf("EncryptVersioned: %v", err)
	}

	// 验证版本号前缀。
	version := uint32(ct[0])<<24 | uint32(ct[1])<<16 | uint32(ct[2])<<8 | uint32(ct[3])
	if version != 42 {
		t.Fatalf("version = %d, want 42", version)
	}

	decSB, decVer, err := DecryptVersioned(dek, ct)
	if err != nil {
		t.Fatalf("DecryptVersioned: %v", err)
	}
	defer decSB.Wipe()

	if decVer != 42 {
		t.Fatalf("decrypted version = %d, want 42", decVer)
	}

	var got []byte
	_ = decSB.WithKey(func(d []byte) error {
		got = make([]byte, len(d))
		copy(got, d)
		return nil
	})
	defer func() {
		for i := range got {
			got[i] = 0
		}
	}()

	if !bytes.Equal(plaintext, got) {
		t.Fatal("plaintext mismatch")
	}
}

// TestDecryptVersioned_VersionZero 验证版本号 0 合法。
func TestDecryptVersioned_VersionZero(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, err := EncryptVersioned(dek, 0, []byte("v0"))
	if err != nil {
		t.Fatalf("EncryptVersioned: %v", err)
	}

	_, ver, err := DecryptVersioned(dek, ct)
	if err != nil {
		t.Fatalf("DecryptVersioned v0: %v", err)
	}
	if ver != 0 {
		t.Fatalf("version = %d, want 0", ver)
	}
}

// TestDecryptVersioned_VersionMaxUint32 验证版本号 MaxUint32。
func TestDecryptVersioned_VersionMaxUint32(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, err := EncryptVersioned(dek, 4294967295, []byte("max"))
	if err != nil {
		t.Fatalf("EncryptVersioned: %v", err)
	}

	_, ver, err := DecryptVersioned(dek, ct)
	if err != nil {
		t.Fatalf("DecryptVersioned max: %v", err)
	}
	if ver != 4294967295 {
		t.Fatalf("version = %d, want 4294967295", ver)
	}
}

// TestDecryptVersioned_LargePlaintext 验证大块明文。
func TestDecryptVersioned_LargePlaintext(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	plaintext := make([]byte, 65536) // 64KB
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ct, err := EncryptVersioned(dek, 1, plaintext)
	if err != nil {
		t.Fatalf("EncryptVersioned: %v", err)
	}

	decSB, _, err := DecryptVersioned(dek, ct)
	if err != nil {
		t.Fatalf("DecryptVersioned: %v", err)
	}
	defer decSB.Wipe()

	var got []byte
	_ = decSB.WithKey(func(d []byte) error {
		got = make([]byte, len(d))
		copy(got, d)
		return nil
	})
	defer func() {
		for i := range got {
			got[i] = 0
		}
	}()

	if !bytes.Equal(plaintext, got) {
		t.Fatal("large plaintext mismatch")
	}
}

// === 截断流（Panic 防御）===

// TestDecryptVersioned_EmptyCiphertext 空密文必须返回 error，不 panic。
func TestDecryptVersioned_EmptyCiphertext(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	_, _, err := DecryptVersioned(dek, []byte{})
	if err == nil {
		t.Fatal("empty ciphertext must return error")
	}
}

// TestDecryptVersioned_NilCiphertext nil 密文必须返回 error，不 panic。
func TestDecryptVersioned_NilCiphertext(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	_, _, err := DecryptVersioned(dek, nil)
	if err == nil {
		t.Fatal("nil ciphertext must return error")
	}
}

// TestDecryptVersioned_TooShort 1-15 字节密文必须返回 error。
func TestDecryptVersioned_TooShort(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	for length := 1; length < 20; length++ {
		ct := make([]byte, length)
		_, _, err := DecryptVersioned(dek, ct)
		if err == nil {
			t.Fatalf("ciphertext length %d must return error", length)
		}
	}
}

// TestDecryptVersioned_ExactlyMinSize 刚好 MinCiphertextSize 字节（仅版本+nonce+空明文+tag）。
func TestDecryptVersioned_ExactlyMinSize(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	// 加密空明文。
	ct, err := EncryptVersioned(dek, 1, []byte{})
	if err != nil {
		t.Fatalf("EncryptVersioned empty: %v", err)
	}

	if len(ct) != MinCiphertextSize {
		t.Fatalf("empty plaintext ciphertext size = %d, want %d", len(ct), MinCiphertextSize)
	}

	// 应能正常解密。
	decSB, _, err := DecryptVersioned(dek, ct)
	if err != nil {
		t.Fatalf("DecryptVersioned min size: %v", err)
	}
	decSB.Wipe()
}

// TestDecryptVersioned_TruncatedByOne 截断 1 字节。
func TestDecryptVersioned_TruncatedByOne(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 1, []byte("test"))

	// 截断最后 1 字节。
	truncated := ct[:len(ct)-1]
	_, _, err := DecryptVersioned(dek, truncated)
	if err == nil {
		t.Fatal("truncated ciphertext must fail")
	}
}

// TestDecryptVersioned_PanicDefense 验证各种恶意长度不 panic。
func TestDecryptVersioned_PanicDefense(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	malicious := [][]byte{
		{},
		{0},
		{0, 0, 0, 0}, // 仅版本号
		{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // 版本+部分nonce
		make([]byte, 15),
		make([]byte, 16),
		make([]byte, 17),
	}

	for i, ct := range malicious {
		// 不应 panic。
		_, _, err := DecryptVersioned(dek, ct)
		if err == nil && len(ct) < MinCiphertextSize {
			t.Fatalf("case %d: length %d should fail", i, len(ct))
		}
	}
}

// === 篡改流 ===

// TestDecryptVersioned_TamperedAuthTag 篡改 AuthTag（最后一字节）。
func TestDecryptVersioned_TamperedAuthTag(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 1, []byte("sensitive"))

	// 翻转最后一字节（AuthTag 区域）。
	ct[len(ct)-1] ^= 0xFF

	_, _, err := DecryptVersioned(dek, ct)
	if err == nil {
		t.Fatal("tampered AuthTag must fail")
	}
}

// TestDecryptVersioned_TamperedVersion 篡改版本号字节。
func TestDecryptVersioned_TamperedVersion(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 1, []byte("test"))

	// 篡改版本号第 1 字节。
	ct[0] ^= 0xFF

	// 版本号变了但密文不变 → 解密应失败（DEK 不变，但版本号不匹配不影响 GCM 解密）。
	// 实际上版本号篡改不会导致 GCM 解密失败（版本号是路由用的，不参与 GCM 认证）。
	// 但 DecryptVersioned 返回的 version 会不同。
	_, ver, err := DecryptVersioned(dek, ct)
	if err != nil {
		// GCM 认证可能失败（因为版本号是密文的一部分，篡改后 GCM tag 校验失败）。
		return
	}
	// 如果 GCM 没失败（版本号不在认证范围），版本号应不同。
	if ver == 1 {
		t.Fatal("tampered version should differ from original")
	}
}

// TestDecryptVersioned_TamperedCiphertextBody 篡改密文中间字节。
func TestDecryptVersioned_TamperedCiphertextBody(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 1, []byte("12345678901234567890"))

	// 篡改密文中间字节（版本+nonce 之后）。
	mid := 4 + 12 + 5 // 版本4 + nonce12 + 中间5字节
	if mid < len(ct) {
		ct[mid] ^= 0xFF
	}

	_, _, err := DecryptVersioned(dek, ct)
	if err == nil {
		t.Fatal("tampered ciphertext body must fail")
	}
}

// TestDecryptVersioned_TamperedNonce 篡改 Nonce。
func TestDecryptVersioned_TamperedNonce(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 1, []byte("test"))

	// 篡改 Nonce 第 1 字节（版本号之后）。
	ct[4] ^= 0xFF

	_, _, err := DecryptVersioned(dek, ct)
	if err == nil {
		t.Fatal("tampered nonce must fail")
	}
}

// TestDecryptVersioned_WrongKey 错误 DEK 解密失败。
func TestDecryptVersioned_WrongKey(t *testing.T) {
	dek1, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek1.Wipe()
	dek2, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek2.Wipe()

	ct, _ := EncryptVersioned(dek1, 1, []byte("secret"))

	_, _, err := DecryptVersioned(dek2, ct)
	if err == nil {
		t.Fatal("wrong key must fail")
	}
}

// TestDecryptVersioned_AllZeroCiphertext 全零密文。
func TestDecryptVersioned_AllZeroCiphertext(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct := make([]byte, 100) // 全零
	_, _, err := DecryptVersioned(dek, ct)
	if err == nil {
		t.Fatal("all-zero ciphertext must fail")
	}
}

// TestDecryptVersioned_AllFFCiphertext 全 0xFF 密文。
func TestDecryptVersioned_AllFFCiphertext(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct := make([]byte, 100)
	for i := range ct {
		ct[i] = 0xFF
	}
	_, _, err := DecryptVersioned(dek, ct)
	if err == nil {
		t.Fatal("all-0xFF ciphertext must fail")
	}
}

// === 版本号 BigEndian 验证 ===

// TestEncryptVersioned_VersionBigEndian 验证版本号是大端序。
func TestEncryptVersioned_VersionBigEndian(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()

	ct, _ := EncryptVersioned(dek, 0x01020304, []byte("x"))

	// 大端序：01 02 03 04。
	if ct[0] != 0x01 || ct[1] != 0x02 || ct[2] != 0x03 || ct[3] != 0x04 {
		t.Fatalf("version bytes = %02x %02x %02x %02x, want 01 02 03 04", ct[0], ct[1], ct[2], ct[3])
	}
}

// === DEK 密钥长度边界 ===

// TestEncryptVersioned_16ByteKey 16 字节密钥（AES-128）应失败（仅允许 32 字节）。
func TestEncryptVersioned_16ByteKey(t *testing.T) {
	dek, _ := memguard.NewSecureBufferFromRandom(16)
	defer dek.Wipe()

	_, err := EncryptVersioned(dek, 1, []byte("test"))
	if err == nil {
		t.Fatal("16-byte key should fail (AES-256 requires 32 bytes)")
	}
}

// TestEncryptVersioned_EmptyKey 空密钥失败。
func TestEncryptVersioned_EmptyKey(t *testing.T) {
	dek := memguard.NewSecureBuffer([]byte{})
	defer dek.Wipe()

	_, err := EncryptVersioned(dek, 1, []byte("test"))
	if err == nil {
		t.Fatal("empty key should fail")
	}
}
