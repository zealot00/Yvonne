//go:build gmsm

package crypto

import (
	"bytes"
	"testing"

	"yvonne/internal/memguard"
)

// TestGMSMCipher_RoundTrip 验证 SM4-GCM 加解密往返。
func TestGMSMCipher_RoundTrip(t *testing.T) {
	c := NewGMSMCipher()
	if c.KeySize() != 16 {
		t.Fatalf("KeySize = %d, want 16", c.KeySize())
	}
	if c.Name() != "sm4-gcm" {
		t.Fatalf("Name = %q, want sm4-gcm", c.Name())
	}

	// SM4 密钥 16 字节。
	key, _ := memguard.NewSecureBufferFromRandom(16)
	defer key.Wipe()

	plaintext := []byte("hello world 国密测试")
	ct, err := c.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) < 28 {
		t.Fatalf("ciphertext too short: %d", len(ct))
	}

	dec, err := c.Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	defer dec.Wipe()

	var got []byte
	_ = dec.WithKey(func(d []byte) error {
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
		t.Fatal("round-trip mismatch")
	}
}

// TestGMSMCipher_Tampered 验证篡改检测。
func TestGMSMCipher_Tampered(t *testing.T) {
	c := NewGMSMCipher()
	key, _ := memguard.NewSecureBufferFromRandom(16)
	defer key.Wipe()

	ct, _ := c.Encrypt(key, []byte("test"))
	ct[len(ct)-1] ^= 0xFF

	_, err := c.Decrypt(key, ct)
	if err == nil {
		t.Fatal("tampered ciphertext should fail")
	}
}

// TestGMSMHash_SM3 验证 SM3 哈希。
func TestGMSMHash_SM3(t *testing.T) {
	h := NewGMSMHash()
	if h.Size() != 32 {
		t.Fatalf("Size = %d, want 32", h.Size())
	}
	if h.Name() != "sm3" {
		t.Fatalf("Name = %q, want sm3", h.Name())
	}

	// SM3("abc") = 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
	data := []byte("abc")
	got := h.Sum(data)
	expected := []byte{0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0}
	if !bytes.Equal(got, expected) {
		t.Fatalf("SM3(abc) = %x, want %x", got, expected)
	}
}

// TestGMSMHash_HMAC 验证 HMAC-SM3。
func TestGMSMHash_HMAC(t *testing.T) {
	h := NewGMSMHash()
	key := []byte("test-key")
	data := []byte("test-data")
	mac1 := h.HMAC(key, data)
	mac2 := h.HMAC(key, data)
	if !bytes.Equal(mac1, mac2) {
		t.Fatal("same key+data should produce same HMAC")
	}
	if len(mac1) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(mac1))
	}
	// 不同数据应产生不同 HMAC。
	mac3 := h.HMAC(key, []byte("different"))
	if bytes.Equal(mac1, mac3) {
		t.Fatal("different data should produce different HMAC")
	}
}

// TestGMSMSuite 验证完整国密套件。
func TestGMSMSuite(t *testing.T) {
	suite, err := NewGMSMSuite()
	if err != nil {
		t.Fatalf("NewGMSMSuite: %v", err)
	}
	if suite.Name() != "gmsm" {
		t.Fatalf("Name = %q, want gmsm", suite.Name())
	}
	if suite.Cipher().Name() != "sm4-gcm" {
		t.Fatalf("Cipher Name = %q", suite.Cipher().Name())
	}
	if suite.Hash().Name() != "sm3" {
		t.Fatalf("Hash Name = %q", suite.Hash().Name())
	}
}

// TestNewSuite_GMSM 验证工厂函数。
func TestNewSuite_GMSM(t *testing.T) {
	suite, err := NewSuite(SuiteGMSM)
	if err != nil {
		t.Fatalf("NewSuite(gmsm): %v", err)
	}
	if suite.Name() != "gmsm" {
		t.Fatalf("Name = %q", suite.Name())
	}
}

// TestNewSuite_Standard 验证标准套件工厂。
func TestNewSuite_Standard(t *testing.T) {
	suite, err := NewSuite(SuiteStandard)
	if err != nil {
		t.Fatalf("NewSuite(standard): %v", err)
	}
	if suite.Name() != "standard" {
		t.Fatalf("Name = %q", suite.Name())
	}
	if suite.Cipher().Name() != "aes-256-gcm" {
		t.Fatalf("Cipher Name = %q", suite.Cipher().Name())
	}
}
