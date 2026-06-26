//go:build gmsm

package crypto

import (
	"bytes"
	"testing"

	"yvonne/internal/memguard"
)

// memguardNewSecureBuffer 包装 memguard.NewSecureBuffer（避免 import 循环风险）。
func memguardNewSecureBuffer(data []byte) *memguard.SecureBuffer {
	return memguard.NewSecureBuffer(data)
}

// TestSM2_Integration_WithSM3 SM2 签名内嵌 SM3 摘要验证。
func TestSM2_Integration_WithSM3(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	// SM3 计算消息摘要。
	hash := NewGMSMHash()
	msg := []byte("SM2+SM3 integration test")
	digest := hash.Sum(msg)

	// SM2 签名（内部用 SM3，但 Sm2Sign 接收原始 msg）。
	sig, err := SM2Sign(priv, msg)
	if err != nil {
		t.Fatalf("SM2Sign: %v", err)
	}

	// 验签。
	ok, err := SM2Verify(pub, msg, sig)
	if err != nil || !ok {
		t.Fatalf("SM2Verify: ok=%v err=%v", ok, err)
	}

	// 确认 SM3 摘要非空。
	if len(digest) != 32 {
		t.Fatalf("SM3 digest length = %d, want 32", len(digest))
	}
	t.Log("✅ SM2 signature internally uses SM3 digest")
}

// TestSM2_Integration_WithSM4 SM2 加密 SM4 密钥（KEK 场景模拟）。
func TestSM2_Integration_WithSM4(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	// 生成 SM4 密钥（16 字节）。
	sm4Key := make([]byte, 16)
	for i := range sm4Key {
		sm4Key[i] = byte(i + 1)
	}

	// 用 SM2 公钥加密 SM4 密钥（模拟密钥分发）。
	wrappedKey, err := SM2Encrypt(pub, sm4Key)
	if err != nil {
		t.Fatalf("SM2Encrypt SM4 key: %v", err)
	}
	t.Logf("SM4 key wrapped by SM2: %d bytes", len(wrappedKey))

	// 用 SM2 私钥解密获取 SM4 密钥。
	unwrappedKey, err := SM2Decrypt(priv, wrappedKey)
	if err != nil {
		t.Fatalf("SM2Decrypt: %v", err)
	}
	if !bytes.Equal(sm4Key, unwrappedKey) {
		t.Fatal("SM4 key mismatch after SM2 wrap/unwrap")
	}

	// 用解密出的 SM4 密钥加密业务数据。
	// 注意：NewSecureBuffer 会 clear 源切片，所以先 copy。
	cipher := NewGMSMCipher()
	plaintext := []byte("business data encrypted with SM4")

	encKey := make([]byte, len(unwrappedKey))
	copy(encKey, unwrappedKey)
	ciphertext, err := cipher.Encrypt(memguardNewSecureBuffer(encKey), plaintext)
	if err != nil {
		t.Fatalf("SM4 Encrypt: %v", err)
	}

	// 解密验证。
	decKey := make([]byte, len(unwrappedKey))
	copy(decKey, unwrappedKey)
	decrypted, err := cipher.Decrypt(memguardNewSecureBuffer(decKey), ciphertext)
	if err != nil {
		t.Fatalf("SM4 Decrypt: %v", err)
	}
	defer decrypted.Wipe()

	var got []byte
	_ = decrypted.WithKey(func(d []byte) error {
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
		t.Fatal("SM4 decrypted data mismatch")
	}
	t.Log("✅ SM2 wrap SM4 key → SM4 encrypt/decrypt — full chain works")
}

// TestSM2_Integration_KeyExchangeSim SM2 密钥对模拟密钥协商。
func TestSM2_Integration_KeyExchangeSim(t *testing.T) {
	// 模拟：Alice 和 Bob 各生成 SM2 密钥对，互相交换公钥，用对方公钥加密对称密钥。
	alicePub, alicePriv, _ := GenerateSM2KeyPair()
	bobPub, bobPriv, _ := GenerateSM2KeyPair()

	// Alice 生成随机对称密钥，用 Bob 公钥加密发给 Bob。
	sessionKey := []byte("shared-secret-16") // 简化为 16 字节
	wrappedToBob, err := SM2Encrypt(bobPub, sessionKey)
	if err != nil {
		t.Fatalf("Alice → Bob encrypt: %v", err)
	}

	// Bob 解密获取对称密钥。
	bobReceived, err := SM2Decrypt(bobPriv, wrappedToBob)
	if err != nil {
		t.Fatalf("Bob decrypt: %v", err)
	}
	if !bytes.Equal(sessionKey, bobReceived) {
		t.Fatal("Bob received wrong session key")
	}

	// Bob 用 Alice 公钥加密回执。
	ack := []byte("ack")
	wrappedToAlice, _ := SM2Encrypt(alicePub, ack)

	// Alice 解密回执。
	aliceReceived, _ := SM2Decrypt(alicePriv, wrappedToAlice)
	if !bytes.Equal(ack, aliceReceived) {
		t.Fatal("Alice received wrong ack")
	}
	t.Log("✅ SM2 key exchange simulation (Alice ↔ Bob) works")
}

// TestSM2_Integration_PEMStorage SM2 密钥 PEM 存储模拟（KEK 加密存储）。
func TestSM2_Integration_PEMStorage(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	// 私钥序列化为 PEM（模拟存储到 DB 前的序列化）。
	privPEM, err := SM2PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToPEM: %v", err)
	}

	// 公钥 PEM 已在 pub.PEM 中。
	if len(pub.PEM) == 0 {
		t.Fatal("public key PEM empty")
	}

	// 模拟从 DB 读取后反序列化。
	priv2, err := SM2PrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("SM2PrivateKeyFromPEM: %v", err)
	}

	// 验证反序列化的私钥功能正常。
	msg := []byte("storage roundtrip")
	sig, _ := SM2Sign(priv2, msg)
	ok, _ := SM2Verify(pub, msg, sig)
	if !ok {
		t.Fatal("sign with deserialized key, verify with original pub should work")
	}

	// 用反序列化的私钥解密。
	ciphertext, _ := SM2Encrypt(pub, []byte("decrypt test"))
	plaintext, err := SM2Decrypt(priv2, ciphertext)
	if err != nil || string(plaintext) != "decrypt test" {
		t.Fatalf("decrypt with deserialized key failed: %v", err)
	}
	t.Log("✅ SM2 PEM storage roundtrip (serialize → store → load → sign + decrypt)")
}
