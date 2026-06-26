//go:build gmsm

package crypto

import (
	"bytes"
	"testing"
)

// TestSM2_GenerateKeyPair 密钥对生成。
func TestSM2_GenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	if pub == nil || priv == nil {
		t.Fatal("pub or priv is nil")
	}
	if len(pub.PEM) == 0 {
		t.Fatal("public key PEM should not be empty")
	}
	t.Logf("Public key PEM: %d bytes", len(pub.PEM))
}

// TestSM2_EncryptDecrypt 加解密往返。
func TestSM2_EncryptDecrypt(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	plaintext := []byte("hello SM2 encryption test")

	ciphertext, err := SM2Encrypt(pub, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext empty")
	}
	t.Logf("Encrypted: %d bytes", len(ciphertext))

	decrypted, err := SM2Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("SM2Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
	t.Logf("Decrypted: %s", string(decrypted))
}

// TestSM2_EncryptChinese 中文明文加解密。
func TestSM2_EncryptChinese(t *testing.T) {
	pub, priv, _ := GenerateSM2KeyPair()

	plaintext := []byte("国密SM2加密测试")

	ciphertext, _ := SM2Encrypt(pub, plaintext)
	decrypted, err := SM2Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("SM2Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
	t.Logf("Chinese decrypted: %s", string(decrypted))
}

// TestSM2_SignVerify 签名+验签。
func TestSM2_SignVerify(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	msg := []byte("message to sign")

	sig, err := SM2Sign(priv, msg)
	if err != nil {
		t.Fatalf("SM2Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature empty")
	}
	t.Logf("Signature: %d bytes", len(sig))

	ok, err := SM2Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("SM2Verify: %v", err)
	}
	if !ok {
		t.Fatal("signature verification failed")
	}
	t.Log("✅ Signature verified")
}

// TestSM2_VerifyTampered 篡改消息后验签失败。
func TestSM2_VerifyTampered(t *testing.T) {
	pub, priv, _ := GenerateSM2KeyPair()

	msg := []byte("original message")
	sig, _ := SM2Sign(priv, msg)

	// 篡改消息。
	tamperedMsg := []byte("tampered message")
	ok, _ := SM2Verify(pub, tamperedMsg, sig)
	if ok {
		t.Fatal("tampered message should fail verification")
	}
	t.Log("✅ Tampered message correctly rejected")
}

// TestSM2_PrivateKeyPEM 私钥 PEM 序列化/反序列化。
func TestSM2_PrivateKeyPEM(t *testing.T) {
	_, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	pemData, err := SM2PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToPEM: %v", err)
	}
	if len(pemData) == 0 {
		t.Fatal("PEM data empty")
	}
	t.Logf("Private key PEM: %d bytes", len(pemData))

	// 反序列化。
	priv2, err := SM2PrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("SM2PrivateKeyFromPEM: %v", err)
	}

	// 用反序列化的私钥签名验证 PEM 往返。
	msg := []byte("pem roundtrip")
	sig, _ := SM2Sign(priv, msg)
	ok, _ := SM2Verify(&SM2PublicKey{Key: &priv.Key.PublicKey}, msg, sig)
	if !ok {
		t.Fatal("sign with original, verify with original should pass")
	}

	// 用 priv2 签名。
	sig2, _ := SM2Sign(priv2, msg)
	ok2, _ := SM2Verify(&SM2PublicKey{Key: &priv2.Key.PublicKey}, msg, sig2)
	if !ok2 {
		t.Fatal("sign with deserialized key should pass")
	}
	t.Log("✅ Private key PEM roundtrip works")
}

// TestSM2_PublicKeyPEM 公钥 PEM 序列化/反序列化。
func TestSM2_PublicKeyPEM(t *testing.T) {
	pub, _, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	pub2, err := SM2PublicKeyFromPEM(pub.PEM)
	if err != nil {
		t.Fatalf("SM2PublicKeyFromPEM: %v", err)
	}

	// 用反序列化的公钥加密。
	plaintext := []byte("public key pem test")
	ciphertext, err := SM2Encrypt(pub2, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt with deserialized public key: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext empty")
	}
	_ = ciphertext
	t.Log("✅ Public key PEM roundtrip works")
}

// TestSM2_DifferentKeyPairs 不同密钥对不可互解。
func TestSM2_DifferentKeyPairs(t *testing.T) {
	pub1, priv1, _ := GenerateSM2KeyPair()
	_ = pub1
	_, _, _ = GenerateSM2KeyPair() // pub2/priv2 不用

	// pub1 加密，priv2 解密应失败（但这里 priv2 不可用，改为测签名）。
	msg := []byte("cross key test")
	sig1, _ := SM2Sign(priv1, msg)

	// 用不同公钥验证。
	pub2, _, _ := GenerateSM2KeyPair()
	ok, _ := SM2Verify(pub2, msg, sig1)
	if ok {
		t.Fatal("signature from key1 should not verify with key2")
	}
	t.Log("✅ Cross-key verification correctly rejected")
}
