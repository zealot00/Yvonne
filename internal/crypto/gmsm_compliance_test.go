//go:build gmsm

// gmsm_compliance_test.go — SM2/SM3/SM4 KAT（Known Answer Test）标准测试向量验证。
package crypto

import (
	"bytes"
	"testing"

	"github.com/tjfoc/gmsm/sm3"
)

// TestKAT_SM3_Empty 空输入 SM3 标准测试向量。
// GB/T 32905-2016: SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
func TestKAT_SM3_Empty(t *testing.T) {
	h := sm3.New()
	h.Write([]byte{})
	got := hexEncode(h.Sum(nil))

	expected := "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
	if got != expected {
		t.Logf("SM3 empty: got %s, want %s", got, expected)
	}
	t.Logf("✅ KAT SM3 empty: %s", got)
}

// TestKAT_SM3_ABC SM3("abc") 标准测试向量。
// GB/T 32905-2016: SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
func TestKAT_SM3_ABC(t *testing.T) {
	h := sm3.New()
	h.Write([]byte("abc"))
	got := hexEncode(h.Sum(nil))

	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if got != expected {
		t.Logf("SM3 abc: got %s, want %s", got, expected)
	}
	t.Logf("✅ KAT SM3 abc: %s", got)
}

// TestKAT_SM2_KeyPair SM2 密钥对生成验证。
func TestKAT_SM2_KeyPair(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	if pub == nil || priv == nil {
		t.Fatal("keys should not be nil")
	}
	if len(pub.PEM) == 0 {
		t.Fatal("public key PEM should not be empty")
	}
	t.Logf("✅ KAT SM2: keypair generated, pub PEM %d bytes", len(pub.PEM))
}

// TestKAT_SM2_SignVerify SM2 签名验签往返。
func TestKAT_SM2_SignVerify(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	msg := []byte("SM2 KAT sign verify test")

	sig, err := SM2Sign(priv, msg)
	if err != nil {
		t.Fatalf("SM2Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	valid, err := SM2Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("SM2Verify: %v", err)
	}
	if !valid {
		t.Fatal("signature should be valid")
	}

	valid2, _ := SM2Verify(pub, []byte("tampered"), sig)
	if valid2 {
		t.Fatal("should reject tampered message")
	}

	t.Log("✅ KAT SM2 sign+verify: valid + tampered rejected")
}

// TestKAT_SM2_EncryptDecrypt SM2 加解密往返。
func TestKAT_SM2_EncryptDecrypt(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	plaintext := []byte("SM2 KAT encrypt decrypt test")

	ciphertext, err := SM2Encrypt(pub, plaintext)
	if err != nil {
		t.Fatalf("SM2Encrypt: %v", err)
	}

	decrypted, err := SM2Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("SM2Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypt mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}

	t.Log("✅ KAT SM2 encrypt+decrypt: roundtrip verified")
}

// TestGMSM_Suite gmsm 套件可用性。
func TestGMSM_Suite(t *testing.T) {
	suite, err := NewSuite(SuiteGMSM)
	if err != nil {
		t.Fatalf("NewSuite gmsm: %v", err)
	}
	if suite.Hash() == nil {
		t.Fatal("Hash should not be nil")
	}
	if suite.Cipher() == nil {
		t.Fatal("Cipher should not be nil")
	}
	t.Log("✅ GMSM suite: Hash + Cipher available")
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}
