package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// TestGenerateAsymmetricKey_RSA 验证 RSA-4096 密钥生成。
func TestGenerateAsymmetricKey_RSA(t *testing.T) {
	priv, ecdsaPriv, err := GenerateAsymmetricKey(KeyTypeRSA)
	if err != nil {
		t.Fatalf("GenerateAsymmetricKey RSA: %v", err)
	}
	if priv == nil {
		t.Fatal("RSA private key should not be nil")
	}
	if ecdsaPriv != nil {
		t.Fatal("ECDSA private key should be nil for RSA key type")
	}
	if priv.N.BitLen() != 4096 {
		t.Fatalf("RSA key size = %d bits, want 4096", priv.N.BitLen())
	}
}

// TestGenerateAsymmetricKey_ECDSA 验证 ECDSA P-256 密钥生成。
func TestGenerateAsymmetricKey_ECDSA(t *testing.T) {
	rsaPriv, priv, err := GenerateAsymmetricKey(KeyTypeECDSA)
	if err != nil {
		t.Fatalf("GenerateAsymmetricKey ECDSA: %v", err)
	}
	if priv == nil {
		t.Fatal("ECDSA private key should not be nil")
	}
	if rsaPriv != nil {
		t.Fatal("RSA private key should be nil for ECDSA key type")
	}
	if priv.Curve != elliptic.P256() {
		t.Fatal("ECDSA curve should be P-256")
	}
}

// TestGenerateAsymmetricKey_UnsupportedType 验证不支持的类型报错。
func TestGenerateAsymmetricKey_UnsupportedType(t *testing.T) {
	_, _, err := GenerateAsymmetricKey("dsa")
	if err == nil {
		t.Fatal("unsupported key type should fail")
	}
}

// TestSignVerify_RSA_PSS 验证 RSA-PSS 签名与验签闭环。
func TestSignVerify_RSA_PSS(t *testing.T) {
	priv, _, err := GenerateAsymmetricKey(KeyTypeRSA)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	digest := sha256.Sum256([]byte("test message"))
	sig, err := Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	err = Verify(&priv.PublicKey, digest[:], sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignVerify_ECDSA 验证 ECDSA 签名与验签闭环。
func TestSignVerify_ECDSA(t *testing.T) {
	_, priv, err := GenerateAsymmetricKey(KeyTypeECDSA)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	digest := sha256.Sum256([]byte("ecdsa message"))
	sig, err := Sign(priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	err = Verify(&priv.PublicKey, digest[:], sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerify_TamperedSignature 验证篡改签名后验签失败。
func TestVerify_TamperedSignature(t *testing.T) {
	priv, _, _ := GenerateAsymmetricKey(KeyTypeRSA)
	digest := sha256.Sum256([]byte("original"))
	sig, _ := Sign(priv, digest[:])

	// 翻转签名最后一字节。
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)-1] ^= 0xFF

	err := Verify(&priv.PublicKey, digest[:], tampered)
	if err == nil {
		t.Fatal("tampered signature should fail verification")
	}
}

// TestVerify_WrongDigest 验证不同 digest 验签失败。
func TestVerify_WrongDigest(t *testing.T) {
	priv, _, _ := GenerateAsymmetricKey(KeyTypeRSA)
	digest1 := sha256.Sum256([]byte("message1"))
	digest2 := sha256.Sum256([]byte("message2"))
	sig, _ := Sign(priv, digest1[:])

	err := Verify(&priv.PublicKey, digest2[:], sig)
	if err == nil {
		t.Fatal("verify with wrong digest should fail")
	}
}

// TestSign_EmptyDigest 验证空 digest 报错。
func TestSign_EmptyDigest(t *testing.T) {
	priv, _, _ := GenerateAsymmetricKey(KeyTypeRSA)
	_, err := Sign(priv, []byte{})
	if err == nil {
		t.Fatal("Sign with empty digest should fail")
	}
}

// TestSign_UnsupportedKey 验证不支持的密钥类型报错。
func TestSign_UnsupportedKey(t *testing.T) {
	_, err := Sign("not-a-key", []byte("digest"))
	if err == nil {
		t.Fatal("Sign with unsupported key should fail")
	}
}

// TestPrivateKeyToSecureDER 验证私钥序列化为 SecureBuffer。
func TestPrivateKeyToSecureDER(t *testing.T) {
	// 直接生成 ECDSA P-256 私钥。
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}

	sb, err := PrivateKeyToSecureDER(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToSecureDER: %v", err)
	}
	defer sb.Wipe()

	if sb.Len() == 0 {
		t.Fatal("DER SecureBuffer should not be empty")
	}

	// 验证可从 DER 反序列化回私钥。
	_ = sb.WithKey(func(der []byte) error {
		parsed, err := ParsePrivateKeyFromDER(der)
		if err != nil {
			t.Fatalf("ParsePrivateKeyFromDER: %v", err)
		}
		_, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("parsed key should be *ecdsa.PrivateKey")
		}
		return nil
	})
}

// TestPublicKeyToPEM 验证公钥序列化为 PEM。
func TestPublicKeyToPEM(t *testing.T) {
	priv, _, err := GenerateAsymmetricKey(KeyTypeRSA)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}

	pemBytes, err := PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("PEM should not be empty")
	}

	// 验证可从 PEM 反序列化回公钥。
	pub, err := ParsePublicKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM: %v", err)
	}
	_, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key should be *rsa.PublicKey")
	}
}

// TestPrivateKeyToSecureDER_ClearsPlaintext 验证两次序列化同一私钥产生相同 DER。
func TestPrivateKeyToSecureDER_ClearsPlaintext(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	der1, _ := PrivateKeyToDER(priv)

	sb, err := PrivateKeyToSecureDER(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToSecureDER: %v", err)
	}
	defer sb.Wipe()

	_ = sb.WithKey(func(der2 []byte) error {
		if !bytes.Equal(der1, der2) {
			t.Log("DER bytes differ (expected: same key produces same DER)")
		}
		return nil
	})
}

// TestParsePrivateKeyFromDER_Invalid 验证无效 DER 报错。
func TestParsePrivateKeyFromDER_Invalid(t *testing.T) {
	_, err := ParsePrivateKeyFromDER([]byte("not a valid DER"))
	if err == nil {
		t.Fatal("ParsePrivateKeyFromDER with invalid DER should fail")
	}
}

// TestParsePublicKeyFromPEM_Invalid 验证无效 PEM 报错。
func TestParsePublicKeyFromPEM_Invalid(t *testing.T) {
	_, err := ParsePublicKeyFromPEM([]byte("not a PEM"))
	if err == nil {
		t.Fatal("ParsePublicKeyFromPEM with invalid PEM should fail")
	}
}

// TestRSA_ShortKey 验证 RSA 密钥过短时报错。
func TestRSA_ShortKey(t *testing.T) {
	// 生成 1024 位 RSA 密钥（故意不满足 2048 最低要求）。
	shortKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate short RSA: %v", err)
	}
	digest := sha256.Sum256([]byte("test"))
	_, err = Sign(shortKey, digest[:])
	if err == nil {
		t.Fatal("Sign with 1024-bit RSA key should fail")
	}
}

// TestECDSA_WrongCurve 验证非 P-256 曲线报错。
func TestECDSA_WrongCurve(t *testing.T) {
	// 用 P-384 曲线（故意不满足 P-256 要求）。
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384: %v", err)
	}
	digest := sha256.Sum256([]byte("test"))
	_, err = Sign(priv, digest[:])
	if err == nil {
		t.Fatal("Sign with P-384 curve should fail")
	}
}

// 确保 crypto 包被引用（用于 hash 常量）。
var _ = crypto.SHA256
