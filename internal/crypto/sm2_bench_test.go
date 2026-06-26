//go:build gmsm

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// BenchmarkSM2_GenerateKeyPair SM2 密钥对生成。
func BenchmarkSM2_GenerateKeyPair(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GenerateSM2KeyPair()
	}
}

// BenchmarkSM2_Encrypt SM2 加密。
func BenchmarkSM2_Encrypt(b *testing.B) {
	pub, _, _ := GenerateSM2KeyPair()
	plaintext := []byte("benchmark data 32 bytes.......")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SM2Encrypt(pub, plaintext)
	}
}

// BenchmarkSM2_Decrypt SM2 解密。
func BenchmarkSM2_Decrypt(b *testing.B) {
	pub, priv, _ := GenerateSM2KeyPair()
	plaintext := []byte("benchmark data 32 bytes.......")
	ciphertext, _ := SM2Encrypt(pub, plaintext)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SM2Decrypt(priv, ciphertext)
	}
}

// BenchmarkSM2_Sign SM2 签名。
func BenchmarkSM2_Sign(b *testing.B) {
	_, priv, _ := GenerateSM2KeyPair()
	msg := []byte("message to sign for benchmark")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SM2Sign(priv, msg)
	}
}

// BenchmarkSM2_Verify SM2 验签。
func BenchmarkSM2_Verify(b *testing.B) {
	pub, priv, _ := GenerateSM2KeyPair()
	msg := []byte("message to sign for benchmark")
	sig, _ := SM2Sign(priv, msg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		SM2Verify(pub, msg, sig)
	}
}

// === 对比基准：RSA-2048 ===

// BenchmarkRSA2048_GenerateKeyPair RSA-2048 密钥对生成。
func BenchmarkRSA2048_GenerateKeyPair(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rsa.GenerateKey(rand.Reader, 2048)
	}
}

// BenchmarkRSA2048_Encrypt RSA-2048 加密。
func BenchmarkRSA2048_Encrypt(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	plaintext := []byte("benchmark data 32 bytes.......")
	hash := sha256.New()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rsa.EncryptOAEP(hash, rand.Reader, &priv.PublicKey, plaintext, nil)
	}
}

// BenchmarkRSA2048_Sign RSA-2048 签名。
func BenchmarkRSA2048_Sign(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	hashed := []byte("hashed message for rsa sign test")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rsa.SignPKCS1v15(rand.Reader, priv, 0, hashed)
	}
}

// === 对比基准：ECDSA P-256 ===

// BenchmarkECDSA_P256_GenerateKeyPair ECDSA P-256 密钥对生成。
func BenchmarkECDSA_P256_GenerateKeyPair(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// BenchmarkECDSA_P256_Sign ECDSA P-256 签名。
func BenchmarkECDSA_P256_Sign(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hashed := []byte("hashed message for ecdsa test!")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ecdsa.SignASN1(rand.Reader, priv, hashed)
	}
}

// BenchmarkECDSA_P256_Verify ECDSA P-256 验签。
func BenchmarkECDSA_P256_Verify(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hashed := []byte("hashed message for ecdsa test!")
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, hashed)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ecdsa.VerifyASN1(&priv.PublicKey, hashed, sig)
	}
}
