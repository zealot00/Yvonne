//go:build gmsm

// PKI crypto 层覆盖率补充测试（gmsm 构建标签）。
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm2"
)

// TestParsePublicKey_SM2 测试 ParsePublicKey 解析 SM2 公钥 PEM。
func TestParsePublicKey_SM2(t *testing.T) {
	// 生成 SM2 密钥对。
	pub, _, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	// ParsePublicKey 应正确解析。
	parsed, err := ParsePublicKey(pub.PEM, KeyTypeSM2)
	if err != nil {
		t.Fatalf("ParsePublicKey SM2: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed key should not be nil")
	}
	if _, ok := parsed.(*sm2.PublicKey); !ok {
		t.Fatalf("expected *sm2.PublicKey, got %T", parsed)
	}
	t.Logf("✅ ParsePublicKey SM2: %T", parsed)
}

// TestParsePublicKey_UnsupportedType 测试不支持的密钥类型。
func TestParsePublicKey_UnsupportedType(t *testing.T) {
	_, err := ParsePublicKey(nil, "unsupported")
	if err == nil {
		t.Fatal("should error for unsupported key type")
	}
	t.Logf("✅ ParsePublicKey unsupported: %v", err)
}

// TestCRLToPEM 测试 CRL DER → PEM 编码。
func TestCRLToPEM(t *testing.T) {
	// 先创建 RSA CA 并签发 CRL（复用已有测试模式）。
	caPriv, _, err := GenerateAsymmetricKey(KeyTypeRSA)
	if err != nil {
		t.Fatalf("GenerateAsymmetricKey: %v", err)
	}
	caSigner, err := NewSecureSigner(mustPrivateKeyDER(t, caPriv, "rsa"), KeyTypeRSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer caSigner.Dispose()

	caResult, err := IssueCertificate(CertRequest{
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}

	caCert, err := x509.ParseCertificate(caResult.DER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// 签发 CRL。
	revoked := []RevokedCert{
		{
			SerialNumber: big.NewInt(12345),
			RevokedAt:    time.Now().UTC(),
			Reason:       1,
		},
	}
	crlDER, err := CreateCRL(caCert, caSigner, revoked)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	// CRLToPEM。
	crlPEM := CRLToPEM(crlDER)
	if len(crlPEM) == 0 {
		t.Fatal("CRLToPEM should return non-empty")
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("CRLToPEM should produce valid PEM")
	}
	if block.Type != "X509 CRL" {
		t.Fatalf("PEM type = %q, want %q", block.Type, "X509 CRL")
	}
	t.Logf("✅ CRLToPEM: %d bytes PEM, type=%s", len(crlPEM), block.Type)
}

// TestCreateSM2CRL 测试 SM2 CA 签发 CRL。
func TestCreateSM2CRL(t *testing.T) {
	// 生成 SM2 CA 密钥。
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	privPEM, err := SM2PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToPEM: %v", err)
	}

	signer, err := NewSecureSigner(privPEM, KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner SM2: %v", err)
	}
	defer signer.Dispose()

	// 签发 SM2 CA 证书。
	caResult, err := IssueCertificate(CertRequest{
		PublicKey: pub.Key,
		KeyType:   KeyTypeSM2,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}, nil, signer)
	if err != nil {
		t.Fatalf("IssueCertificate SM2 CA: %v", err)
	}

	// 签发 SM2 CRL。
	revoked := []RevokedCert{
		{
			SerialNumber: big.NewInt(99999),
			RevokedAt:    time.Now().UTC(),
			Reason:       1,
		},
	}
	crlDER, err := CreateSM2CRL(caResult.PEM, signer, revoked)
	if err != nil {
		t.Fatalf("CreateSM2CRL: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("CRL DER should not be empty")
	}
	t.Logf("✅ CreateSM2CRL: %d bytes", len(crlDER))
}

// TestCreateSM2CRL_InvalidPEM 测试无效 CA 证书 PEM。
func TestCreateSM2CRL_InvalidPEM(t *testing.T) {
	signer, err := NewSecureSigner(mustSM2PrivPEM(t), KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	_, err = CreateSM2CRL([]byte("not a PEM"), signer, nil)
	if err == nil {
		t.Fatal("should error for invalid PEM")
	}
	t.Logf("✅ CreateSM2CRL invalid PEM: %v", err)
}

// TestSM2Signer_Public 测试 SecureSigner.Public() 返回 SM2 公钥。
func TestSM2Signer_Public(t *testing.T) {
	signer, err := NewSecureSigner(mustSM2PrivPEM(t), KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() should not return nil")
	}
	if _, ok := pub.(*sm2.PublicKey); !ok {
		t.Fatalf("expected *sm2.PublicKey, got %T", pub)
	}
	t.Logf("✅ SM2 Signer Public(): %T", pub)
}

// TestSM2Signer_Sign 测试 SecureSigner.Sign() SM2 签名。
func TestSM2Signer_Sign(t *testing.T) {
	signer, err := NewSecureSigner(mustSM2PrivPEM(t), KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	digest := []byte("test digest for sm2 signing")
	sig, err := signer.Sign(nil, digest, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}
	t.Logf("✅ SM2 Signer Sign: %d bytes", len(sig))
}

// TestSM2Signer_DisposeAfterSign 测试 Dispose 后 Sign 失败。
func TestSM2Signer_DisposeAfterSign(t *testing.T) {
	signer, err := NewSecureSigner(mustSM2PrivPEM(t), KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	signer.Dispose()

	_, err = signer.Sign(nil, []byte("digest"), nil)
	if err == nil {
		t.Fatal("Sign after Dispose should error")
	}
	t.Logf("✅ SM2 Signer after Dispose: %v", err)
}

// mustSM2PrivPEM 生成测试用 SM2 私钥 PEM。
func mustSM2PrivPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	pem, err := SM2PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("SM2PrivateKeyToPEM: %v", err)
	}
	return pem
}

// mustPrivateKeyDER 将 RSA/ECDSA 私钥序列化为 PKCS#8 DER。
func mustPrivateKeyDER(t *testing.T, priv interface{}, keyType string) []byte {
	t.Helper()
	der, err := PrivateKeyToDER(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToDER %s: %v", keyType, err)
	}
	return der
}
