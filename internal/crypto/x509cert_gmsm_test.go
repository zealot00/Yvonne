//go:build gmsm

package crypto

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// TestIssueCertificate_SM2_SelfSignedCA SM2 CA 自签根证书。
func TestIssueCertificate_SM2_SelfSignedCA(t *testing.T) {
	// 生成 SM2 密钥对。
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}

	// 私钥 PEM。
	privPEM, err := gmx509.WritePrivateKeyToPem(priv, nil)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPem: %v", err)
	}

	// 创建 SecureSigner。
	signer, err := NewSecureSigner(privPEM, KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner SM2: %v", err)
	}
	defer signer.Dispose()

	// 签发 SM2 CA 证书。
	req := CertRequest{
		Subject:   pkix.Name{CommonName: "Test SM2 CA"},
		PublicKey: &priv.PublicKey,
		KeyType:   KeyTypeSM2,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}

	result, err := IssueCertificate(req, nil, signer)
	if err != nil {
		t.Fatalf("IssueCertificate SM2 CA: %v", err)
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}
	if result.SerialNumber == nil {
		t.Fatal("SerialNumber should not be nil")
	}

	t.Logf("✅ SM2 CA self-signed: serial=%s, PEM=%d bytes", result.SerialNumber, len(result.PEM))
}

// TestIssueCertificate_SM2_EndCert SM2 CA 签发终端证书。
func TestIssueCertificate_SM2_EndCert(t *testing.T) {
	// 1. 创建 SM2 CA。
	caPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 CA key: %v", err)
	}
	caPrivPEM, _ := gmx509.WritePrivateKeyToPem(caPriv, nil)
	caSigner, err := NewSecureSigner(caPrivPEM, KeyTypeSM2)
	if err != nil {
		t.Fatalf("NewSecureSigner CA: %v", err)
	}
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Test SM2 CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeSM2,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate SM2 CA: %v", err)
	}

	// 2. 生成终端 SM2 密钥。
	endPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 end key: %v", err)
	}

	// 3. 签发终端证书（SM2 路径用 CACertPEM 绕过标准库解析限制）。
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "sm2.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeSM2,
		CertType:  CertTypeSign,
		TTL:       DefaultCertTTL,
		CACertPEM: caResult.PEM, // SM2 CA 证书 PEM（tjfoc 格式）
	}
	endResult, err := IssueCertificate(endReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate SM2 end: %v", err)
	}
	if len(endResult.PEM) == 0 {
		t.Fatal("end cert PEM should not be empty")
	}

	t.Logf("✅ SM2 end cert issued by CA: PEM=%d bytes", len(endResult.PEM))
}
