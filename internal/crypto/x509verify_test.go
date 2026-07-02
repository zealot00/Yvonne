package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// TestVerifyCertificate_RSA_ValidChain RSA 证书链验证通过。
func TestVerifyCertificate_RSA_ValidChain(t *testing.T) {
	// 创建 CA。
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeRSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Verify RSA CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}

	// 签发终端证书。
	endPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert, _ := ParseCertificatePEM(caResult.PEM)
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "verify.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		CertType:  CertTypeSign,
		TTL:       DefaultCertTTL,
		DNSNames:  []string{"verify.example.com"},
	}
	endResult, err := IssueCertificate(endReq, caCert, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate end: %v", err)
	}

	// 验证证书链。
	result, err := VerifyCertificate(endResult.PEM, caResult.PEM, nil)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if !result.Valid {
		t.Fatalf("cert should be valid, error: %s", result.Error)
	}
	t.Log("✅ RSA cert chain verified")
}

// TestVerifyCertificate_RSA_Expired 过期证书。
func TestVerifyCertificate_RSA_Expired(t *testing.T) {
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeRSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Expired CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, _ := ParseCertificatePEM(caResult.PEM)

	// 签发已过期的终端证书（TTL=-1hour）。
	endPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "expired.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		TTL:       -1 * time.Hour, // 已过期
	}
	endResult, err := IssueCertificate(endReq, caCert, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate end: %v", err)
	}

	// 验证应报告过期。
	result, err := VerifyCertificate(endResult.PEM, caResult.PEM, nil)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	// 过期证书验证失败（Valid=false 或 Expired=true）。
	if result.Valid && !result.Expired {
		t.Fatal("expired cert should not be valid")
	}
	t.Logf("✅ Expired cert detected: valid=%v expired=%v", result.Valid, result.Expired)
}

// TestVerifyCertificate_ECDSA_ValidChain ECDSA 证书链验证。
func TestVerifyCertificate_ECDSA_ValidChain(t *testing.T) {
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeECDSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Verify ECDSA CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeECDSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, _ := ParseCertificatePEM(caResult.PEM)

	endPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "ecdsa-verify.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeECDSA,
		CertType:  CertTypeSign,
		TTL:       DefaultCertTTL,
		DNSNames:  []string{"ecdsa-verify.example.com"},
	}
	endResult, err := IssueCertificate(endReq, caCert, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate end: %v", err)
	}

	result, err := VerifyCertificate(endResult.PEM, caResult.PEM, nil)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if !result.Valid {
		t.Fatalf("ECDSA cert should be valid, error: %s", result.Error)
	}
	t.Log("✅ ECDSA cert chain verified")
}
