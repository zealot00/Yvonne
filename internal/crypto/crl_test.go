package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestCreateCRL_RSA RSA CA 签发 CRL。
func TestCreateCRL_RSA(t *testing.T) {
	// 创建 CA。
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeRSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "CRL RSA CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, err := ParseCertificatePEM(caResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// 创建空 CRL。
	crlDER, err := CreateCRL(caCert, caSigner, nil)
	if err != nil {
		t.Fatalf("CreateCRL empty: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatal("CRL DER should not be empty")
	}

	// 创建含一个吊销证书的 CRL。
	revoked := []RevokedCert{
		{
			SerialNumber: big.NewInt(12345),
			RevokedAt:    time.Now().UTC(),
			Reason:       1, // keyCompromise
		},
	}
	crlDER2, err := CreateCRL(caCert, caSigner, revoked)
	if err != nil {
		t.Fatalf("CreateCRL with revoked: %v", err)
	}
	if len(crlDER2) == 0 {
		t.Fatal("CRL DER should not be empty")
	}
	t.Logf("✅ CRL created: empty=%d bytes, with-revoked=%d bytes", len(crlDER), len(crlDER2))
}

// TestParseCRL 解析 CRL。
func TestParseCRL(t *testing.T) {
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeRSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Parse CRL CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, err := ParseCertificatePEM(caResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	crlDER, err := CreateCRL(caCert, caSigner, nil)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	crl, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}
	if crl == nil {
		t.Fatal("CRL should not be nil")
	}
	t.Logf("✅ CRL parsed: thisUpdate=%s", crl.ThisUpdate.Format(time.RFC3339))
}

// TestIsRevoked 检查吊销。
func TestIsRevoked(t *testing.T) {
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, _ := NewSecureSigner(caDER, KeyTypeRSA)
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Revoke CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, err := ParseCertificatePEM(caResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// 吊销 serial 12345。
	revoked := []RevokedCert{
		{SerialNumber: big.NewInt(12345), RevokedAt: time.Now().UTC()},
	}
	crlDER, err := CreateCRL(caCert, caSigner, revoked)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}

	// 12345 应被吊销。
	if !IsRevoked(crl, big.NewInt(12345)) {
		t.Fatal("serial 12345 should be revoked")
	}
	// 99999 不应被吊销。
	if IsRevoked(crl, big.NewInt(99999)) {
		t.Fatal("serial 99999 should not be revoked")
	}
	// nil 检查。
	if IsRevoked(nil, big.NewInt(1)) {
		t.Fatal("nil CRL should return false")
	}
	t.Log("✅ IsRevoked check passed")
}
