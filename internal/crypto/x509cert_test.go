package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// TestIssueCertificate_RSA_SelfSignedCA RSA CA 自签根证书。
func TestIssueCertificate_RSA_SelfSignedCA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // 测试用 2048 加速
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	signer, err := NewSecureSigner(der, KeyTypeRSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	req := CertRequest{
		Subject:   pkix.Name{CommonName: "Test RSA CA"},
		PublicKey: &priv.PublicKey,
		KeyType:   KeyTypeRSA,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}

	result, err := IssueCertificate(req, nil, signer)
	if err != nil {
		t.Fatalf("IssueCertificate RSA CA: %v", err)
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}
	if result.SerialNumber == nil {
		t.Fatal("SerialNumber should not be nil")
	}

	// 验证 PEM 可解析。
	cert, err := ParseCertificatePEM(result.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("cert should be CA")
	}
	if cert.Subject.CommonName != "Test RSA CA" {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, "Test RSA CA")
	}
	t.Logf("✅ RSA CA self-signed: serial=%s, notAfter=%s", result.SerialNumber, result.NotAfter.Format(time.RFC3339))
}

// TestIssueCertificate_ECDSA_SelfSignedCA ECDSA CA 自签根证书。
func TestIssueCertificate_ECDSA_SelfSignedCA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	signer, err := NewSecureSigner(der, KeyTypeECDSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	req := CertRequest{
		Subject:   pkix.Name{CommonName: "Test ECDSA CA"},
		PublicKey: &priv.PublicKey,
		KeyType:   KeyTypeECDSA,
		CertType:  CertTypeCA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}

	result, err := IssueCertificate(req, nil, signer)
	if err != nil {
		t.Fatalf("IssueCertificate ECDSA CA: %v", err)
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}

	cert, err := ParseCertificatePEM(result.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("cert should be CA")
	}
	t.Logf("✅ ECDSA CA self-signed: serial=%s", result.SerialNumber)
}

// TestIssueCertificate_RSA_EndCert RSA CA 签发终端证书。
func TestIssueCertificate_RSA_EndCert(t *testing.T) {
	// 1. 创建 CA。
	caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, err := NewSecureSigner(caDER, KeyTypeRSA)
	if err != nil {
		t.Fatalf("NewSecureSigner CA: %v", err)
	}
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Test RSA CA"},
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
		t.Fatalf("ParseCertificatePEM CA: %v", err)
	}

	// 2. 生成终端密钥。
	endPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 3. 签发终端证书。
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "test.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeRSA,
		CertType:  CertTypeSign,
		TTL:       DefaultCertTTL,
		DNSNames:  []string{"test.example.com"},
	}
	endResult, err := IssueCertificate(endReq, caCert, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate end: %v", err)
	}

	endCert, err := ParseCertificatePEM(endResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM end: %v", err)
	}
	if endCert.IsCA {
		t.Fatal("end cert should not be CA")
	}
	if endCert.Issuer.CommonName != "Test RSA CA" {
		t.Fatalf("issuer CN = %q, want %q", endCert.Issuer.CommonName, "Test RSA CA")
	}
	t.Log("✅ RSA end cert issued by CA")
}

// TestIssueCertificate_ECDSA_EndCert ECDSA CA 签发终端证书。
func TestIssueCertificate_ECDSA_EndCert(t *testing.T) {
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caPriv)
	caSigner, err := NewSecureSigner(caDER, KeyTypeECDSA)
	if err != nil {
		t.Fatalf("NewSecureSigner CA: %v", err)
	}
	defer caSigner.Dispose()

	caReq := CertRequest{
		Subject:   pkix.Name{CommonName: "Test ECDSA CA"},
		PublicKey: &caPriv.PublicKey,
		KeyType:   KeyTypeECDSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	caResult, err := IssueCertificate(caReq, nil, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate CA: %v", err)
	}
	caCert, err := ParseCertificatePEM(caResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM CA: %v", err)
	}

	endPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	endReq := CertRequest{
		Subject:   pkix.Name{CommonName: "ecdsa.example.com"},
		PublicKey: &endPriv.PublicKey,
		KeyType:   KeyTypeECDSA,
		CertType:  CertTypeSign,
		TTL:       DefaultCertTTL,
	}
	endResult, err := IssueCertificate(endReq, caCert, caSigner)
	if err != nil {
		t.Fatalf("IssueCertificate end: %v", err)
	}

	endCert, err := ParseCertificatePEM(endResult.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM end: %v", err)
	}
	if endCert.IsCA {
		t.Fatal("end cert should not be CA")
	}
	t.Log("✅ ECDSA end cert issued by CA")
}

// TestParseCertificatePEM PEM 解析往返。
func TestParseCertificatePEM(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	signer, _ := NewSecureSigner(der, KeyTypeRSA)
	defer signer.Dispose()

	req := CertRequest{
		Subject:   pkix.Name{CommonName: "Parse Test"},
		PublicKey: &priv.PublicKey,
		KeyType:   KeyTypeRSA,
		IsCA:      true,
		TTL:       DefaultRootTTL,
	}
	result, err := IssueCertificate(req, nil, signer)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// 正常解析。
	cert, err := ParseCertificatePEM(result.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if cert.Subject.CommonName != "Parse Test" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}

	// 无效 PEM。
	_, err = ParseCertificatePEM([]byte("not a pem"))
	if err == nil {
		t.Fatal("should error on invalid PEM")
	}
	t.Log("✅ ParseCertificatePEM round-trip")
}

// TestSecureSigner_RSA SecureSigner RSA 签名 + Dispose。
func TestSecureSigner_RSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)

	signer, err := NewSecureSigner(der, KeyTypeRSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}

	// 签名。
	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// 验证签名（PKCS#1v1.5，证书签名标准）。
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15: %v", err)
	}

	// Dispose 后签名应失败。
	signer.Dispose()
	_, err = signer.Sign(rand.Reader, digest[:], nil)
	if err == nil {
		t.Fatal("Sign after Dispose should fail")
	}
	t.Log("✅ SecureSigner RSA sign + dispose")
}

// TestSecureSigner_ECDSA SecureSigner ECDSA 签名。
func TestSecureSigner_ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)

	signer, err := NewSecureSigner(der, KeyTypeECDSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}
	defer signer.Dispose()

	digest := sha256.Sum256([]byte("ecdsa test"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// 验证。
	if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
		t.Fatal("ECDSA verify failed")
	}
	t.Log("✅ SecureSigner ECDSA sign")
}
