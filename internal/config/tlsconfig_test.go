package config

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert 生成自签名 CA 证书 + 写入文件，返回路径。
func generateSelfSignedCert(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")

	// 生成 CA 证书（简化：用固定 RSA 密钥）。
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	// 用 RSA 生成（避免 import ecdsa）。
	priv := generateRSAKey(t)
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return certPath
}

// TestBuildTLSConfig_Disabled TLS 禁用时返回 nil。
func TestBuildTLSConfig_Disabled(t *testing.T) {
	cfg := TLSConfig{Enabled: false}
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if tlsCfg != nil {
		t.Fatal("disabled TLS should return nil")
	}
}

// TestBuildTLSConfig_NoClientAuth 默认 NoClientCert。
func TestBuildTLSConfig_NoClientAuth(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "TLS1.3",
	}
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS1.3", tlsCfg.MinVersion)
	}
}

// TestBuildTLSConfig_RequireClientCert mTLS require 模式。
func TestBuildTLSConfig_RequireClientCert(t *testing.T) {
	caPath := generateSelfSignedCert(t)
	cfg := TLSConfig{
		Enabled:      true,
		MinVersion:   "TLS1.2",
		ClientAuth:   "require",
		ClientCAFile: caPath,
	}
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("ClientCAs should not be nil")
	}
}

// TestBuildTLSConfig_OptionalClientCert mTLS optional 模式。
func TestBuildTLSConfig_OptionalClientCert(t *testing.T) {
	caPath := generateSelfSignedCert(t)
	cfg := TLSConfig{
		Enabled:      true,
		MinVersion:   "TLS1.2",
		ClientAuth:   "optional",
		ClientCAFile: caPath,
	}
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven", tlsCfg.ClientAuth)
	}
}

// TestBuildTLSConfig_RequireWithoutCA require 模式无 CA → error。
func TestBuildTLSConfig_RequireWithoutCA(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "TLS1.2",
		ClientAuth: "require",
		// 无 ClientCAFile
	}
	_, err := BuildTLSConfig(cfg)
	if err == nil {
		t.Fatal("require without CA should fail")
	}
}

// TestBuildTLSConfig_InvalidClientAuth 无效 client_auth → error。
func TestBuildTLSConfig_InvalidClientAuth(t *testing.T) {
	cfg := TLSConfig{
		Enabled:    true,
		MinVersion: "TLS1.2",
		ClientAuth: "invalid",
	}
	_, err := BuildTLSConfig(cfg)
	if err == nil {
		t.Fatal("invalid client_auth should fail")
	}
}

// TestBuildTLSConfig_InvalidCAFile CA 文件不存在 → error。
func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	cfg := TLSConfig{
		Enabled:      true,
		MinVersion:   "TLS1.2",
		ClientAuth:   "require",
		ClientCAFile: "/nonexistent/ca.pem",
	}
	_, err := BuildTLSConfig(cfg)
	if err == nil {
		t.Fatal("nonexistent CA file should fail")
	}
}
