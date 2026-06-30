// Package config - 国密 TLS 配置测试。
package config

import (
	"testing"
)

// TestGMTLS_NotEnabled 未启用国密 TLS 拒绝。
func TestGMTLS_NotEnabled(t *testing.T) {
	cfg := TLSConfig{GMEnabled: false}
	_, err := BuildGMTLSConfig(cfg)
	if err == nil {
		t.Fatal("should fail when GMEnabled=false")
	}
	t.Logf("✅ GMEnabled=false rejected: %v", err)
}

// TestGMTLS_MissingCerts 缺少双证书拒绝。
func TestGMTLS_MissingCerts(t *testing.T) {
	cfg := TLSConfig{
		GMEnabled:      true,
		GMSignCertFile: "", // 缺少
		GMSignKeyFile:  "",
	}
	_, err := BuildGMTLSConfig(cfg)
	if err == nil {
		t.Fatal("should fail when sign cert missing")
	}
	t.Logf("✅ Missing sign cert rejected: %v", err)
}

// TestGMTLS_MissingEncCert 缺少加密证书拒绝。
func TestGMTLS_MissingEncCert(t *testing.T) {
	cfg := TLSConfig{
		GMEnabled:      true,
		GMSignCertFile: "/tmp/sign.pem",
		GMSignKeyFile:  "/tmp/sign-key.pem",
		GMEncCertFile:  "", // 缺少
		GMEncKeyFile:   "",
	}
	_, err := BuildGMTLSConfig(cfg)
	if err == nil {
		t.Fatal("should fail when enc cert missing")
	}
	t.Logf("✅ Missing enc cert rejected: %v", err)
}

// TestGMTLS_NonExistentCert 文件不存在拒绝。
func TestGMTLS_NonExistentCert(t *testing.T) {
	cfg := TLSConfig{
		GMEnabled:      true,
		GMSignCertFile: "/tmp/nonexistent-sign.pem",
		GMSignKeyFile:  "/tmp/nonexistent-sign-key.pem",
		GMEncCertFile:  "/tmp/nonexistent-enc.pem",
		GMEncKeyFile:   "/tmp/nonexistent-enc-key.pem",
	}
	_, err := BuildGMTLSConfig(cfg)
	if err == nil {
		t.Fatal("should fail when cert files don't exist")
	}
	t.Logf("✅ Non-existent cert rejected: %v", err)
}

// TestGMTLS_InvalidClientAuth 非法 client_auth 拒绝。
func TestGMTLS_InvalidClientAuth(t *testing.T) {
	cfg := TLSConfig{
		GMEnabled:      true,
		GMSignCertFile: "/tmp/sign.pem",
		GMSignKeyFile:  "/tmp/sign-key.pem",
		GMEncCertFile:  "/tmp/enc.pem",
		GMEncKeyFile:   "/tmp/enc-key.pem",
		ClientAuth:     "invalid",
	}
	_, err := BuildGMTLSConfig(cfg)
	if err == nil {
		t.Fatal("should fail with invalid client_auth")
	}
	t.Logf("✅ Invalid client_auth rejected: %v", err)
}
