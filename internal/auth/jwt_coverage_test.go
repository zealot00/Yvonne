// Package auth - JWT 辅助函数补充测试。
package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestParseSigningMethod_AllMethods 所有签名方法。
func TestParseSigningMethod_AllMethods(t *testing.T) {
	methods := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	for _, m := range methods {
		sm, err := parseSigningMethod(m)
		if err != nil {
			t.Errorf("parseSigningMethod(%s): %v", m, err)
		}
		if sm == nil {
			t.Errorf("parseSigningMethod(%s): nil", m)
		}
	}
	t.Logf("✅ parseSigningMethod: %d methods", len(methods))
}

func TestParseSigningMethod_SM2(t *testing.T) {
	_, err := parseSigningMethod("SM2")
	if err == nil {
		t.Log("✅ parseSigningMethod SM2: available (gmsm build)")
	} else {
		t.Logf("✅ parseSigningMethod SM2: not available (non-gmsm): %v", err)
	}
}

func TestParseSigningMethod_Invalid(t *testing.T) {
	_, err := parseSigningMethod("INVALID")
	if err == nil {
		t.Fatal("should fail for invalid method")
	}
	t.Log("✅ parseSigningMethod invalid → error")
}

func TestParseSigningMethod_Empty(t *testing.T) {
	_, err := parseSigningMethod("")
	if err == nil {
		t.Fatal("should fail for empty method")
	}
	t.Log("✅ parseSigningMethod empty → error")
}

// TestLoadRSAPublicKey_NotFound 文件不存在。
func TestLoadRSAPublicKey_NotFound(t *testing.T) {
	_, err := loadRSAPublicKey("/nonexistent/rsa.pem")
	if err == nil {
		t.Fatal("should fail for nonexistent file")
	}
	t.Logf("✅ loadRSAPublicKey not found: %v", err)
}

// TestLoadECDSAPublicKey_NotFound 文件不存在。
func TestLoadECDSAPublicKey_NotFound(t *testing.T) {
	_, err := loadECDSAPublicKey("/nonexistent/ecdsa.pem")
	if err == nil {
		t.Fatal("should fail for nonexistent file")
	}
	t.Logf("✅ loadECDSAPublicKey not found: %v", err)
}

// TestLoadRSAPublicKey_InvalidPEM 无效 PEM。
func TestLoadRSAPublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.pem")
	os.WriteFile(path, []byte("not a PEM file"), 0o600)

	_, err := loadRSAPublicKey(path)
	if err == nil {
		t.Fatal("should fail for invalid PEM")
	}
	t.Logf("✅ loadRSAPublicKey invalid PEM: %v", err)
}

// TestLoadECDSAPublicKey_InvalidPEM 无效 PEM。
func TestLoadECDSAPublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.pem")
	os.WriteFile(path, []byte("not a PEM file"), 0o600)

	_, err := loadECDSAPublicKey(path)
	if err == nil {
		t.Fatal("should fail for invalid PEM")
	}
	t.Logf("✅ loadECDSAPublicKey invalid PEM: %v", err)
}

// TestJWTAuthenticator_NewWithHMAC HMAC 构造。
func TestJWTAuthenticator_NewWithHMAC(t *testing.T) {
	store := NewAppRoleAuthenticator()
	store.RegisterPolicy("test-role", "", &Policy{RoleID: "test-role", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}})

	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        "test-secret-32-bytes-long-xxxxxxxx",
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
		RoleClaim:     "role",
	}, store)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator HMAC: %v", err)
	}
	if auth == nil {
		t.Fatal("should not be nil")
	}
	t.Log("✅ NewJWTAuthenticator HMAC")
}

// TestJWTAuthenticator_NewInvalidMethod 非法签名方法。
func TestJWTAuthenticator_NewInvalidMethod(t *testing.T) {
	store := NewAppRoleAuthenticator()
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "INVALID",
		Secret:        "test",
	}, store)
	if err == nil {
		t.Fatal("should fail for invalid method")
	}
	t.Logf("✅ NewJWTAuthenticator invalid method: %v", err)
}

// TestJWTAuthenticator_NewHMACNoSecret HMAC 无 secret。
func TestJWTAuthenticator_NewHMACNoSecret(t *testing.T) {
	store := NewAppRoleAuthenticator()
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        "",
	}, store)
	if err == nil {
		t.Fatal("should fail for HMAC without secret")
	}
	t.Logf("✅ NewJWTAuthenticator HMAC no secret: %v", err)
}

// 确保 jwt 包被引用。
var _ = jwt.SigningMethodHS256
