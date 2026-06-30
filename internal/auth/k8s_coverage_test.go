// Package auth - K8s validateHost 补充测试。
package auth

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateHost_IP(t *testing.T) {
	if err := validateHost("10.0.0.1"); err != nil {
		t.Fatalf("IP should be valid: %v", err)
	}
	t.Log("✅ validateHost IP")
}

func TestValidateHost_IPv6(t *testing.T) {
	if err := validateHost("::1"); err != nil {
		t.Fatalf("IPv6 should be valid: %v", err)
	}
	t.Log("✅ validateHost IPv6")
}

func TestValidateHost_Hostname(t *testing.T) {
	if err := validateHost("kubernetes.default.svc.cluster.local"); err != nil {
		t.Fatalf("hostname should be valid: %v", err)
	}
	t.Log("✅ validateHost hostname")
}

func TestValidateHost_Empty(t *testing.T) {
	if err := validateHost(""); err == nil {
		t.Fatal("empty host should fail")
	}
	t.Log("✅ validateHost empty → error")
}

func TestValidateHost_Scheme(t *testing.T) {
	if err := validateHost("https://host"); err == nil {
		t.Fatal("host with scheme should fail")
	}
	t.Log("✅ validateHost scheme → error")
}

func TestValidateHost_Path(t *testing.T) {
	if err := validateHost("host/path"); err == nil {
		t.Fatal("host with path should fail")
	}
	t.Log("✅ validateHost path → error")
}

func TestValidateHost_InvalidChar(t *testing.T) {
	if err := validateHost("host@evil"); err == nil {
		t.Fatal("host with invalid char should fail")
	}
	t.Log("✅ validateHost invalid char → error")
}

func TestNewK8sAuthenticator_MissingIssuer(t *testing.T) {
	_, err := NewK8sAuthenticator(K8sAuthConfig{})
	if err == nil {
		t.Fatal("should fail without issuer")
	}
	t.Logf("✅ NewK8sAuthenticator missing issuer: %v", err)
}

func TestNewK8sAuthenticator_MissingAudience(t *testing.T) {
	_, err := NewK8sAuthenticator(K8sAuthConfig{Issuer: "test"})
	if err == nil {
		t.Fatal("should fail without audience")
	}
	t.Logf("✅ NewK8sAuthenticator missing audience: %v", err)
}

func TestNewK8sAuthenticator_MissingRoleMapping(t *testing.T) {
	_, err := NewK8sAuthenticator(K8sAuthConfig{Issuer: "test", Audience: []string{"test"}})
	if err == nil {
		t.Fatal("should fail without role_mapping")
	}
	t.Logf("✅ NewK8sAuthenticator missing role_mapping: %v", err)
}

// TestNewK8sAuthenticatorWithKeyFunc 带 mock keyFunc 构造。
func TestNewK8sAuthenticatorWithKeyFunc(t *testing.T) {
	cfg := K8sAuthConfig{
		Issuer:   "https://k8s.test",
		Audience: []string{"yvonne"},
		RoleMapping: map[string]K8sRoleMapping{
			"default:app": {
				RoleID:         "app",
				AllowedKeys:    []string{"*"},
				AllowedActions: []string{"encrypt", "decrypt"},
			},
		},
	}

	mockKeyFunc := func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	}

	auth, err := NewK8sAuthenticatorWithKeyFunc(cfg, mockKeyFunc)
	if err != nil {
		t.Fatalf("NewK8sAuthenticatorWithKeyFunc: %v", err)
	}
	if auth == nil {
		t.Fatal("should not be nil")
	}

	// Close 应不 panic（jwks 为 nil）。
	auth.Close()
	t.Log("✅ NewK8sAuthenticatorWithKeyFunc + Close")
}

// TestK8sAuthenticator_AuthenticateEmptyToken 空 token 拒绝。
func TestK8sAuthenticator_AuthenticateEmptyToken(t *testing.T) {
	cfg := K8sAuthConfig{
		Issuer:   "test",
		Audience: []string{"yvonne"},
		RoleMapping: map[string]K8sRoleMapping{
			"ns:sa": {RoleID: "r", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}},
		},
	}
	auth, _ := NewK8sAuthenticatorWithKeyFunc(cfg, func(t *jwt.Token) (interface{}, error) { return nil, nil })

	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Fatal("should reject empty token")
	}
	t.Logf("✅ K8s Authenticate empty token: %v", err)
}
