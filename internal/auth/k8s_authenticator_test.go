package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 生成 RSA 测试密钥。
func generateRSATestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return key
}

// newTestK8sAuthenticator 创建测试 K8s 认证器。
func newTestK8sAuthenticator(t *testing.T, key *rsa.PrivateKey, mappings map[string]K8sRoleMapping) *K8sAuthenticator {
	t.Helper()
	cfg := K8sAuthConfig{
		Issuer:      "https://kubernetes.default.svc.cluster.local",
		Audience:    []string{"yvonne-kms"},
		RoleMapping: mappings,
	}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}
	a, err := NewK8sAuthenticatorWithKeyFunc(cfg, keyFunc)
	if err != nil {
		t.Fatalf("NewK8sAuthenticator: %v", err)
	}
	return a
}

// signK8sJWT 签发测试用 K8s SA JWT。
func signK8sJWT(t *testing.T, key *rsa.PrivateKey, namespace, saName string, audience []string) string {
	t.Helper()
	claims := &k8sSAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://kubernetes.default.svc.cluster.local",
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Namespace:          namespace,
		ServiceAccountName: saName,
		ServiceAccountUID:  "test-uid",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// TestK8sAuth_ValidToken 合法 SA JWT 认证成功。
func TestK8sAuth_ValidToken(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {
			RoleID:         "order-service",
			AllowedKeys:    []string{"order-*"},
			AllowedActions: []string{"Encrypt", "Decrypt"},
		},
	})

	token := signK8sJWT(t, key, "default", "order-service", []string{"yvonne-kms"})
	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q", policy.RoleID)
	}
	if len(policy.AllowedKeys) != 1 || policy.AllowedKeys[0] != "order-*" {
		t.Fatalf("AllowedKeys = %v", policy.AllowedKeys)
	}
}

// TestK8sAuth_WrongAudience 错误 audience 拒绝。
func TestK8sAuth_WrongAudience(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {RoleID: "test"},
	})

	token := signK8sJWT(t, key, "default", "order-service", []string{"wrong-audience"})
	_, err := auth.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("wrong audience should fail")
	}
}

// TestK8sAuth_UnmappedSA 未映射的 SA 拒绝。
func TestK8sAuth_UnmappedSA(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {RoleID: "test"},
	})

	token := signK8sJWT(t, key, "default", "unknown-service", []string{"yvonne-kms"})
	_, err := auth.Authenticate(context.Background(), token)
	if err == nil {
		t.Fatal("unmapped SA should fail")
	}
}

// TestK8sAuth_ExpiredToken 过期 JWT 拒绝。
func TestK8sAuth_ExpiredToken(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {RoleID: "test"},
	})

	claims := &k8sSAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://kubernetes.default.svc.cluster.local",
			Audience:  []string{"yvonne-kms"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // 过期
		},
		Namespace:          "default",
		ServiceAccountName: "order-service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(key)

	_, err := auth.Authenticate(context.Background(), signed)
	if err == nil {
		t.Fatal("expired token should fail")
	}
}

// TestK8sAuth_EmptyToken 空 token 拒绝。
func TestK8sAuth_EmptyToken(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {RoleID: "test"},
	})

	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Fatal("empty token should fail")
	}
}

// TestK8sAuth_WrongIssuer 错误 issuer 拒绝。
func TestK8sAuth_WrongIssuer(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"default:order-service": {RoleID: "test"},
	})

	claims := &k8sSAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://wrong-issuer.example.com",
			Audience:  []string{"yvonne-kms"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		Namespace:          "default",
		ServiceAccountName: "order-service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(key)

	_, err := auth.Authenticate(context.Background(), signed)
	if err == nil {
		t.Fatal("wrong issuer should fail")
	}
}

// TestK8sAuth_ConfigValidation 配置校验。
func TestK8sAuth_ConfigValidation(t *testing.T) {
	// 缺 issuer。
	_, err := NewK8sAuthenticator(K8sAuthConfig{
		Audience:    []string{"yvonne"},
		RoleMapping: map[string]K8sRoleMapping{"a:b": {RoleID: "x"}},
	})
	if err == nil {
		t.Fatal("missing issuer should fail")
	}

	// 缺 audience。
	_, err = NewK8sAuthenticator(K8sAuthConfig{
		Issuer:      "https://k8s",
		RoleMapping: map[string]K8sRoleMapping{"a:b": {RoleID: "x"}},
	})
	if err == nil {
		t.Fatal("missing audience should fail")
	}

	// 缺 role_mapping。
	_, err = NewK8sAuthenticator(K8sAuthConfig{
		Issuer:   "https://k8s",
		Audience: []string{"yvonne"},
	})
	if err == nil {
		t.Fatal("missing role_mapping should fail")
	}
}

// TestK8sAuth_MultipleNamespaces 不同 namespace 的 SA 映射不同 Policy。
func TestK8sAuth_MultipleNamespaces(t *testing.T) {
	key := generateRSATestKey(t)
	auth := newTestK8sAuthenticator(t, key, map[string]K8sRoleMapping{
		"prod:order-service": {
			RoleID:         "order-prod",
			AllowedKeys:    []string{"order-prod-*"},
			AllowedActions: []string{"Encrypt"},
		},
		"dev:order-service": {
			RoleID:         "order-dev",
			AllowedKeys:    []string{"order-dev-*"},
			AllowedActions: []string{"Encrypt", "Decrypt"},
		},
	})

	// prod namespace。
	tokenProd := signK8sJWT(t, key, "prod", "order-service", []string{"yvonne-kms"})
	policyProd, err := auth.Authenticate(context.Background(), tokenProd)
	if err != nil {
		t.Fatalf("prod: %v", err)
	}
	if policyProd.RoleID != "order-prod" {
		t.Fatalf("prod RoleID = %q", policyProd.RoleID)
	}

	// dev namespace。
	tokenDev := signK8sJWT(t, key, "dev", "order-service", []string{"yvonne-kms"})
	policyDev, err := auth.Authenticate(context.Background(), tokenDev)
	if err != nil {
		t.Fatalf("dev: %v", err)
	}
	if policyDev.RoleID != "order-dev" {
		t.Fatalf("dev RoleID = %q", policyDev.RoleID)
	}
}

// 确保 pem import 被引用（测试辅助可能用到）。
var _ = pem.Decode
