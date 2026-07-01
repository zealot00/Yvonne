//go:build gmsm

// jwt_sm2_test.go — SM2 JWT 签名验证测试。
package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tjfoc/gmsm/sm2"

	"yvonne/internal/crypto"
)

// TestJWT_SM2_SignVerify SM2 JWT 签发 + 验证往返。
func TestJWT_SM2_SignVerify(t *testing.T) {
	// 用 crypto.GenerateSM2KeyPair 获取 PEM。
	pub, priv, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	pubPEM := pub.PEM

	dir := t.TempDir()
	pubPath := filepath.Join(dir, "sm2-pub.pem")
	os.WriteFile(pubPath, pubPEM, 0o600)

	store := NewAppRoleAuthenticator()
	store.RegisterPolicy("sm2-role", "", &Policy{
		RoleID:         "sm2-role",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"*"},
	})

	authn, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "SM2",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		Audience:         []string{"test-audience"},
		RoleClaim:        "role",
	}, store)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator SM2: %v", err)
	}

	// 用 tjfoc sm2 私钥签名。
	claims := jwt.MapClaims{
		"role": "sm2-role",
		"iss":  "test-issuer",
		"aud":  "test-audience",
		"exp":  9999999999,
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("SM2"), claims)
	tokenString, err := token.SignedString(priv.Key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	policy, err := authn.Authenticate(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy == nil || policy.RoleID != "sm2-role" {
		t.Fatalf("wrong policy: %v", policy)
	}
	t.Logf("✅ SM2 JWT sign+verify: role=%s", policy.RoleID)
}

// TestJWT_SM2_Available SM2 签名方法已注册。
func TestJWT_SM2_Available(t *testing.T) {
	sm := jwt.GetSigningMethod("SM2")
	if sm == nil {
		t.Fatal("SM2 signing method should be available with -tags gmsm")
	}
	t.Logf("✅ SM2 signing method registered: %T", sm)
}

// TestJWT_SM2_WrongToken 错误 token 拒绝。
func TestJWT_SM2_WrongToken(t *testing.T) {
	pub, _, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}

	dir := t.TempDir()
	pubPath := filepath.Join(dir, "sm2-pub.pem")
	os.WriteFile(pubPath, pub.PEM, 0o600)

	store := NewAppRoleAuthenticator()
	store.RegisterPolicy("sm2-role", "", &Policy{RoleID: "sm2-role", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}})

	authn, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "SM2",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		Audience:         []string{"test-audience"},
		RoleClaim:        "role",
	}, store)

	_, err = authn.Authenticate(context.Background(), "invalid.token.here")
	if err == nil {
		t.Fatal("should reject invalid token")
	}
	t.Logf("✅ SM2 JWT wrong token rejected: %v", err)
}

// 确保 sm2 引用。
var _ = sm2.GenerateKey
