package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateRSAKeyForRoleTest 生成 RSA 密钥对 + 公钥 PEM 文件。
func generateRSAKeyForRoleTest(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "role-test-pub.pem")
	os.WriteFile(path, pubPEM, 0o600)
	return priv, path
}

// signJWTForRoleTest 签发测试 JWT。
func signJWTForRoleTest(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// TestJWT_MultiRoleArrayClaim 验证数组角色 claim 提取全部角色。
// 修复前：只取 v[0]（"user"），"admin" 被忽略。
// 修复后：extractRoleIDs 返回全部角色，Authenticate 遍历查找匹配。
func TestJWT_MultiRoleArrayClaim(t *testing.T) {
	priv, pubPath := generateRSAKeyForRoleTest(t)

	store := NewMemoryPolicyStore()
	// 注册 user（权限少）和 admin（权限多）。
	store.AddPolicy(&Policy{
		RoleID:         "user",
		AllowedKeys:    []string{"user-*"},
		AllowedActions: []string{"Encrypt"},
	})
	store.AddPolicy(&Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey"},
	})

	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		RoleClaim:        "roles",
	}, store)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	// JWT 中 roles = ["user", "admin"]。
	// 修复前：只取 "user"（v[0]），权限受限。
	// 修复后：遍历 ["user", "admin"]，"user" 先匹配 → 返回 user Policy。
	// 但如果 user 未注册，会继续找 admin。
	token := signJWTForRoleTest(t, priv, jwt.MapClaims{
		"roles": []string{"user", "admin"},
		"iss":   "test-issuer",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// "user" 在 store 中，先匹配。
	if policy.RoleID != "user" {
		t.Fatalf("RoleID = %q, want user (first match)", policy.RoleID)
	}
}

// TestJWT_MultiRole_FirstUnregistered 验证第一个角色未注册时回退到第二个。
func TestJWT_MultiRole_FirstUnregistered(t *testing.T) {
	priv, pubPath := generateRSAKeyForRoleTest(t)

	store := NewMemoryPolicyStore()
	// 只注册 admin，不注册 guest。
	store.AddPolicy(&Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		RoleClaim:        "roles",
	}, store)

	// roles = ["guest", "admin"]，guest 未注册 → 应回退到 admin。
	token := signJWTForRoleTest(t, priv, jwt.MapClaims{
		"roles": []string{"guest", "admin"},
		"iss":   "test-issuer",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatalf("RoleID = %q, want admin (fallback)", policy.RoleID)
	}
}

// TestJWT_MultiRole_NoneRegistered 全部角色未注册 → ErrUnauthorized。
func TestJWT_MultiRole_NoneRegistered(t *testing.T) {
	priv, pubPath := generateRSAKeyForRoleTest(t)

	store := NewMemoryPolicyStore() // 空 store

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		RoleClaim:        "roles",
	}, store)

	token := signJWTForRoleTest(t, priv, jwt.MapClaims{
		"roles": []string{"guest", "visitor"},
		"iss":   "test-issuer",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestJWT_SingleStringRole 验证单个字符串角色仍正常。
func TestJWT_SingleStringRole(t *testing.T) {
	priv, pubPath := generateRSAKeyForRoleTest(t)

	store := NewMemoryPolicyStore()
	store.AddPolicy(&Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	})

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubPath,
		Issuer:           "test-issuer",
		RoleClaim:        "sub",
	}, store)

	token := signJWTForRoleTest(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q", policy.RoleID)
	}
}

// TestExtractRoleIDs_ArrayReturnsAll 验证 extractRoleIDs 返回全部数组元素。
func TestExtractRoleIDs_ArrayReturnsAll(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"admin", "user", "guest"},
	}

	roles := extractRoleIDs(claims, "roles")
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d: %v", len(roles), roles)
	}
	if roles[0] != "admin" || roles[1] != "user" || roles[2] != "guest" {
		t.Fatalf("roles = %v, want [admin user guest]", roles)
	}
}

// TestExtractRoleIDs_StringReturnsSingle 验证字符串返回单元素。
func TestExtractRoleIDs_StringReturnsSingle(t *testing.T) {
	claims := jwt.MapClaims{
		"sub": "order-service",
	}

	roles := extractRoleIDs(claims, "sub")
	if len(roles) != 1 || roles[0] != "order-service" {
		t.Fatalf("roles = %v, want [order-service]", roles)
	}
}

// TestExtractRoleIDs_EmptyArray 验证空数组返回 nil。
func TestExtractRoleIDs_EmptyArray(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{},
	}

	roles := extractRoleIDs(claims, "roles")
	if len(roles) != 0 {
		t.Fatalf("expected 0 roles, got %d", len(roles))
	}
}

// TestExtractRoleIDs_NestedPath 验证嵌套路径。
func TestExtractRoleIDs_NestedPath(t *testing.T) {
	claims := jwt.MapClaims{
		"custom": map[string]interface{}{
			"roles": []interface{}{"admin", "auditor"},
		},
	}

	roles := extractRoleIDs(claims, "custom.roles")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}
