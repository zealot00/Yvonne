//go:build integration

// JWT 越权攻击集成测试。
//
// 验证 Phase 1 资源级授权：
//   - 普通服务 Token 不能创建 Key（无 CreateKey action）
//   - 普通服务 Token 不能解密未授权 Key（资源越权）
//   - 普通服务 Token 不能查询审计日志（无 AuditQuery action）
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// generateRSAPrivKey 生成 RSA 私钥并写入临时文件，返回私钥 + 公钥 PEM 路径。
func generateRSAPrivKey(t *testing.T) (privKey *rsa.PrivateKey, pubKeyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pubKeyPath = filepath.Join(t.TempDir(), "jwt-pub.pem")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}
	return priv, pubKeyPath
}

// signTestJWT 用 RSA 私钥签发测试 JWT。
func signTestJWT(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// newJWTAuthRouter 创建带 JWT 认证的完整 V1Router。
func newJWTAuthRouter(t *testing.T) (*V1Router, *lifecycle.Manager, *memguard.SecureBuffer, *rsa.PrivateKey, string) {
	t.Helper()

	masterKey, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(masterKey.Wipe)

	vault := seal.NewVaultState(5, 3, 0)
	if err := vault.DirectUnseal(masterKey); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	var auditBuf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(logger.Close)

	reg := metrics.NewRegistry()

	// JWT 认证器。
	priv, pubKeyPath := generateRSAPrivKey(t)
	policyStore := auth.NewMemoryPolicyStore()

	// 注册 order-service 角色：只能加解密 order-key。
	policyStore.AddPolicy(&auth.Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-key"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		Audience:         []string{"yvonne-kms"},
		RoleClaim:        "sub",
	}, policyStore)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	r := NewV1Router(vault, logger, mgr, reg, jwtAuth)
	return r, mgr, masterKey, priv, "order-service"
}

// === JWT 越权攻击测试 ===

// TestJWT_Attack_CreateKeyForbidden 普通服务 Token 尝试创建 Key → 403。
func TestJWT_Attack_CreateKeyForbidden(t *testing.T) {
	r, mgr, mk, priv, _ := newJWTAuthRouter(t)

	// 签发 Token：order-service 角色（无 CreateKey action）。
	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	// 先创建 order-key（用 manager 直接创建，模拟管理员操作）。
	mgr.CreateKey(context.Background(), "order-key", seal.NewSoftwareKEK(mk), 0)

	// 攻击：用 order-service Token 尝试创建新 Key。
	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys", token, map[string]interface{}{
		"key_id": "malicious-key",
	})
	if code != http.StatusForbidden {
		t.Fatalf("CreateKey with non-admin token: got %d, want 403", code)
	}
}

// TestJWT_Attack_DecryptUnauthorizedKey 普通服务 Token 尝试解密 user-key → 403。
func TestJWT_Attack_DecryptUnauthorizedKey(t *testing.T) {
	r, mgr, mk, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	// 创建 order-key 和 user-key。
	mgr.CreateKey(context.Background(), "order-key", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(context.Background(), "user-key", seal.NewSoftwareKEK(mk), 0)

	// 用 user-key 加密数据（模拟 user-service 的操作）。
	// 直接用 manager 获取 user-key 的 DEK 并加密。
	userMeta, _ := mgr.GetActiveKey(context.Background(), "user-key")
	kek := seal.NewSoftwareKEK(mk)
	storedDEK, _ := kek.UnwrapDEK(userMeta.EncryptedMaterial)
	defer storedDEK.Wipe()
	ciphertext, _ := crypto.EncryptVersioned(storedDEK, uint32(userMeta.Version), []byte("user secret"))
	ctB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// 攻击：用 order-service Token 尝试解密 user-key 的密文。
	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", token, map[string]interface{}{
		"key_id":     "user-key",
		"ciphertext": ctB64,
	})
	if code != http.StatusForbidden {
		t.Fatalf("decrypt unauthorized key: got %d, want 403", code)
	}
}

// TestJWT_Attack_AuditQueryForbidden 普通服务 Token 尝试查询审计 → 403。
func TestJWT_Attack_AuditQueryForbidden(t *testing.T) {
	r, _, _, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/audit/query", token, map[string]interface{}{
		"limit": 10,
	})
	if code != http.StatusForbidden {
		t.Fatalf("audit query with non-admin token: got %d, want 403", code)
	}
}

// TestJWT_Attack_ExpiredToken 过期 Token → 401。
func TestJWT_Attack_ExpiredToken(t *testing.T) {
	r, _, _, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // 过期
	})

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", token, map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("expired token: got %d, want 401", code)
	}
}

// TestJWT_Attack_AlgNone 无签名 Token → 401。
func TestJWT_Attack_AlgNone(t *testing.T) {
	r, _, _, _, _ := newJWTAuthRouter(t)

	// 构造 alg:none Token。
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", signed, map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("alg:none token: got %d, want 401", code)
	}
}

// TestJWT_Attack_WrongIssuer 错误 Issuer → 401。
func TestJWT_Attack_WrongIssuer(t *testing.T) {
	r, _, _, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "wrong-issuer", // 错误
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", token, map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong issuer: got %d, want 401", code)
	}
}

// TestJWT_Attack_ForgedRole 伪造 admin 角色 → 401（PolicyStore 无此角色）。
func TestJWT_Attack_ForgedRole(t *testing.T) {
	r, _, _, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "fake-admin", // PolicyStore 中无此角色
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys", token, map[string]interface{}{
		"key_id": "forged-key",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("forged role: got %d, want 401", code)
	}
}

// TestJWT_Attack_NoToken 无 Token → 401。
func TestJWT_Attack_NoToken(t *testing.T) {
	r, _, _, _, _ := newJWTAuthRouter(t)

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "", map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", code)
	}
}

// TestJWT_LegitEncrypt 普通服务 Token 加密授权 Key → 200（正常流验证）。
func TestJWT_LegitEncrypt(t *testing.T) {
	r, mgr, mk, priv, _ := newJWTAuthRouter(t)

	token := signTestJWT(t, priv, jwt.MapClaims{
		"sub": "order-service",
		"iss": "test-issuer",
		"aud": []string{"yvonne-kms"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	mgr.CreateKey(context.Background(), "order-key", seal.NewSoftwareKEK(mk), 0)

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", token, map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusOK {
		t.Fatalf("legit encrypt: got %d, want 200", code)
	}
}
