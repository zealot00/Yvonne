package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

// === 测试辅助 ===

// generateRSAKeyPair 生成 RSA-2048 密钥对，返回公钥 PEM 文件路径。
func generateRSAKeyPair(t *testing.T) (pubKeyPath string, privateKey *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	privDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDER})
	pubKeyPath = filepath.Join(t.TempDir(), "rsa-public.pem")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return pubKeyPath, priv
}

// generateECDSAKeyPair 生成 ECDSA P-256 密钥对，返回公钥 PEM 文件路径。
func generateECDSAKeyPair(t *testing.T) (pubKeyPath string, privateKey *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDER})
	pubKeyPath = filepath.Join(t.TempDir(), "ecdsa-public.pem")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return pubKeyPath, priv
}

// signJWT 用 RSA 私钥签发 JWT。
func signRSJWT(t *testing.T, priv *rsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// signECDSAJWT 用 ECDSA 私钥签发 JWT。
func signESJWT(t *testing.T, priv *ecdsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// signHSJWT 用 HMAC secret 签发 JWT。
func signHSJWT(t *testing.T, secret []byte, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// makeClaims 构造标准 claims。
func makeClaims(roleID string, issuer string, audience []string, exp time.Time) jwt.MapClaims {
	claims := jwt.MapClaims{
		"sub": roleID,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	if len(audience) > 0 {
		claims["aud"] = audience
	}
	return claims
}

// makePolicyStore 创建带一个 role 的 PolicyStore。
func makePolicyStore(roleID string) *MemoryPolicyStore {
	store := NewMemoryPolicyStore()
	store.AddPolicy(&Policy{
		RoleID:         roleID,
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})
	return store
}

// === RS256 测试 ===

func TestJWT_RS256_ValidToken(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		Audience:         []string{"yvonne-kms"},
		RoleClaim:        "sub",
	}, store)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("order-service", "test-issuer", []string{"yvonne-kms"}, time.Now().Add(1*time.Hour)))

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q, want order-service", policy.RoleID)
	}
	if !policy.IsKeyAllowed("order-001") {
		t.Fatal("should allow order-001")
	}
}

func TestJWT_RS256_ExpiredToken(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(-1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestJWT_RS256_WrongIssuer(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "expected-issuer",
	}, store)

	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("order-service", "wrong-issuer", nil, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("wrong issuer should fail, got %v", err)
	}
}

func TestJWT_RS256_WrongAudience(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		Audience:         []string{"expected-aud"},
	}, store)

	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("order-service", "test-issuer", []string{"wrong-aud"}, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("wrong audience should fail, got %v", err)
	}
}

func TestJWT_RS256_AlgorithmConfusionAttack(t *testing.T) {
	pubKeyPath, _ := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	// 攻击者用 HMAC 算法 + 公钥内容作为 secret 签名（经典 alg 混淆攻击）。
	pubKeyBytes, _ := os.ReadFile(pubKeyPath)
	token := signHSJWT(t, pubKeyBytes, jwt.SigningMethodHS256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("algorithm confusion attack should fail, got %v", err)
	}
}

func TestJWT_RS256_AlgNoneAttack(t *testing.T) {
	pubKeyPath, _ := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	// 构造 alg:none token（jwt/v5 不直接支持，手动构造）。
	token := jwt.NewWithClaims(jwt.SigningMethodNone, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))
	signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := auth.Authenticate(context.Background(), signed)
	if err != ErrUnauthorized {
		t.Fatalf("alg:none should fail, got %v", err)
	}
}

func TestJWT_RS256_UnknownRole(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service") // 只有 order-service

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	// token 中 sub=unknown-role，PolicyStore 中无此 role。
	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("unknown-role", "test-issuer", nil, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("unknown role should fail, got %v", err)
	}
}

func TestJWT_RS256_MalformedToken(t *testing.T) {
	pubKeyPath, _ := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	_, err := auth.Authenticate(context.Background(), "not.a.valid.jwt")
	if err != ErrUnauthorized {
		t.Fatalf("malformed token should fail, got %v", err)
	}
}

func TestJWT_RS256_EmptyToken(t *testing.T) {
	pubKeyPath, _ := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	_, err := auth.Authenticate(context.Background(), "")
	if err != ErrUnauthorized {
		t.Fatalf("empty token should fail, got %v", err)
	}
}

// === ES256 测试 ===

func TestJWT_ES256_ValidToken(t *testing.T) {
	pubKeyPath, priv := generateECDSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "ES256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	token := signESJWT(t, priv, jwt.SigningMethodES256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q", policy.RoleID)
	}
}

func TestJWT_ES256_RSATokenRejected(t *testing.T) {
	ecdsaPubPath, _ := generateECDSAKeyPair(t)
	rsaPubPath, rsaPriv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "ES256",
		VerifyingKeyPath: ecdsaPubPath,
		Issuer:           "test-issuer",
	}, store)

	// 用 RSA 签名的 token，但认证器期望 ES256。
	token := signRSJWT(t, rsaPriv, jwt.SigningMethodRS256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))
	_ = rsaPubPath

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("RSA token with ES256 auth should fail, got %v", err)
	}
}

// === HMAC 测试 ===

func TestJWT_HS256_ValidToken(t *testing.T) {
	store := makePolicyStore("order-service")
	secret := []byte("test-secret-32-bytes-long-xxxxxx")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        string(secret),
		Issuer:        "test-issuer",
	}, store)

	token := signHSJWT(t, secret, jwt.SigningMethodHS256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q", policy.RoleID)
	}
}

func TestJWT_HS256_WrongSecret(t *testing.T) {
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        "correct-secret-32-bytes-long-xxxx",
		Issuer:        "test-issuer",
	}, store)

	// 用错误的 secret 签名。
	token := signHSJWT(t, []byte("wrong-secret"), jwt.SigningMethodHS256, makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("wrong secret should fail, got %v", err)
	}
}

// === Role Claim 路径测试 ===

func TestJWT_CustomRoleClaim(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("admin")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		RoleClaim:        "custom.role",
	}, store)

	claims := makeClaims("", "test-issuer", nil, time.Now().Add(1*time.Hour))
	claims["custom"] = map[string]interface{}{"role": "admin"}
	token := signRSJWT(t, priv, jwt.SigningMethodRS256, claims)

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatalf("RoleID = %q, want admin", policy.RoleID)
	}
}

func TestJWT_ArrayRoleClaim(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("admin")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		RoleClaim:        "roles",
	}, store)

	claims := makeClaims("", "test-issuer", nil, time.Now().Add(1*time.Hour))
	claims["roles"] = []interface{}{"admin", "user"}
	token := signRSJWT(t, priv, jwt.SigningMethodRS256, claims)

	policy, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatalf("RoleID = %q, want admin (first element)", policy.RoleID)
	}
}

// === 配置错误测试 ===

func TestJWT_MissingSigningMethod(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "",
	}, store)
	if err == nil {
		t.Fatal("empty signing_method should fail")
	}
}

func TestJWT_RSAMissingKeyPath(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "RS256",
	}, store)
	if err == nil {
		t.Fatal("missing verifying_key_path should fail")
	}
}

func TestJWT_HMACMissingSecret(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
	}, store)
	if err == nil {
		t.Fatal("missing secret should fail")
	}
}

func TestJWT_NilPolicyStore(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        "x",
	}, nil)
	if err == nil {
		t.Fatal("nil policy store should fail")
	}
}

func TestJWT_UnsupportedAlgorithm(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "PS256",
	}, store)
	if err == nil {
		t.Fatal("unsupported algorithm should fail")
	}
}

func TestJWT_KeyFileNotFound(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: "/nonexistent/key.pem",
	}, store)
	if err == nil {
		t.Fatal("missing key file should fail")
	}
}

// === NBF 测试 ===

func TestJWT_NotBeforeFuture(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	claims := makeClaims("order-service", "test-issuer", nil, time.Now().Add(1*time.Hour))
	claims["nbf"] = time.Now().Add(1 * time.Hour).Unix() // 未来生效
	token := signRSJWT(t, priv, jwt.SigningMethodRS256, claims)

	_, err := auth.Authenticate(context.Background(), token)
	if err != ErrUnauthorized {
		t.Fatalf("future nbf should fail, got %v", err)
	}
}

// === 多 Audience 测试 ===

func TestJWT_MultiAudienceMatch(t *testing.T) {
	pubKeyPath, priv := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
		Audience:         []string{"yvonne-kms", "audit-system"},
	}, store)

	// token 的 aud 是 yvonne-kms（配置的第二个）。
	token := signRSJWT(t, priv, jwt.SigningMethodRS256, makeClaims("order-service", "test-issuer", []string{"yvonne-kms"}, time.Now().Add(1*time.Hour)))

	_, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("multi-audience match should succeed, got %v", err)
	}
}

// === 错误模糊化测试 ===

func TestJWT_ErrorObfuscation(t *testing.T) {
	pubKeyPath, _ := generateRSAKeyPair(t)
	store := makePolicyStore("order-service")

	auth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod:    "RS256",
		VerifyingKeyPath: pubKeyPath,
		Issuer:           "test-issuer",
	}, store)

	// 各种错误场景，都应返回统一的 ErrUnauthorized。
	tokens := []string{
		"",                                     // 空
		"invalid",                              // 格式错误
		"header.payload.signature",             // 伪 JWT
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", // alg:none
	}

	for _, token := range tokens {
		_, err := auth.Authenticate(context.Background(), token)
		if err != ErrUnauthorized {
			t.Fatalf("token %q should return ErrUnauthorized, got %v", token, err)
		}
	}
}

// === 确保 ed25519 不被意外支持（未实现） ===
func TestJWT_EdDSAUnsupported(t *testing.T) {
	store := makePolicyStore("order-service")
	_, err := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "EdDSA",
	}, store)
	if err == nil {
		t.Fatal("EdDSA should not be supported yet")
	}
	_ = ed25519.Sign
}
