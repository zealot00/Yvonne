// Package auth - JWT 认证器。
//
// 通用的 JWT 验证器，支持：
//   - 算法：RS256/384/512、ES256/384/512、HS256/384/512
//   - 非对称验签：RSA/ECDSA 公钥 PEM 文件
//   - 对称验签：HMAC secret
//   - 标准 Claims：exp、nbf、iss、aud
//   - 可配置的 RoleID claim 字段（支持嵌套点号路径）
//   - 防范 alg: none 和算法混淆攻击
//
// 安全红线：
//   - 启动时预加载验签密钥，绝不每次请求读文件
//   - 算法严格匹配：配置 RSA 则拒绝 HMAC 签名的 token
//   - 绝不返回具体解析错误给 API 层（防侧信道）
//   - 默认拒绝：任何校验失败返回统一 "Invalid Token"
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// PolicyStore 是通用的角色 → Policy 查找接口。
// AppRoleAuthenticator 和 JWTAuthenticator 共用此接口。
// 实现：内存 map、数据库、配置文件加载等。
type PolicyStore interface {
	// LookupPolicy 根据 RoleID 查找对应的 Policy。
	// 找不到返回 nil（调用方默认拒绝）。
	LookupPolicy(roleID string) (*Policy, error)
}

// MemoryPolicyStore 是基于内存 map 的 PolicyStore 实现。
type MemoryPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewMemoryPolicyStore 创建空的内存 PolicyStore。
func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{policies: make(map[string]*Policy)}
}

// AddPolicy 注册一个角色的 Policy（线程安全）。
func (m *MemoryPolicyStore) AddPolicy(policy *Policy) {
	if policy != nil && policy.RoleID != "" {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.policies[policy.RoleID] = policy
	}
}

// LookupPolicy 查找角色的 Policy（线程安全）。
func (m *MemoryPolicyStore) LookupPolicy(roleID string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[roleID]
	if !ok {
		return nil, nil
	}
	return p, nil
}

// JWTConfig 是 JWT 认证器的配置（与 config.JWTConfig 对齐，避免循环依赖）。
type JWTConfig struct {
	SigningMethod    string
	Secret           string
	VerifyingKeyPath string
	Issuer           string
	Audience         []string
	RoleClaim        string
}

// JWTAuthenticator 是基于 JWT 的认证器。
//
// 启动时预加载验签密钥，每次请求仅做内存中的验签。
type JWTAuthenticator struct {
	signingMethod jwt.SigningMethod
	verifyKey     interface{} // *rsa.PublicKey | *ecdsa.PublicKey | []byte (HMAC)
	issuer        string
	audience      []string
	roleClaim     string
	policyStore   PolicyStore
}

// NewJWTAuthenticator 创建 JWT 认证器。
//
// 启动时预加载验签密钥（公钥 PEM 或 HMAC secret），绝不每次请求读文件。
// 配置错误时返回 error，拒绝启动。
func NewJWTAuthenticator(cfg JWTConfig, policyStore PolicyStore) (*JWTAuthenticator, error) {
	if cfg.SigningMethod == "" {
		return nil, errors.New("auth: jwt signing_method is required")
	}
	if policyStore == nil {
		return nil, errors.New("auth: jwt policy store is nil")
	}

	// 1. 解析算法。
	sm, err := parseSigningMethod(cfg.SigningMethod)
	if err != nil {
		return nil, fmt.Errorf("auth: jwt: %w", err)
	}

	// 2. 预加载验签密钥。
	var verifyKey interface{}
	switch cfg.SigningMethod[:2] {
	case "RS":
		if cfg.VerifyingKeyPath == "" {
			return nil, errors.New("auth: jwt: verifying_key_path required for RSA")
		}
		pub, err := loadRSAPublicKey(cfg.VerifyingKeyPath)
		if err != nil {
			return nil, fmt.Errorf("auth: jwt: load RSA public key: %w", err)
		}
		verifyKey = pub
	case "ES":
		if cfg.VerifyingKeyPath == "" {
			return nil, errors.New("auth: jwt: verifying_key_path required for ECDSA")
		}
		pub, err := loadECDSAPublicKey(cfg.VerifyingKeyPath)
		if err != nil {
			return nil, fmt.Errorf("auth: jwt: load ECDSA public key: %w", err)
		}
		verifyKey = pub
	case "HS":
		if cfg.Secret == "" {
			return nil, errors.New("auth: jwt: secret required for HMAC")
		}
		verifyKey = []byte(cfg.Secret)
	default:
		return nil, fmt.Errorf("auth: jwt: unsupported algorithm family %q", cfg.SigningMethod[:2])
	}

	// 3. RoleClaim 默认 sub。
	roleClaim := cfg.RoleClaim
	if roleClaim == "" {
		roleClaim = "sub"
	}

	return &JWTAuthenticator{
		signingMethod: sm,
		verifyKey:     verifyKey,
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		roleClaim:     roleClaim,
		policyStore:   policyStore,
	}, nil
}

// Authenticate 验证 JWT Token 并返回对应的 Policy。
//
// 安全红线：
//   - 错误信息模糊化：所有失败返回统一的 ErrUnauthorized。
//   - 详细错误不通过返回值泄露（调用方可写日志）。
//   - 强制算法匹配，拒绝 alg:none 和算法混淆。
func (a *JWTAuthenticator) Authenticate(ctx context.Context, tokenString string) (*Policy, error) {
	// 1. 解析 Token（不验签，先获取 header）。
	parser := jwt.NewParser(jwt.WithValidMethods([]string{a.signingMethod.Alg()}))

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 2. 强制算法匹配：parser.WithValidMethods 已拦截 alg:none 和算法混淆。
		//    这里再做一次防御性检查。
		if token.Method.Alg() != a.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return a.verifyKey, nil
	})

	if err != nil || token == nil {
		// 错误模糊化：不区分 expired/invalid signature/malformed。
		return nil, ErrUnauthorized
	}

	// 3. 校验标准 Claims。
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrUnauthorized
	}

	// exp 校验（jwt/v5 默认校验 exp，但防御性再确认）。
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, ErrUnauthorized
	}

	// nbf 校验。
	nbf, err := claims.GetNotBefore()
	if err != nil {
		return nil, ErrUnauthorized
	}
	_ = nbf // jwt/v5 默认校验 nbf

	// iss 校验。
	if a.issuer != "" {
		iss, err := claims.GetIssuer()
		if err != nil || iss != a.issuer {
			return nil, ErrUnauthorized
		}
	}

	// aud 校验（配置了才校验，支持多 audience）。
	if len(a.audience) > 0 {
		aud, err := claims.GetAudience()
		if err != nil {
			return nil, ErrUnauthorized
		}
		if !matchAudience(aud, a.audience) {
			return nil, ErrUnauthorized
		}
	}

	// 4. 从 Claims 提取 RoleID。
	roleID := extractRoleID(claims, a.roleClaim)
	if roleID == "" {
		return nil, ErrUnauthorized
	}

	// 5. 从 PolicyStore 查找 Policy。
	policy, err := a.policyStore.LookupPolicy(roleID)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if policy == nil {
		// 角色未注册 → 默认拒绝。
		return nil, ErrUnauthorized
	}

	return policy, nil
}

// parseSigningMethod 将算法字符串转为 jwt.SigningMethod。
func parseSigningMethod(method string) (jwt.SigningMethod, error) {
	switch method {
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "RS384":
		return jwt.SigningMethodRS384, nil
	case "RS512":
		return jwt.SigningMethodRS512, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "ES384":
		return jwt.SigningMethodES384, nil
	case "ES512":
		return jwt.SigningMethodES512, nil
	case "HS256":
		return jwt.SigningMethodHS256, nil
	case "HS384":
		return jwt.SigningMethodHS384, nil
	case "HS512":
		return jwt.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", method)
	}
}

// loadRSAPublicKey 从 PEM 文件加载 RSA 公钥。
// 支持 PKIX DER 和 PKCS#1 DER。
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	// 尝试 PKIX（SubjectPublicKeyInfo）。
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return rsaPub, nil
	}

	// 尝试 PKCS#1。
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX/PKCS1: %w", err)
	}
	return rsaPub, nil
}

// loadECDSAPublicKey 从 PEM 文件加载 ECDSA 公钥。
func loadECDSAPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return ecdsaPub, nil
}

// matchAudience 检查 token 的 audience 是否与配置的任一 audience 匹配。
func matchAudience(tokenAud []string, configAud []string) bool {
	for _, t := range tokenAud {
		for _, c := range configAud {
			if t == c {
				return true
			}
		}
	}
	return false
}

// extractRoleID 从 JWT Claims 中提取 RoleID。
//
// 支持嵌套点号路径（如 "custom.role"）。
// 支持数组取第一个元素（如 roles: ["admin","user"] → "admin"）。
func extractRoleID(claims jwt.MapClaims, path string) string {
	parts := strings.Split(path, ".")
	var current interface{} = claims

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case jwt.MapClaims:
			current = v[part]
		default:
			return ""
		}
		if current == nil {
			return ""
		}
	}

	// 最终值转为 string。
	switch v := current.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
		return ""
	case float64:
		return fmt.Sprintf("%v", v)
	default:
		return ""
	}
}
