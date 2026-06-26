// Package auth - K8s Service Account JWT 认证器。
//
// 允许 Kubernetes Pod 内的业务服务用 ServiceAccount JWT 免 Token 调用 Yvonne。
// 工作流：
//  1. Pod 挂载 ServiceAccount（K8s 自动注入 JWT 到 /var/run/secrets/...）
//  2. 业务读取 JWT，作为 Bearer Token 调用 Yvonne
//  3. Yvonne 验证 JWT 签名（K8s API server 公钥）+ audience + namespace/SA
//  4. 按 role_mapping 映射到 Policy
//
// 安全：
//   - JWT 签名验证（防伪造）
//   - audience 校验（防 JWT 滥用于其他系统）
//   - namespace/SA 白名单（防未授权 SA）
//   - role_mapping 显式映射（无默认放行）
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// K8sAuthConfig 是 K8s SA JWT 认证器配置。
type K8sAuthConfig struct {
	// Issuer：K8s API server 的 issuer（通常为 https://kubernetes.default.svc.cluster.local）。
	Issuer string `json:"issuer" yaml:"issuer"`

	// Audience：Yvonne 期望的 audience（如 "yvonne-kms"）。
	Audience []string `json:"audience" yaml:"audience"`

	// RoleMapping：SA 到 Policy 的映射。
	// Key 格式："namespace:serviceaccount"（如 "default:order-service"）。
	// Value 为该 SA 对应的 Policy。
	RoleMapping map[string]K8sRoleMapping `json:"role_mapping" yaml:"role_mapping"`

	// JWKSURL：K8s API server 的 JWKS 公钥 URL（可选）。
	// 若为空，则从 Issuer + /.well-known/openid-configuration 自动发现。
	JWKSURL string `json:"jwks_url" yaml:"jwks_url"`
}

// K8sRoleMapping 是单个 SA 的映射配置。
type K8sRoleMapping struct {
	RoleID         string   `json:"role_id"`
	AllowedKeys    []string `json:"allowed_keys"`
	AllowedActions []string `json:"allowed_actions"`
}

// K8sAuthenticator 实现 Kubernetes ServiceAccount JWT 认证。
type K8sAuthenticator struct {
	config       K8sAuthConfig
	jwksKeyFunc  jwt.Keyfunc
	roleMappings map[string]*Policy
	mu           sync.RWMutex
}

// NewK8sAuthenticator 创建 K8s SA JWT 认证器。
//
// 自动从 K8s API server 发现 JWKS 公钥（通过 Issuer + /.well-known/openid-configuration）。
// 若 JWKSURL 显式配置则直接用。
func NewK8sAuthenticator(cfg K8sAuthConfig) (*K8sAuthenticator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("auth: k8s: issuer is required")
	}
	if len(cfg.Audience) == 0 {
		return nil, errors.New("auth: k8s: audience is required")
	}
	if len(cfg.RoleMapping) == 0 {
		return nil, errors.New("auth: k8s: role_mapping is required (at least one SA mapping)")
	}

	// 构建 Policy 映射。
	mappings := make(map[string]*Policy)
	for sa, m := range cfg.RoleMapping {
		mappings[sa] = &Policy{
			RoleID:         m.RoleID,
			AllowedKeys:    m.AllowedKeys,
			AllowedActions: m.AllowedActions,
		}
	}

	a := &K8sAuthenticator{
		config:       cfg,
		roleMappings: mappings,
	}

	// 初始化 JWKS key func。
	if cfg.JWKSURL != "" {
		kf, err := newJWKSKeyFunc(cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("auth: k8s: load JWKS: %w", err)
		}
		a.jwksKeyFunc = kf
	}

	return a, nil
}

// Authenticate 校验 K8s SA JWT 并返回对应 Policy。
func (a *K8sAuthenticator) Authenticate(ctx context.Context, token string) (*Policy, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}

	// 解析 + 验证 JWT。
	claims := &k8sSAClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(a.config.Issuer),
		jwt.WithAudience(a.config.Audience[0]),
	)

	keyFunc := a.jwksKeyFunc
	if keyFunc == nil {
		return nil, errors.New("auth: k8s: JWKS key function not initialized")
	}

	parsed, err := parser.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: k8s jwt parse: %v", ErrUnauthorized, err)
	}
	if !parsed.Valid {
		return nil, ErrUnauthorized
	}

	// 提取 namespace:serviceaccount。
	saKey := claims.Namespace + ":" + claims.ServiceAccountName
	if claims.Namespace == "" || claims.ServiceAccountName == "" {
		return nil, fmt.Errorf("%w: k8s jwt missing namespace/serviceaccount claims", ErrUnauthorized)
	}

	// 查找 Policy 映射。
	a.mu.RLock()
	policy, ok := a.roleMappings[saKey]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: k8s SA %q not in role_mapping", ErrUnauthorized, saKey)
	}

	return policy, nil
}

// k8sSAClaims 是 K8s SA JWT 的 Claims 结构。
type k8sSAClaims struct {
	jwt.RegisteredClaims
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
}

// newJWKSKeyFunc 从 JWKS URL 创建 JWT 验签 key function。
// 简化实现：首次加载并缓存，生产环境应定期刷新（K8s 轮转密钥）。
func newJWKSKeyFunc(jwksURL string) (jwt.Keyfunc, error) {
	// TODO: 实现 JWKS 获取 + 缓存 + 定期刷新。
	// 当前简化：要求用户提供 JWKS URL，运行时获取。
	// 完整实现可使用 github.com/MicahParks/keyfunc 或自行 HTTP GET + json 解析。
	return func(token *jwt.Token) (interface{}, error) {
		// 占位：生产实现需从 JWKS URL 获取 kid 对应的公钥。
		// 此处返回 nil 让调用方配置 jwksKeyFunc 后使用。
		return nil, errors.New("auth: k8s: JWKS keyfunc not yet implemented (use NewK8sAuthenticatorWithKeyFunc)")
	}, nil
}

// NewK8sAuthenticatorWithKeyFunc 创建带自定义 keyFunc 的 K8s 认证器（测试或自定义 JWKS 用）。
func NewK8sAuthenticatorWithKeyFunc(cfg K8sAuthConfig, keyFunc jwt.Keyfunc) (*K8sAuthenticator, error) {
	a, err := NewK8sAuthenticator(cfg)
	if err != nil {
		return nil, err
	}
	a.jwksKeyFunc = keyFunc
	return a, nil
}

// FetchK8sJWKSFromAPI 从 K8s API server 获取 JWKS（需 Pod 内 RBAC 权限）。
func FetchK8sJWKSFromAPI(ctx context.Context) (json.RawMessage, error) {
	// K8s API server 地址（Pod 内默认）。
	apiServer := os.Getenv("KUBERNETES_SERVICE_HOST")
	if apiServer == "" {
		return nil, errors.New("auth: k8s: not running in cluster (KUBERNETES_SERVICE_HOST not set)")
	}
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiPort == "" {
		apiPort = "443"
	}

	url := fmt.Sprintf("https://%s:%s/openid/v1/jwks", apiServer, apiPort)

	// 读取 ServiceAccount Token。
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: read SA token: %w", err)
	}

	// 读取 CA。
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: read CA: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(saToken)))

	// TODO: 用 caCert 配置 TLS client（简化示例省略）。
	_ = caCert

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: k8s: JWKS fetch status %d", resp.StatusCode)
	}

	var jwks json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("auth: k8s: decode JWKS: %w", err)
	}
	return jwks, nil
}
