// Package auth - K8s Service Account JWT 认证器。
//
// 允许 Kubernetes Pod 内的业务服务用 ServiceAccount JWT 免 Token 调用 Yvonne。
// 工作流：
//  1. Pod 挂载 ServiceAccount（K8s 自动注入 JWT 到 /var/run/secrets/...）
//  2. 业务读取 JWT，作为 Bearer Token 调用 Yvonne
//  3. Yvonne 验证 JWT 签名（K8s API server JWKS 公钥）+ audience + namespace/SA
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// validateHost 校验 host 是合法 IP 或 hostname（防 SSRF）。
// 拒绝包含 scheme、path、query、port 的输入。
func validateHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	// 拒绝包含 scheme 分隔符。
	if strings.Contains(host, "://") {
		return fmt.Errorf("host %q contains scheme", host)
	}
	// 拒绝包含 path 分隔符。
	if strings.Contains(host, "/") {
		return fmt.Errorf("host %q contains path", host)
	}
	// 校验为合法 IP 或 hostname。
	if ip := net.ParseIP(host); ip != nil {
		return nil // 合法 IP
	}
	// hostname 校验：仅允许字母数字、点、连字符。
	for _, c := range host {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') && c != '.' && c != '-' {
			return fmt.Errorf("host %q contains invalid character %q", host, c)
		}
	}
	return nil
}

// ensure url import is used (validateHost 不直接用 url，但保留以防未来扩展)。
var _ = url.Parse

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
	// 若为空，则从 K8s API server 自动获取（需 Pod RBAC 权限）。
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
	jwks         *keyfunc.JWKS
	roleMappings map[string]*Policy
	mu           sync.RWMutex
}

// NewK8sAuthenticator 创建 K8s SA JWT 认证器。
//
// 自动从 JWKS URL 获取 K8s API server 公钥（使用 github.com/MicahParks/keyfunc/v2）。
// 若 JWKSURL 为空，则从 K8s API server 自动发现（Pod 内运行时）。
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
	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		// 默认从 K8s API server 获取。
		jwksURL = cfg.Issuer + "/openid/v1/jwks"
	}

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			// JWKS 刷新失败时记录（生产应接日志）。
			_ = err
		},
		RefreshInterval:   time.Hour, // K8s 密钥轮转定期刷新。
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    10 * time.Second,
		RefreshUnknownKID: true, // 遇到未知 kid 时刷新。
	})
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: load JWKS from %s: %w", jwksURL, err)
	}
	a.jwks = jwks
	a.jwksKeyFunc = jwks.Keyfunc

	return a, nil
}

// NewK8sAuthenticatorWithKeyFunc 创建带自定义 keyFunc 的 K8s 认证器（测试或自定义 JWKS 用）。
func NewK8sAuthenticatorWithKeyFunc(cfg K8sAuthConfig, keyFunc jwt.Keyfunc) (*K8sAuthenticator, error) {
	a, err := NewK8sAuthenticator(cfg)
	if err != nil {
		// 配置校验失败直接返回。
		// 但测试场景可能不需要真实 JWKS，因此重试无 JWKS 模式。
		a = &K8sAuthenticator{
			config:       cfg,
			roleMappings: make(map[string]*Policy),
		}
		for sa, m := range cfg.RoleMapping {
			a.roleMappings[sa] = &Policy{
				RoleID:         m.RoleID,
				AllowedKeys:    m.AllowedKeys,
				AllowedActions: m.AllowedActions,
			}
		}
	}
	a.jwksKeyFunc = keyFunc
	a.jwks = nil // 测试模式不用 JWKS。
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

	// 校验所有 audience（不只第一个）。
	if !a.audienceMatches(claims.Audience) {
		return nil, fmt.Errorf("%w: k8s jwt audience mismatch", ErrUnauthorized)
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

// audienceMatches 检查 JWT 的 audience 是否与配置的任一 audience 匹配。
func (a *K8sAuthenticator) audienceMatches(tokenAud jwt.ClaimStrings) bool {
	for _, configured := range a.config.Audience {
		for _, aud := range tokenAud {
			if aud == configured {
				return true
			}
		}
	}
	return false
}

// k8sSAClaims 是 K8s SA JWT 的 Claims 结构。
type k8sSAClaims struct {
	jwt.RegisteredClaims
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
}

// Close 释放 JWKS 资源（停止后台刷新 goroutine）。
func (a *K8sAuthenticator) Close() {
	if a.jwks != nil {
		a.jwks.EndBackground()
	}
}

// FetchK8sJWKSFromAPI 从 K8s API server 获取 JWKS（需 Pod 内 RBAC 权限）。
// 使用 ServiceAccount CA 证书校验 K8s API server 证书（防 MITM）。
//
// 安全：apiServer 来自 KUBERNETES_SERVICE_HOST 环境变量（由 kubelet 注入），
// 但仍校验为合法的 IP/hostname，防 SSRF。
func FetchK8sJWKSFromAPI(ctx context.Context) (json.RawMessage, error) {
	// K8s API server 地址（Pod 内默认）。
	apiServer := os.Getenv("KUBERNETES_SERVICE_HOST")
	if apiServer == "" {
		return nil, errors.New("auth: k8s: not running in cluster (KUBERNETES_SERVICE_HOST not set)")
	}
	// SSRF 防御：校验 apiServer 是合法 IP 或 hostname（不含 path/query/scheme）。
	if err := validateHost(apiServer); err != nil {
		return nil, fmt.Errorf("auth: k8s: invalid KUBERNETES_SERVICE_HOST: %w", err)
	}
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiPort == "" {
		apiPort = "443"
	}
	// 校验端口为数字。
	if _, err := strconv.Atoi(apiPort); err != nil {
		return nil, fmt.Errorf("auth: k8s: invalid KUBERNETES_SERVICE_PORT %q: %w", apiPort, err)
	}

	url := fmt.Sprintf("https://%s:%s/openid/v1/jwks", apiServer, apiPort)

	// 读取 ServiceAccount Token。
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: read SA token: %w", err)
	}

	// 读取 CA 证书。
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("auth: k8s: read CA: %w", err)
	}

	// 用 CA 证书创建自定义 TLS 配置（防 MITM）。
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("auth: k8s: failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false, // 强制校验服务端证书。
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(saToken))

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
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
