// Package auth 实现 Yvonne 的身份认证与基于资源的访问控制（RBAC/ABAC）。
//
// 设计：
//   - Policy 定义角色可访问的 Key（支持通配符）与 Action。
//   - Authenticator 接口由 AppRoleAuthenticator 实现，通过 Token 查找 Policy。
//   - Token 比对强制使用 subtle.ConstantTimeCompare 防计时侧信道。
//
// 安全红线：
//   - 凭证脱敏：绝不打印 Token 明文到日志/error/审计。
//   - 默认拒绝：无法解析 Token 或找不到 Policy 时拒绝访问。
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Policy 定义一个角色的访问控制策略。
type Policy struct {
	RoleID         string   `json:"role_id"`
	AllowedKeys    []string `json:"allowed_keys"`    // 支持通配符，如 "order-*", "*"
	AllowedActions []string `json:"allowed_actions"` // 如 ["encrypt", "decrypt", "sign"]

	// v1.3: MFA + Quorum
	RequireMFA    bool     `json:"require_mfa,omitempty"`    // 敏感操作需 TOTP 二次确认
	RequireQuorum int      `json:"require_quorum,omitempty"` // 0=不需要，N=需 N 人审批
	ApproverRoles []string `json:"approver_roles,omitempty"` // 有权审批的角色

	// v1.3.1: 多租户
	TenantID string `json:"tenant_id,omitempty"` // 租户 ID（空=非多租户模式）
}

// MFAState 存储角色的 MFA 绑定状态。
type MFAState struct {
	RoleID     string    `json:"role_id"`
	Secret     string    `json:"secret"`  // TOTP secret（base32，KEK 加密存储）
	Enabled    bool      `json:"enabled"` // 是否已启用
	CreatedAt  time.Time `json:"created_at"`
	VerifiedAt time.Time `json:"verified_at"` // 首次验证时间
}

// MFAStore 是 MFA 状态存储接口。
type MFAStore interface {
	// GetMFAState 获取角色的 MFA 状态。
	GetMFAState(roleID string) (*MFAState, error)
	// SaveMFAState 保存角色的 MFA 状态。
	SaveMFAState(state *MFAState) error
	// DeleteMFAState 删除角色的 MFA 绑定。
	DeleteMFAState(roleID string) error
}

// ErrMFANotEnabled 表示角色未启用 MFA。
var ErrMFANotEnabled = errors.New("auth: mfa not enabled for role")

// ErrMFANotRequired 表示操作不需要 MFA。
var ErrMFANotRequired = errors.New("auth: mfa not required for this operation")

// Authenticator 是身份认证接口。
type Authenticator interface {
	// Authenticate 校验 Token 并返回对应的 Policy。
	// Token 无效或找不到 Policy 时返回 error（默认拒绝）。
	Authenticate(ctx context.Context, token string) (*Policy, error)
}

// ErrUnauthorized 表示认证失败或越权。
var ErrUnauthorized = errors.New("auth: unauthorized")

// AppRoleAuthenticator 基于 AppRole Token 的静态认证器。
//
// 内部维护 token→Policy 的映射。Token 比对用 subtle.ConstantTimeCompare。
type AppRoleAuthenticator struct {
	mu       sync.RWMutex
	tokens   map[string]string  // token → roleID
	policies map[string]*Policy // roleID → Policy
}

// NewAppRoleAuthenticator 创建空认证器。
func NewAppRoleAuthenticator() *AppRoleAuthenticator {
	return &AppRoleAuthenticator{
		tokens:   make(map[string]string),
		policies: make(map[string]*Policy),
	}
}

// RegisterPolicy 注册一个角色及其 Token 与 Policy。
// 用于初始化阶段加载配置。
//
// 如果 roleID 已存在，旧 token 会被清除（覆盖注册）。
func (a *AppRoleAuthenticator) RegisterPolicy(roleID, token string, policy *Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	policy.RoleID = roleID

	// 清除该 roleID 的旧 token（如果有）。
	for oldToken, oldRole := range a.tokens {
		if oldRole == roleID {
			delete(a.tokens, oldToken)
		}
	}

	a.tokens[token] = roleID
	a.policies[roleID] = policy
}

// Authenticate 校验 Token，返回对应 Policy。
//
// 安全：
//   - Token 比对用 subtle.ConstantTimeCompare 防计时侧信道。
//   - 绝不打印 Token 明文。
//   - 找不到 Token 返回 ErrUnauthorized（默认拒绝）。
func (a *AppRoleAuthenticator) Authenticate(ctx context.Context, token string) (*Policy, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// 用 ConstantTimeCompare 逐个比对，防计时侧信道。
	// 虽然遍历 map 本身不常数时间，但每个比对是常数时间，
	// 且不因 Token 长度不同而提前退出。
	for storedToken, roleID := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			policy, ok := a.policies[roleID]
			if !ok {
				return nil, ErrUnauthorized
			}
			return policy, nil
		}
	}

	return nil, ErrUnauthorized
}

// LookupPolicy 实现 PolicyStore 接口。
// 允许 AppRoleAuthenticator 同时作为 JWT 的 PolicyStore。
func (a *AppRoleAuthenticator) LookupPolicy(roleID string) (*Policy, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p, ok := a.policies[roleID]
	if !ok {
		return nil, nil
	}
	return p, nil
}

// IsKeyAllowed 检查 keyID 是否在 Policy 允许范围内。
// 支持通配符："*" 匹配所有，"order-*" 匹配 "order-001" 等。
func (p *Policy) IsKeyAllowed(keyID string) bool {
	for _, pattern := range p.AllowedKeys {
		if matchPattern(pattern, keyID) {
			return true
		}
	}
	return false
}

// IsActionAllowed 检查 action 是否在 Policy 允许范围内。
// 支持 "*" 通配符（匹配所有 action）。
func (p *Policy) IsActionAllowed(action string) bool {
	for _, allowed := range p.AllowedActions {
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, action) {
			return true
		}
	}
	return false
}

// matchPattern 检查 keyID 是否匹配通配符 pattern。
// 支持前缀通配："order-*" 匹配 "order-001"。
// 支持全通配："*" 匹配一切。
func matchPattern(pattern, keyID string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(keyID, prefix)
	}
	return pattern == keyID
}

// ContextKey 是 context 中存储 RoleID 的键类型。
type ContextKey int

const (
	// RoleIDKey 存储 RoleID。
	RoleIDKey ContextKey = iota
	// PolicyKey 存储完整 Policy 对象（资源级授权用）。
	PolicyKey
	// TenantIDKey 存储租户 ID（多租户隔离用）。
	TenantIDKey
)

// RoleIDFromContext 从 context 提取 RoleID。
func RoleIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RoleIDKey).(string); ok {
		return v
	}
	return ""
}

// WithRoleID 将 RoleID 注入 context。
func WithRoleID(ctx context.Context, roleID string) context.Context {
	return context.WithValue(ctx, RoleIDKey, roleID)
}

// PolicyFromContext 从 context 提取完整 Policy 对象。
// 用于 handler 内部做 body.KeyID 资源级授权校验。
func PolicyFromContext(ctx context.Context) *Policy {
	if v, ok := ctx.Value(PolicyKey).(*Policy); ok {
		return v
	}
	return nil
}

// WithPolicy 将完整 Policy 注入 context。
func WithPolicy(ctx context.Context, policy *Policy) context.Context {
	return context.WithValue(ctx, PolicyKey, policy)
}

// TenantFromContext 从 context 提取 TenantID（多租户隔离用）。
func TenantFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(TenantIDKey).(string); ok {
		return v
	}
	return ""
}

// WithTenant 将 TenantID 注入 context。
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// ScopedKeyID 返回带租户前缀的 keyID（多租户模式）。
// 非多租户模式（tenantID 为空）直接返回原 keyID。
func ScopedKeyID(tenantID, keyID string) string {
	if tenantID == "" {
		return keyID
	}
	return tenantID + ":" + keyID
}

// UnscopedKeyID 从带租户前缀的 keyID 中提取原始 keyID。
func UnscopedKeyID(tenantID, scopedKeyID string) string {
	if tenantID == "" {
		return scopedKeyID
	}
	prefix := tenantID + ":"
	if len(scopedKeyID) > len(prefix) && scopedKeyID[:len(prefix)] == prefix {
		return scopedKeyID[len(prefix):]
	}
	return scopedKeyID
}

// ExtractBearerToken 从 Authorization header 提取 Bearer token。
// 格式：Authorization: Bearer <token>
// 绝不打印 token 明文。
func ExtractBearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", fmt.Errorf("auth: missing or invalid Authorization header")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", fmt.Errorf("auth: empty bearer token")
	}
	return token, nil
}
