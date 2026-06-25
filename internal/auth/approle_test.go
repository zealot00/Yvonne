package auth

import (
	"context"
	"strings"
	"testing"
)

// === 有效 Token 认证 ===

func TestAppRole_AuthenticateValidToken(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("order-service", "order-token-xxx", &Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	policy, err := auth.Authenticate(context.Background(), "order-token-xxx")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy == nil {
		t.Fatal("policy should not be nil")
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q, want order-service", policy.RoleID)
	}
	if !policy.IsKeyAllowed("order-001") {
		t.Fatal("should allow order-001")
	}
	if !policy.IsActionAllowed("Encrypt") {
		t.Fatal("should allow Encrypt")
	}
}

// === 空 Token ===

func TestAppRole_AuthenticateEmptyToken(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role", "token", &Policy{RoleID: "role"})

	_, err := auth.Authenticate(context.Background(), "")
	if err != ErrUnauthorized {
		t.Fatalf("empty token should return ErrUnauthorized, got %v", err)
	}
}

// === 无效 Token ===

func TestAppRole_AuthenticateInvalidToken(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("order-service", "order-token-xxx", &Policy{RoleID: "order-service"})

	_, err := auth.Authenticate(context.Background(), "invalid-token")
	if err != ErrUnauthorized {
		t.Fatalf("invalid token should return ErrUnauthorized, got %v", err)
	}
}

// === Token 长度不同（防计时侧信道） ===

func TestAppRole_DifferentTokenLengths(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role-a", "short", &Policy{RoleID: "role-a"})
	auth.RegisterPolicy("role-b", "this-is-a-much-longer-token-value", &Policy{RoleID: "role-b"})

	// 两个不同长度的无效 token 都应返回 ErrUnauthorized。
	for _, token := range []string{"nope", "this-is-a-really-long-invalid-token-string"} {
		_, err := auth.Authenticate(context.Background(), token)
		if err != ErrUnauthorized {
			t.Fatalf("token %q should return ErrUnauthorized, got %v", token, err)
		}
	}

	// 有效 token 仍能认证。
	policy, err := auth.Authenticate(context.Background(), "short")
	if err != nil || policy == nil {
		t.Fatalf("valid short token should authenticate: err=%v", err)
	}
}

// === 多角色共存 ===

func TestAppRole_MultipleRoles(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("order-service", "order-token", &Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	})
	auth.RegisterPolicy("user-service", "user-token", &Policy{
		RoleID:         "user-service",
		AllowedKeys:    []string{"user-*"},
		AllowedActions: []string{"Decrypt"},
	})
	auth.RegisterPolicy("admin", "admin-token", &Policy{
		RoleID:         "admin",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp", "AuditQuery"},
	})

	// 每个 token 返回正确的 Policy。
	cases := []struct {
		token         string
		expectedRole  string
		expectedKey   string
		allowedKey    string
		forbiddenKey  string
		allowedAction string
	}{
		{"order-token", "order-service", "order-*", "order-001", "user-001", "Encrypt"},
		{"user-token", "user-service", "user-*", "user-001", "order-001", "Decrypt"},
		{"admin-token", "admin", "*", "anything", "", "AuditQuery"},
	}

	for _, tc := range cases {
		policy, err := auth.Authenticate(context.Background(), tc.token)
		if err != nil {
			t.Fatalf("token %q: Authenticate: %v", tc.token, err)
		}
		if policy.RoleID != tc.expectedRole {
			t.Fatalf("token %q: RoleID = %q, want %q", tc.token, policy.RoleID, tc.expectedRole)
		}
		if !policy.IsKeyAllowed(tc.allowedKey) {
			t.Fatalf("token %q: should allow key %q", tc.token, tc.allowedKey)
		}
		if tc.forbiddenKey != "" && policy.IsKeyAllowed(tc.forbiddenKey) {
			t.Fatalf("token %q: should NOT allow key %q", tc.token, tc.forbiddenKey)
		}
		if !policy.IsActionAllowed(tc.allowedAction) {
			t.Fatalf("token %q: should allow action %q", tc.token, tc.allowedAction)
		}
	}
}

// === Token 相似但不同 ===

func TestAppRole_SimilarTokensNotConfused(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role-a", "token-abc-123", &Policy{RoleID: "role-a", AllowedKeys: []string{"a-*"}})
	auth.RegisterPolicy("role-b", "token-abc-124", &Policy{RoleID: "role-b", AllowedKeys: []string{"b-*"}})

	// 相似但不同的 token 不应混淆。
	policy, err := auth.Authenticate(context.Background(), "token-abc-123")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "role-a" {
		t.Fatalf("RoleID = %q, want role-a", policy.RoleID)
	}
	if policy.IsKeyAllowed("b-001") {
		t.Fatal("role-a should not allow b-* keys")
	}

	policy2, err := auth.Authenticate(context.Background(), "token-abc-124")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy2.RoleID != "role-b" {
		t.Fatalf("RoleID = %q, want role-b", policy2.RoleID)
	}
}

// === 重复注册覆盖 ===

func TestAppRole_DuplicateRegistrationOverwrites(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role-a", "token-v1", &Policy{
		RoleID:         "role-a",
		AllowedKeys:    []string{"key-v1"},
		AllowedActions: []string{"Encrypt"},
	})

	// 覆盖注册。
	auth.RegisterPolicy("role-a", "token-v2", &Policy{
		RoleID:         "role-a",
		AllowedKeys:    []string{"key-v2"},
		AllowedActions: []string{"Decrypt"},
	})

	// 旧 token 应失效（被覆盖）。
	_, err := auth.Authenticate(context.Background(), "token-v1")
	if err != ErrUnauthorized {
		t.Fatalf("old token should be invalidated after re-register, got %v", err)
	}

	// 新 token 应有效。
	policy, err := auth.Authenticate(context.Background(), "token-v2")
	if err != nil {
		t.Fatalf("new token should work: %v", err)
	}
	if !policy.IsKeyAllowed("key-v2") {
		t.Fatal("should allow key-v2")
	}
	if policy.IsKeyAllowed("key-v1") {
		t.Fatal("old key should not be allowed")
	}
	if !policy.IsActionAllowed("Decrypt") {
		t.Fatal("should allow Decrypt")
	}
	if policy.IsActionAllowed("Encrypt") {
		t.Fatal("old action should not be allowed")
	}
}

// === 同一 Token 注册到不同 Role ===

func TestAppRole_SameTokenDifferentRole(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	// 用同一 token 注册两个 role（后者覆盖前者）。
	auth.RegisterPolicy("role-a", "shared-token", &Policy{RoleID: "role-a"})
	auth.RegisterPolicy("role-b", "shared-token", &Policy{RoleID: "role-b"})

	// map 中 token→roleID 只能有一个值（后注册的覆盖）。
	policy, err := auth.Authenticate(context.Background(), "shared-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// 后注册的 role-b 应生效。
	if policy.RoleID != "role-b" {
		t.Fatalf("RoleID = %q, want role-b (last registered)", policy.RoleID)
	}
}

// === Policy nil 安全 ===

func TestAppRole_NilPolicyFields(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	// 注册一个 AllowedKeys 和 AllowedActions 都为空的 Policy。
	auth.RegisterPolicy("empty-role", "empty-token", &Policy{
		RoleID: "empty-role",
	})

	policy, err := auth.Authenticate(context.Background(), "empty-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// 空 Policy 应拒绝所有 key 和 action。
	if policy.IsKeyAllowed("any-key") {
		t.Fatal("empty AllowedKeys should deny all keys")
	}
	if policy.IsActionAllowed("Encrypt") {
		t.Fatal("empty AllowedActions should deny all actions")
	}
}

// === RegisterPolicy 自动设置 RoleID ===

func TestAppRole_RegisterPolicySetsRoleID(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	// Policy 结构体中 RoleID 为空，RegisterPolicy 应自动设置。
	policy := &Policy{
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	}
	auth.RegisterPolicy("auto-role-id", "auto-token", policy)

	if policy.RoleID != "auto-role-id" {
		t.Fatalf("RegisterPolicy should set RoleID, got %q", policy.RoleID)
	}

	// 认证后返回的 Policy 应有 RoleID。
	got, _ := auth.Authenticate(context.Background(), "auto-token")
	if got.RoleID != "auto-role-id" {
		t.Fatalf("RoleID = %q, want auto-role-id", got.RoleID)
	}
}

// === 并发认证 ===

func TestAppRole_ConcurrentAuthenticate(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("concurrent-role", "concurrent-token", &Policy{
		RoleID:         "concurrent-role",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			policy, err := auth.Authenticate(context.Background(), "concurrent-token")
			if err != nil {
				t.Errorf("Authenticate: %v", err)
			}
			if policy == nil || policy.RoleID != "concurrent-role" {
				t.Errorf("unexpected policy: %v", policy)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

// === 并发注册 + 认证 ===

func TestAppRole_ConcurrentRegisterAndAuthenticate(t *testing.T) {
	auth := NewAppRoleAuthenticator()

	// 先注册一个 baseline。
	auth.RegisterPolicy("role-0", "token-0", &Policy{RoleID: "role-0", AllowedKeys: []string{"*"}})

	done := make(chan struct{})

	// 并发注册新角色。
	for i := 1; i <= 20; i++ {
		go func(idx int) {
			roleID := "role-" + string(rune('a'+idx))
			token := "token-" + string(rune('a'+idx))
			auth.RegisterPolicy(roleID, token, &Policy{RoleID: roleID, AllowedKeys: []string{"*"}})
			done <- struct{}{}
		}(i)
	}

	// 并发认证已有角色。
	for i := 0; i < 20; i++ {
		go func() {
			_, err := auth.Authenticate(context.Background(), "token-0")
			if err != nil {
				t.Errorf("Authenticate token-0: %v", err)
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 40; i++ {
		<-done
	}
}

// === 大量角色性能/正确性 ===

func TestAppRole_ManyRoles(t *testing.T) {
	auth := NewAppRoleAuthenticator()

	// 注册 100 个角色。
	for i := 0; i < 100; i++ {
		roleID := "role-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		token := "token-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		auth.RegisterPolicy(roleID, token, &Policy{
			RoleID:         roleID,
			AllowedKeys:    []string{roleID + "-*"},
			AllowedActions: []string{"Encrypt"},
		})
	}

	// 验证最后一个角色可认证。
	lastRole := "role-" + string(rune('a'+99%26)) + string(rune('a'+99/26))
	lastToken := "token-" + string(rune('a'+99%26)) + string(rune('a'+99/26))

	policy, err := auth.Authenticate(context.Background(), lastToken)
	if err != nil {
		t.Fatalf("Authenticate last role: %v", err)
	}
	if policy.RoleID != lastRole {
		t.Fatalf("RoleID = %q, want %q", policy.RoleID, lastRole)
	}

	// 验证不存在的 token。
	_, err = auth.Authenticate(context.Background(), "nonexistent-token")
	if err != ErrUnauthorized {
		t.Fatalf("nonexistent token should fail, got %v", err)
	}
}

// === Policy 匹配测试（通过 AppRole 间接测试）===

func TestAppRole_PolicyWildcardMatching(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role", "token", &Policy{
		RoleID:         "role",
		AllowedKeys:    []string{"order-*", "payment-*", "exact-key"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	policy, _ := auth.Authenticate(context.Background(), "token")

	// 通配符匹配。
	cases := []struct {
		keyID    string
		expected bool
	}{
		{"order-001", true},
		{"order-002", true},
		{"payment-001", true},
		{"exact-key", true},
		{"exact-key-2", false}, // 精确匹配不前缀
		{"order", false},       // 前缀通配需匹配 order-*
		{"other-key", false},
		{"", false},
	}

	for _, tc := range cases {
		got := policy.IsKeyAllowed(tc.keyID)
		if got != tc.expected {
			t.Errorf("IsKeyAllowed(%q) = %v, want %v", tc.keyID, got, tc.expected)
		}
	}
}

func TestAppRole_PolicyActionCaseInsensitive(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role", "token", &Policy{
		RoleID:         "role",
		AllowedActions: []string{"Encrypt", "Decrypt"},
	})

	policy, _ := auth.Authenticate(context.Background(), "token")

	// Action 匹配应大小写不敏感。
	if !policy.IsActionAllowed("encrypt") {
		t.Fatal("should allow 'encrypt' (case insensitive)")
	}
	if !policy.IsActionAllowed("ENCRYPT") {
		t.Fatal("should allow 'ENCRYPT' (case insensitive)")
	}
	if !policy.IsActionAllowed("Decrypt") {
		t.Fatal("should allow 'Decrypt'")
	}
	if policy.IsActionAllowed("RotateKey") {
		t.Fatal("should not allow RotateKey")
	}
}

// === 错误信息不泄露 Token ===

func TestAppRole_ErrorDoesNotLeakToken(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role", "real-token", &Policy{RoleID: "role"})

	_, err := auth.Authenticate(context.Background(), "fake-token-with-sensitive-data")
	if err == nil {
		t.Fatal("should fail")
	}
	// 错误信息不应包含 token 明文。
	if strings.Contains(err.Error(), "fake-token-with-sensitive-data") {
		t.Fatalf("error message leaks token: %v", err)
	}
	// 错误应是 ErrUnauthorized。
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// === Context 传递 ===

func TestAppRole_ContextPropagation(t *testing.T) {
	auth := NewAppRoleAuthenticator()
	auth.RegisterPolicy("role", "token", &Policy{RoleID: "role"})

	// 带 cancel 的 context（模拟请求取消）。
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 即使 context 取消，认证仍应完成（AppRole 是内存查找，不依赖 context）。
	policy, err := auth.Authenticate(ctx, "token")
	if err != nil {
		t.Fatalf("Authenticate with cancelled ctx: %v", err)
	}
	if policy == nil {
		t.Fatal("policy should not be nil")
	}
}
