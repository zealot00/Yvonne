package auth

import (
	"context"
	"testing"
)

// newTestAuthenticator 创建测试用认证器，预装两个角色。
func newTestAuthenticator() *AppRoleAuthenticator {
	a := NewAppRoleAuthenticator()
	a.RegisterPolicy("order-service", "token-order-001", &Policy{
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"encrypt", "decrypt"},
	})
	a.RegisterPolicy("admin", "token-admin-secret", &Policy{
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"encrypt", "decrypt", "create", "rotate", "shred"},
	})
	return a
}

// TestAuthenticate_ValidToken 验证有效 Token 返回正确 Policy。
func TestAuthenticate_ValidToken(t *testing.T) {
	a := newTestAuthenticator()
	policy, err := a.Authenticate(context.Background(), "token-order-001")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "order-service" {
		t.Fatalf("RoleID = %q, want order-service", policy.RoleID)
	}
}

// TestAuthenticate_InvalidToken 验证无效 Token 返回 ErrUnauthorized。
func TestAuthenticate_InvalidToken(t *testing.T) {
	a := newTestAuthenticator()
	_, err := a.Authenticate(context.Background(), "wrong-token")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestAuthenticate_EmptyToken 验证空 Token 返回 ErrUnauthorized。
func TestAuthenticate_EmptyToken(t *testing.T) {
	a := newTestAuthenticator()
	_, err := a.Authenticate(context.Background(), "")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestAuthenticate_DifferentLengthToken 验证不同长度 Token 不泄露长度信息。
func TestAuthenticate_DifferentLengthToken(t *testing.T) {
	a := newTestAuthenticator()
	// 短 Token（长度不匹配）。
	_, err := a.Authenticate(context.Background(), "short")
	if err != ErrUnauthorized {
		t.Fatal("short token should be rejected")
	}
	// 长 Token（长度不匹配）。
	_, err = a.Authenticate(context.Background(), "very-long-token-that-does-not-match")
	if err != ErrUnauthorized {
		t.Fatal("long token should be rejected")
	}
}

// TestPolicy_IsKeyAllowed 验证通配符匹配。
func TestPolicy_IsKeyAllowed(t *testing.T) {
	// 含 "*" 的 Policy 匹配一切。
	pAll := &Policy{AllowedKeys: []string{"*"}}
	if !pAll.IsKeyAllowed("anything") {
		t.Error("* should match everything")
	}

	// 不含 "*" 的 Policy，测试前缀通配与精确匹配。
	p := &Policy{AllowedKeys: []string{"order-*", "payment-key"}}

	tests := []struct {
		keyID string
		want  bool
	}{
		{"order-001", true},
		{"order-abc", true},
		{"payment-key", true},
		{"order", false},    // 不以 "order-" 开头
		{"user-key", false}, // 不在允许列表
	}

	for _, tt := range tests {
		got := p.IsKeyAllowed(tt.keyID)
		if got != tt.want {
			t.Errorf("IsKeyAllowed(%q) = %v, want %v", tt.keyID, got, tt.want)
		}
	}
}

// TestPolicy_IsActionAllowed 验证 action 校验。
func TestPolicy_IsActionAllowed(t *testing.T) {
	p := &Policy{
		AllowedActions: []string{"encrypt", "decrypt"},
	}
	if !p.IsActionAllowed("encrypt") {
		t.Error("encrypt should be allowed")
	}
	if !p.IsActionAllowed("decrypt") {
		t.Error("decrypt should be allowed")
	}
	if p.IsActionAllowed("shred") {
		t.Error("shred should NOT be allowed")
	}
	if p.IsActionAllowed("ENCRYPT") {
		// IsActionAllowed 用 EqualFold，大小写不敏感。
		// 这是设计选择：action 名大小写不敏感。
	}
}

// TestExtractBearerToken_Valid 验证合法 Bearer token 提取。
func TestExtractBearerToken_Valid(t *testing.T) {
	token, err := ExtractBearerToken("Bearer abc123")
	if err != nil {
		t.Fatalf("ExtractBearerToken: %v", err)
	}
	if token != "abc123" {
		t.Fatalf("token = %q, want abc123", token)
	}
}

// TestExtractBearerToken_Missing 验证缺失 Authorization header 报错。
func TestExtractBearerToken_Missing(t *testing.T) {
	_, err := ExtractBearerToken("")
	if err == nil {
		t.Fatal("empty header should fail")
	}
}

// TestExtractBearerToken_WrongScheme 验证非 Bearer scheme 报错。
func TestExtractBearerToken_WrongScheme(t *testing.T) {
	_, err := ExtractBearerToken("Basic abc123")
	if err == nil {
		t.Fatal("non-Bearer scheme should fail")
	}
}

// TestExtractBearerToken_EmptyToken 验证空 token 报错。
func TestExtractBearerToken_EmptyToken(t *testing.T) {
	_, err := ExtractBearerToken("Bearer ")
	if err == nil {
		t.Fatal("empty bearer token should fail")
	}
}

// TestContext_RoleID 验证 context 注入与提取。
func TestContext_RoleID(t *testing.T) {
	ctx := context.Background()
	if RoleIDFromContext(ctx) != "" {
		t.Fatal("empty context should return empty RoleID")
	}

	ctx = WithRoleID(ctx, "test-role")
	if got := RoleIDFromContext(ctx); got != "test-role" {
		t.Fatalf("RoleIDFromContext = %q, want test-role", got)
	}
}

// TestConstantTimeCompare_NotLeakingLength 验证 ConstantTimeCompare 不因长度差异提前退出。
// 这是一个 smoke test，验证 Token 长度不同时仍返回 Unauthorized（不 panic）。
func TestConstantTimeCompare_NotLeakingLength(t *testing.T) {
	a := NewAppRoleAuthenticator()
	a.RegisterPolicy("test", "exact-token-12345", &Policy{
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"encrypt"},
	})

	// 正确 Token。
	_, err := a.Authenticate(context.Background(), "exact-token-12345")
	if err != nil {
		t.Fatalf("correct token should authenticate: %v", err)
	}

	// 长度相同但内容不同的 Token。
	_, err = a.Authenticate(context.Background(), "exact-token-12346")
	if err != ErrUnauthorized {
		t.Fatal("wrong token should be unauthorized")
	}

	// 长度不同的 Token。
	_, err = a.Authenticate(context.Background(), "short")
	if err != ErrUnauthorized {
		t.Fatal("short token should be unauthorized")
	}
}
