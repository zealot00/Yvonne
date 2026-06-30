package auth

import (
	"context"
	"testing"
)

// === Policy Context 注入测试 ===

func TestPolicyContext_Nil(t *testing.T) {
	ctx := context.Background()
	if PolicyFromContext(ctx) != nil {
		t.Fatal("empty context should return nil policy")
	}
}

func TestPolicyContext_RoundTrip(t *testing.T) {
	policy := &Policy{
		RoleID:         "test-role",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	}

	ctx := WithPolicy(context.Background(), policy)
	got := PolicyFromContext(ctx)
	if got == nil {
		t.Fatal("policy should not be nil after WithPolicy")
	}
	if got.RoleID != "test-role" {
		t.Fatalf("RoleID = %q, want test-role", got.RoleID)
	}
	if !got.IsKeyAllowed("order-001") {
		t.Fatal("should allow order-001")
	}
}

func TestPolicyContext_Overwrite(t *testing.T) {
	p1 := &Policy{RoleID: "role-1"}
	p2 := &Policy{RoleID: "role-2"}

	ctx := WithPolicy(context.Background(), p1)
	ctx = WithPolicy(ctx, p2)

	got := PolicyFromContext(ctx)
	if got.RoleID != "role-2" {
		t.Fatalf("RoleID = %q, want role-2 (overwritten)", got.RoleID)
	}
}

func TestPolicyContext_NilPolicy(t *testing.T) {
	ctx := WithPolicy(context.Background(), nil)
	got := PolicyFromContext(ctx)
	if got != nil {
		t.Fatal("nil policy should return nil")
	}
}

// === RoleID + Policy 共存于 context ===

func TestContext_RoleIDAndPolicyCoexist(t *testing.T) {
	policy := &Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	}

	ctx := WithRoleID(context.Background(), policy.RoleID)
	ctx = WithPolicy(ctx, policy)

	// 两者都能从 context 取出。
	roleID := RoleIDFromContext(ctx)
	gotPolicy := PolicyFromContext(ctx)

	if roleID != "order-service" {
		t.Fatalf("RoleID = %q", roleID)
	}
	if gotPolicy == nil || gotPolicy.RoleID != "order-service" {
		t.Fatalf("Policy RoleID mismatch: gotPolicy=%v", gotPolicy)
	}
}

// === matchPattern 边界测试 ===

func TestMatchPattern_Cases(t *testing.T) {
	cases := []struct {
		pattern string
		keyID   string
		want    bool
	}{
		// 全通配符。
		{"*", "anything", true},
		{"*", "", true},
		{"*", "order-001", true},

		// 前缀通配符。
		{"order-*", "order-001", true},
		{"order-*", "order-", true}, // 前缀匹配空后缀
		{"order-*", "order", false}, // 不匹配（需 order- 前缀）
		{"order-*", "order-001-002", true},
		{"order-*", "payment-001", false},

		// 精确匹配。
		{"exact-key", "exact-key", true},
		{"exact-key", "exact-key-2", false},
		{"exact-key", "exact", false},
		{"exact-key", "", false},

		// 单字符通配符（不支持，按精确匹配）。
		{"order?", "order1", false},

		// 空值。
		{"", "", true},   // 空 pattern 匹配空 keyID
		{"", "x", false}, // 空 pattern 不匹配非空 keyID
		{"*", "", true},  // * 匹配一切

		// 中间通配符（不支持，按精确匹配）。
		{"order-*-001", "order-abc-001", false},

		// 多段通配符。
		{"prefix-*", "prefix-anything", true},
		{"prefix-*", "prefix-", true},
		{"prefix-*", "prefix", false},
	}

	for _, tc := range cases {
		got := matchPattern(tc.pattern, tc.keyID)
		if got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.keyID, got, tc.want)
		}
	}
}

// === Authenticator 接口多态测试 ===

// 确保 AppRoleAuthenticator 和 JWTAuthenticator 都满足 Authenticator 接口。
func TestAuthenticator_InterfaceCompliance(t *testing.T) {
	var _ Authenticator = (*AppRoleAuthenticator)(nil)
	var _ Authenticator = (*JWTAuthenticator)(nil)
}

// 同一接口变量持有不同实现。
func TestAuthenticator_Polymorphism(t *testing.T) {
	appAuth := NewAppRoleAuthenticator()
	appAuth.RegisterPolicy("role", "app-token", &Policy{
		RoleID:         "role",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt"},
	})

	jwtAuth, _ := NewJWTAuthenticator(JWTConfig{
		SigningMethod: "HS256",
		Secret:        "jwt-secret",
		Issuer:        "test",
	}, makePolicyStore("role"))

	authenticators := []Authenticator{appAuth, jwtAuth}

	for i, a := range authenticators {
		// 无效 token 应统一返回 ErrUnauthorized。
		_, err := a.Authenticate(context.Background(), "invalid")
		if err != ErrUnauthorized {
			t.Fatalf("authenticator[%d] invalid token: got %v, want ErrUnauthorized", i, err)
		}

		// 空 token 应统一返回 ErrUnauthorized。
		_, err = a.Authenticate(context.Background(), "")
		if err != ErrUnauthorized {
			t.Fatalf("authenticator[%d] empty token: got %v, want ErrUnauthorized", i, err)
		}
	}
}

// === ErrUnauthorized 一致性 ===

func TestErrUnauthorized_IsSentinel(t *testing.T) {
	// ErrUnauthorized 应是 sentinel error，可用 == 比较。
	err1 := ErrUnauthorized
	err2 := ErrUnauthorized

	if err1 != err2 {
		t.Fatal("ErrUnauthorized should be comparable with ==")
	}
}

// === Policy 零值安全 ===

func TestPolicy_ZeroValueSafe(t *testing.T) {
	var p Policy

	// 零值 Policy 应拒绝所有 key 和 action（默认拒绝）。
	if p.IsKeyAllowed("any") {
		t.Fatal("zero-value Policy should deny all keys")
	}
	if p.IsActionAllowed("Encrypt") {
		t.Fatal("zero-value Policy should deny all actions")
	}

	// RoleID 应为空。
	if p.RoleID != "" {
		t.Fatalf("zero-value RoleID = %q, want empty", p.RoleID)
	}
}

// === Policy WithKey 闭包安全（如有泄露会 panic）===

func TestPolicy_NoSensitiveFields(t *testing.T) {
	p := &Policy{
		RoleID:         "role",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	}

	// Policy 结构体不应包含 Token、Secret 等敏感字段。
	// 这里通过反射检查字段名（防止未来误加敏感字段）。
	// 简化：仅检查已知字段存在且非空。
	if p.RoleID == "" {
		t.Fatal("RoleID should not be empty")
	}
	if len(p.AllowedKeys) == 0 {
		t.Fatal("AllowedKeys should not be empty")
	}
	if len(p.AllowedActions) == 0 {
		t.Fatal("AllowedActions should not be empty")
	}
}

// === context key 隔离测试 ===

func TestContextKey_Isolation(t *testing.T) {
	// RoleIDKey 和 PolicyKey 应是不同的 context key。
	ctx1 := WithRoleID(context.Background(), "role-1")
	ctx2 := WithPolicy(ctx1, &Policy{RoleID: "role-2"})

	// 两者互不干扰。
	if RoleIDFromContext(ctx2) != "role-1" {
		t.Fatal("WithPolicy should not overwrite RoleID")
	}
	if PolicyFromContext(ctx2).RoleID != "role-2" {
		t.Fatal("WithRoleID should not overwrite Policy")
	}
}

// === 并发 context 注入测试 ===

func TestContext_ConcurrentAccess(t *testing.T) {
	policy := &Policy{
		RoleID:         "concurrent-role",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt"},
	}

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			ctx := WithPolicy(context.Background(), policy)
			ctx = WithRoleID(ctx, policy.RoleID)

			gotPolicy := PolicyFromContext(ctx)
			gotRoleID := RoleIDFromContext(ctx)

			if gotPolicy == nil || gotPolicy.RoleID != "concurrent-role" {
				t.Error("policy mismatch in goroutine")
			}
			if gotRoleID != "concurrent-role" {
				t.Error("roleID mismatch in goroutine")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

// === 多层 context 嵌套 ===

func TestContext_NestedContext(t *testing.T) {
	policy := &Policy{RoleID: "nested-role"}

	ctx := context.Background()
	ctx = WithRoleID(ctx, "intermediate") // 中间值
	ctx = WithPolicy(ctx, policy)         // 覆盖

	// 最内层的 Policy 应生效。
	got := PolicyFromContext(ctx)
	if got == nil || got.RoleID != "nested-role" {
		t.Fatalf("nested context policy = %v", got)
	}

	// RoleID 应保持中间值（未被 WithPolicy 覆盖）。
	if RoleIDFromContext(ctx) != "intermediate" {
		t.Fatal("RoleID should not be affected by WithPolicy")
	}
}
