package auth

import (
	"errors"
	"testing"
)

// === MemoryPolicyStore ===

func TestMemoryPolicyStore_AddAndLookup(t *testing.T) {
	store := NewMemoryPolicyStore()
	policy := &Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	}
	store.AddPolicy(policy)

	got, err := store.LookupPolicy("order-service")
	if err != nil {
		t.Fatalf("LookupPolicy: %v", err)
	}
	if got == nil {
		t.Fatal("policy should be found")
	}
	if got.RoleID != "order-service" {
		t.Fatalf("RoleID = %q", got.RoleID)
	}
	if !got.IsKeyAllowed("order-001") {
		t.Fatal("should allow order-001")
	}
}

func TestMemoryPolicyStore_LookupNotFound(t *testing.T) {
	store := NewMemoryPolicyStore()
	got, err := store.LookupPolicy("nonexistent")
	if err != nil {
		t.Fatalf("LookupPolicy should not return error for missing role: %v", err)
	}
	if got != nil {
		t.Fatal("policy should be nil for missing role")
	}
}

func TestMemoryPolicyStore_AddNilPolicy(t *testing.T) {
	store := NewMemoryPolicyStore()
	store.AddPolicy(nil)
	store.AddPolicy(&Policy{RoleID: ""}) // 空 RoleID 不应被存储

	// 验证空 RoleID 未被存储。
	got, _ := store.LookupPolicy("")
	if got != nil {
		t.Fatal("empty RoleID policy should not be stored")
	}
}

func TestMemoryPolicyStore_AddDuplicateRole(t *testing.T) {
	store := NewMemoryPolicyStore()
	store.AddPolicy(&Policy{RoleID: "role-a", AllowedKeys: []string{"key-1"}})
	// 覆盖同一 role。
	store.AddPolicy(&Policy{RoleID: "role-a", AllowedKeys: []string{"key-2"}})

	got, _ := store.LookupPolicy("role-a")
	if !got.IsKeyAllowed("key-2") {
		t.Fatal("duplicate AddPolicy should overwrite")
	}
	if got.IsKeyAllowed("key-1") {
		t.Fatal("old policy should be overwritten")
	}
}

func TestMemoryPolicyStore_MultipleRoles(t *testing.T) {
	store := NewMemoryPolicyStore()
	store.AddPolicy(&Policy{RoleID: "role-a", AllowedKeys: []string{"a-*"}})
	store.AddPolicy(&Policy{RoleID: "role-b", AllowedKeys: []string{"b-*"}})
	store.AddPolicy(&Policy{RoleID: "role-c", AllowedKeys: []string{"c-*"}})

	for _, roleID := range []string{"role-a", "role-b", "role-c"} {
		got, err := store.LookupPolicy(roleID)
		if err != nil || got == nil {
			t.Fatalf("LookupPolicy(%q) failed: err=%v got=%v", roleID, err, got)
		}
	}

	// 验证不存在的 role。
	got, _ := store.LookupPolicy("role-d")
	if got != nil {
		t.Fatal("role-d should not exist")
	}
}

// === AppRoleAuthenticator as PolicyStore ===

func TestAppRoleAuthenticator_LookupPolicy(t *testing.T) {
	appAuth := NewAppRoleAuthenticator()
	policy := &Policy{
		RoleID:         "payment-service",
		AllowedKeys:    []string{"payment-*"},
		AllowedActions: []string{"Encrypt", "Decrypt"},
	}
	appAuth.RegisterPolicy("payment-service", "token-xxx", policy)

	// 通过 PolicyStore 接口查找。
	got, err := appAuth.LookupPolicy("payment-service")
	if err != nil {
		t.Fatalf("LookupPolicy: %v", err)
	}
	if got == nil {
		t.Fatal("policy should be found")
	}
	if got.RoleID != "payment-service" {
		t.Fatalf("RoleID = %q", got.RoleID)
	}
	if !got.IsKeyAllowed("payment-001") {
		t.Fatal("should allow payment-001")
	}
}

func TestAppRoleAuthenticator_LookupPolicyNotFound(t *testing.T) {
	appAuth := NewAppRoleAuthenticator()

	got, err := appAuth.LookupPolicy("nonexistent")
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}
	if got != nil {
		t.Fatal("policy should be nil")
	}
}

// === PolicyStore 接口多态测试 ===

// mockPolicyStore 用于测试接口多态性。
type mockPolicyStore struct {
	policies map[string]*Policy
	err      error
}

func (m *mockPolicyStore) LookupPolicy(roleID string) (*Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policies[roleID], nil
}

func TestPolicyStore_InterfacePolymorphism(t *testing.T) {
	// 同一个接口变量可以持有不同实现。
	stores := []PolicyStore{
		NewMemoryPolicyStore(),
		NewAppRoleAuthenticator(),
		&mockPolicyStore{policies: map[string]*Policy{}},
	}

	for i, store := range stores {
		// 统一测试：查找不存在的 role 应返回 nil（无 error）。
		got, err := store.LookupPolicy("nonexistent")
		if err != nil {
			t.Fatalf("store[%d] LookupPolicy error: %v", i, err)
		}
		if got != nil {
			t.Fatalf("store[%d] should return nil for missing role", i)
		}
	}
}

func TestPolicyStore_MockWithError(t *testing.T) {
	expectedErr := errors.New("database connection failed")
	store := &mockPolicyStore{err: expectedErr}

	_, err := store.LookupPolicy("any-role")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
}

// === Policy 验证测试（通过 PolicyStore 间接测试）===

func TestPolicyStore_PolicyValidation(t *testing.T) {
	store := NewMemoryPolicyStore()
	store.AddPolicy(&Policy{
		RoleID:         "wildcard-role",
		AllowedKeys:    []string{"*"},
		AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp", "AuditQuery"},
	})

	policy, _ := store.LookupPolicy("wildcard-role")

	// 通配符 key。
	if !policy.IsKeyAllowed("anything") {
		t.Fatal("wildcard * should allow any key")
	}

	// 各种 action。
	actions := []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp", "AuditQuery"}
	for _, action := range actions {
		if !policy.IsActionAllowed(action) {
			t.Fatalf("action %q should be allowed", action)
		}
	}

	// 未授权的 action。
	if policy.IsActionAllowed("DeleteKey") {
		t.Fatal("DeleteKey should not be allowed")
	}
}

// === 并发安全测试 ===

func TestMemoryPolicyStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryPolicyStore()

	// 并发写入。
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			roleID := "role-" + string(rune('a'+idx))
			store.AddPolicy(&Policy{RoleID: roleID, AllowedKeys: []string{"*"}})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// 并发读取。
	for i := 0; i < 10; i++ {
		go func(idx int) {
			roleID := "role-" + string(rune('a'+idx))
			got, _ := store.LookupPolicy(roleID)
			if got == nil {
				t.Errorf("role-%c should exist", rune('a'+idx))
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestAppRoleAuthenticator_ConcurrentLookup(t *testing.T) {
	appAuth := NewAppRoleAuthenticator()
	appAuth.RegisterPolicy("role-a", "token-a", &Policy{RoleID: "role-a", AllowedKeys: []string{"*"}})

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			got, _ := appAuth.LookupPolicy("role-a")
			if got == nil {
				t.Error("role-a should exist")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// === 边界测试 ===

func TestMemoryPolicyStore_EmptyStore(t *testing.T) {
	store := NewMemoryPolicyStore()
	got, err := store.LookupPolicy("any")
	if err != nil {
		t.Fatalf("empty store should not return error: %v", err)
	}
	if got != nil {
		t.Fatal("empty store should return nil policy")
	}
}

func TestPolicyStore_NilPolicyRoleID(t *testing.T) {
	store := NewMemoryPolicyStore()
	// Policy with empty RoleID should not be stored.
	store.AddPolicy(&Policy{RoleID: "", AllowedKeys: []string{"*"}})

	got, _ := store.LookupPolicy("")
	if got != nil {
		t.Fatal("empty RoleID policy should not be stored")
	}
}
