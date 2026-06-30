// Package auth - 补充覆盖测试（ApprovalTicket 方法 + MemoryApprovalStore + MultiAuthenticator + JWT 辅助）。
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// === ApprovalTicket 方法测试 ===

func TestApprovalTicket_IsApprovalComplete(t *testing.T) {
	ticket := &ApprovalTicket{Required: 2, Approvers: []string{"a1"}}
	if ticket.IsApprovalComplete() {
		t.Fatal("1/2 should not be complete")
	}

	ticket.Approvers = append(ticket.Approvers, "a2")
	if !ticket.IsApprovalComplete() {
		t.Fatal("2/2 should be complete")
	}
	t.Log("✅ IsApprovalComplete")
}

func TestApprovalTicket_IsExpired(t *testing.T) {
	ticket := &ApprovalTicket{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	if !ticket.IsExpired() {
		t.Fatal("should be expired")
	}

	ticket.ExpiresAt = time.Now().Add(1 * time.Hour)
	if ticket.IsExpired() {
		t.Fatal("should not be expired")
	}
	t.Log("✅ IsExpired")
}

func TestApprovalTicket_HasApproved(t *testing.T) {
	ticket := &ApprovalTicket{Approvers: []string{"a1", "a2"}}
	if !ticket.HasApproved("a1") {
		t.Fatal("should have a1")
	}
	if ticket.HasApproved("a3") {
		t.Fatal("should not have a3")
	}
	t.Log("✅ HasApproved")
}

func TestApprovalTicket_HasRejected(t *testing.T) {
	ticket := &ApprovalTicket{Rejectors: []string{"r1"}}
	if !ticket.HasRejected("r1") {
		t.Fatal("should have r1")
	}
	if ticket.HasRejected("r2") {
		t.Fatal("should not have r2")
	}
	t.Log("✅ HasRejected")
}

// === MemoryApprovalStore 测试 ===

func TestMemoryApprovalStore_CRUD(t *testing.T) {
	store := NewMemoryApprovalStore()

	// Create.
	ticket := &ApprovalTicket{
		ID:        "test-001",
		Operation: "ShredKey",
		Required:  2,
		Status:    ApprovalPending,
		Approvers: []string{},
		Rejectors: []string{},
	}
	if err := store.CreateTicket(ticket); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	t.Log("✅ CreateTicket")

	// Get.
	got, err := store.GetTicket("test-001")
	if err != nil {
		t.Fatalf("GetTicket: %v", err)
	}
	if got.ID != "test-001" {
		t.Fatal("ID mismatch")
	}
	t.Log("✅ GetTicket")

	// Update.
	got.Approvers = append(got.Approvers, "approver-1")
	if err := store.UpdateTicket(got); err != nil {
		t.Fatalf("UpdateTicket: %v", err)
	}
	updated, _ := store.GetTicket("test-001")
	if len(updated.Approvers) != 1 {
		t.Fatal("approvers should have 1")
	}
	t.Log("✅ UpdateTicket")

	// Delete.
	store.DeleteTicket("test-001")
	_, err = store.GetTicket("test-001")
	if err == nil {
		t.Fatal("should be deleted")
	}
	t.Log("✅ DeleteTicket")
}

func TestMemoryApprovalStore_GetNotFound(t *testing.T) {
	store := NewMemoryApprovalStore()
	_, err := store.GetTicket("nonexistent")
	if err != ErrApprovalNotFound {
		t.Fatalf("expected ErrApprovalNotFound, got %v", err)
	}
	t.Log("✅ GetTicket not found")
}

func TestMemoryApprovalStore_UpdateNotFound(t *testing.T) {
	store := NewMemoryApprovalStore()
	err := store.UpdateTicket(&ApprovalTicket{ID: "nonexistent"})
	if err != ErrApprovalNotFound {
		t.Fatalf("expected ErrApprovalNotFound, got %v", err)
	}
	t.Log("✅ UpdateTicket not found")
}

func TestMemoryApprovalStore_CreateDuplicate(t *testing.T) {
	store := NewMemoryApprovalStore()
	ticket := &ApprovalTicket{ID: "dup-001", Approvers: []string{}, Rejectors: []string{}}
	store.CreateTicket(ticket)
	err := store.CreateTicket(ticket)
	if err == nil {
		t.Fatal("should reject duplicate")
	}
	t.Log("✅ CreateTicket duplicate rejected")
}

func TestMemoryApprovalStore_ListPending(t *testing.T) {
	store := NewMemoryApprovalStore()
	store.CreateTicket(&ApprovalTicket{ID: "p1", Status: ApprovalPending, Approvers: []string{}, Rejectors: []string{}})
	store.CreateTicket(&ApprovalTicket{ID: "p2", Status: ApprovalPending, Approvers: []string{}, Rejectors: []string{}})
	store.CreateTicket(&ApprovalTicket{ID: "a1", Status: ApprovalApproved, Approvers: []string{}, Rejectors: []string{}})

	pending, err := store.ListPending()
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}
	t.Logf("✅ ListPending: %d", len(pending))
}

func TestMemoryApprovalStore_ListByOperation(t *testing.T) {
	store := NewMemoryApprovalStore()
	store.CreateTicket(&ApprovalTicket{ID: "o1", Operation: "ShredKey", Approvers: []string{}, Rejectors: []string{}})
	store.CreateTicket(&ApprovalTicket{ID: "o2", Operation: "ExportKey", Approvers: []string{}, Rejectors: []string{}})

	results, err := store.ListByOperation("ShredKey")
	if err != nil {
		t.Fatalf("ListByOperation: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
	t.Logf("✅ ListByOperation: %d", len(results))
}

func TestMemoryApprovalStore_CleanupExpired(t *testing.T) {
	store := NewMemoryApprovalStore()
	store.CreateTicket(&ApprovalTicket{
		ID:        "expired-001",
		Status:    ApprovalPending,
		Approvers: []string{},
		Rejectors: []string{},
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	store.CreateTicket(&ApprovalTicket{
		ID:        "active-001",
		Status:    ApprovalPending,
		Approvers: []string{},
		Rejectors: []string{},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	count := store.CleanupExpired()
	if count != 1 {
		t.Fatalf("expected 1 expired, got %d", count)
	}

	expired, _ := store.GetTicket("expired-001")
	if expired.Status != ApprovalExpired {
		t.Fatal("should be marked expired")
	}
	t.Log("✅ CleanupExpired: 1 ticket expired")
}

func TestMemoryApprovalStore_DeepCopy(t *testing.T) {
	store := NewMemoryApprovalStore()
	store.CreateTicket(&ApprovalTicket{
		ID:        "copy-001",
		Approvers: []string{"a1"},
		Rejectors: []string{"r1"},
	})

	// Get 返回副本。
	got, _ := store.GetTicket("copy-001")
	got.Approvers[0] = "MODIFIED"

	// 原 store 不应受影响。
	original, _ := store.GetTicket("copy-001")
	if original.Approvers[0] != "a1" {
		t.Fatal("store should be isolated from returned copy")
	}
	t.Log("✅ MemoryApprovalStore deep copy")
}

// === MultiAuthenticator 测试 ===

func TestMultiAuthenticator_FirstSucceeds(t *testing.T) {
	appRole := NewAppRoleAuthenticator()
	appRole.RegisterPolicy("admin", "admin-token", &Policy{RoleID: "admin", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}})

	multi := NewMultiAuthenticator(appRole)
	policy, err := multi.Authenticate(context.Background(), "admin-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatal("wrong policy")
	}
	t.Log("✅ MultiAuthenticator first succeeds")
}

func TestMultiAuthenticator_SecondSucceeds(t *testing.T) {
	appRole1 := NewAppRoleAuthenticator()
	appRole2 := NewAppRoleAuthenticator()
	appRole2.RegisterPolicy("admin", "admin-token", &Policy{RoleID: "admin", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}})

	multi := NewMultiAuthenticator(appRole1, appRole2)
	policy, err := multi.Authenticate(context.Background(), "admin-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatal("wrong policy")
	}
	t.Log("✅ MultiAuthenticator second succeeds")
}

func TestMultiAuthenticator_AllFail(t *testing.T) {
	appRole := NewAppRoleAuthenticator()
	multi := NewMultiAuthenticator(appRole)
	_, err := multi.Authenticate(context.Background(), "wrong-token")
	if err == nil {
		t.Fatal("should fail")
	}
	t.Logf("✅ MultiAuthenticator all fail: %v", err)
}

func TestMultiAuthenticator_NilAuthenticator(t *testing.T) {
	appRole := NewAppRoleAuthenticator()
	appRole.RegisterPolicy("admin", "admin-token", &Policy{RoleID: "admin", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}})

	multi := NewMultiAuthenticator(nil, appRole)
	policy, err := multi.Authenticate(context.Background(), "admin-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if policy.RoleID != "admin" {
		t.Fatal("wrong policy")
	}
	t.Log("✅ MultiAuthenticator skips nil")
}

func TestMultiAuthenticator_Empty(t *testing.T) {
	multi := NewMultiAuthenticator()
	_, err := multi.Authenticate(context.Background(), "any")
	if err == nil {
		t.Fatal("should fail with no authenticators")
	}
	t.Logf("✅ MultiAuthenticator empty: %v", err)
}

// === JWT extractRoleID 测试 ===

func TestExtractRoleID_String(t *testing.T) {
	claims := jwt.MapClaims{
		"role": "admin",
	}
	roleID := extractRoleID(claims, "role")
	if roleID != "admin" {
		t.Fatalf("got %q, want admin", roleID)
	}
	t.Log("✅ extractRoleID string")
}

func TestExtractRoleID_NestedPath(t *testing.T) {
	claims := jwt.MapClaims{
		"resource_access": map[string]interface{}{
			"client": map[string]interface{}{
				"roles": []interface{}{"admin", "operator"},
			},
		},
	}
	roleID := extractRoleID(claims, "resource_access.client.roles")
	if roleID != "admin" {
		t.Fatalf("got %q, want admin", roleID)
	}
	t.Log("✅ extractRoleID nested path")
}

func TestExtractRoleID_NotFound(t *testing.T) {
	claims := jwt.MapClaims{
		"other": "value",
	}
	roleID := extractRoleID(claims, "role")
	if roleID != "" {
		t.Fatalf("got %q, want empty", roleID)
	}
	t.Log("✅ extractRoleID not found")
}

func TestExtractRoleIDs_Array(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"admin", "operator", 123, ""},
	}
	roles := extractRoleIDs(claims, "roles")
	if len(roles) != 2 {
		t.Fatalf("expected 2 valid roles, got %d", len(roles))
	}
	t.Logf("✅ extractRoleIDs array: %v", roles)
}

// === Policy 新字段测试 ===

func TestPolicy_RequireMFA(t *testing.T) {
	p := &Policy{RequireMFA: true}
	if !p.RequireMFA {
		t.Fatal("RequireMFA should be true")
	}
	t.Log("✅ Policy.RequireMFA")
}

func TestPolicy_RequireQuorum(t *testing.T) {
	p := &Policy{RequireQuorum: 3}
	if p.RequireQuorum != 3 {
		t.Fatal("RequireQuorum should be 3")
	}
	t.Log("✅ Policy.RequireQuorum")
}

func TestPolicy_IsActionAllowed_Wildcard(t *testing.T) {
	p := &Policy{AllowedActions: []string{"*"}}
	if !p.IsActionAllowed("Sign") {
		t.Fatal("wildcard should allow Sign")
	}
	if !p.IsActionAllowed("Encrypt") {
		t.Fatal("wildcard should allow Encrypt")
	}
	t.Log("✅ Policy.IsActionAllowed wildcard")
}

func TestPolicy_IsActionAllowed_Specific(t *testing.T) {
	p := &Policy{AllowedActions: []string{"encrypt", "decrypt"}}
	if !p.IsActionAllowed("encrypt") {
		t.Fatal("should allow encrypt")
	}
	if p.IsActionAllowed("sign") {
		t.Fatal("should not allow sign")
	}
	t.Log("✅ Policy.IsActionAllowed specific")
}
