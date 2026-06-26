package service

import (
	"context"
	"strings"
	"testing"

	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestCore_ErrorMessages_ActionDenied 验证 action 拒绝错误含详情。
func TestCore_ErrorMessages_ActionDenied(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	policy := &auth.Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"test-key"},
		AllowedActions: []string{"Decrypt"}, // 只有 Decrypt，无 Encrypt
	}

	_, err := core.Encrypt(ctx, "test-key", []byte("x"), policy)
	if err == nil {
		t.Fatal("should deny Encrypt")
	}

	msg := err.Error()
	if !strings.Contains(msg, "order-service") {
		t.Errorf("error should contain role: %s", msg)
	}
	if !strings.Contains(msg, "Encrypt") {
		t.Errorf("error should contain action: %s", msg)
	}
	if !strings.Contains(msg, "Decrypt") {
		t.Errorf("error should contain allowed actions: %s", msg)
	}
}

// TestCore_ErrorMessages_KeyDenied 验证 key 拒绝错误含详情。
func TestCore_ErrorMessages_KeyDenied(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "order-key", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "payment-key", seal.NewSoftwareKEK(mk), 0)

	policy := &auth.Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"}, // 不含 payment-key
		AllowedActions: []string{"Encrypt"},
	}

	_, err := core.Encrypt(ctx, "payment-key", []byte("x"), policy)
	if err == nil {
		t.Fatal("should deny payment-key")
	}

	msg := err.Error()
	if !strings.Contains(msg, "order-service") {
		t.Errorf("error should contain role: %s", msg)
	}
	if !strings.Contains(msg, "payment-key") {
		t.Errorf("error should contain denied key: %s", msg)
	}
	if !strings.Contains(msg, "order-*") {
		t.Errorf("error should contain allowed keys: %s", msg)
	}
}

// TestCore_ErrorMessages_Sealed 验证 sealed 错误含指引。
func TestCore_ErrorMessages_Sealed(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(5, 3, 0) // sealed
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	core := NewCore(mgr, vault, nil)

	_, err := core.Encrypt(context.Background(), "any", []byte("x"), nil)
	if err == nil {
		t.Fatal("should fail when sealed")
	}

	msg := err.Error()
	if !strings.Contains(msg, "sealed") {
		t.Errorf("error should mention sealed: %s", msg)
	}
	if !strings.Contains(msg, "unseal") {
		t.Errorf("error should guide to unseal: %s", msg)
	}
}

// TestCore_ErrorMessages_EmergencySealed 验证 emergency sealed 错误含指引。
func TestCore_ErrorMessages_EmergencySealed(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	// 触发 emergency seal。
	core.seal.EmergencySeal(ctx)

	_, err := core.Encrypt(ctx, "test-key", []byte("x"), nil)
	if err == nil {
		t.Fatal("should fail when emergency sealed")
	}

	msg := err.Error()
	if !strings.Contains(msg, "emergency sealed") {
		t.Errorf("error should mention emergency sealed: %s", msg)
	}
}

// TestCore_DegradedMode_WriteRefused 验证 MemoryStore 路径不 panic。
func TestCore_DegradedMode_WriteRefused(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	// MemoryStore 不支持健康检查，requireWritable 直接放行。
	_, err := core.CreateKey(ctx, "degraded-test", 0, false, nil)
	if err != nil {
		t.Fatalf("CreateKey on MemoryStore should not fail: %v", err)
	}
}

// TestCore_AdminTokenValidation 验证 EmergencySeal 校验 admin token。
func TestCore_AdminTokenValidation(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	// 未设置 admin token。
	err := core.EmergencySeal(ctx, "any-token")
	if err == nil {
		t.Fatal("EmergencySeal without configured token should fail")
	}

	// 设置 admin token。
	core.SetAdminToken("correct-token")

	// 错误 token。
	err = core.EmergencySeal(ctx, "wrong-token")
	if err == nil {
		t.Fatal("wrong admin token should fail")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention invalid: %s", err.Error())
	}

	// 正确 token。
	err = core.EmergencySeal(ctx, "correct-token")
	if err != nil {
		t.Fatalf("correct admin token should succeed: %v", err)
	}
}
