//go:build !hsm

// Package seal - HSM stub + KEK + VaultState 补充覆盖测试。
package seal

import (
	"context"
	"testing"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
)

// TestHSMStub_BuildHSMBackend 非 hsm 构建的 stub。
func TestHSMStub_BuildHSMBackend(t *testing.T) {
	_, err := BuildHSMBackend(HSMConfig{})
	if err == nil {
		t.Fatal("should error without hsm tag")
	}
	t.Logf("✅ BuildHSMBackend stub: %v", err)
}

// TestNewSoftwareKEKWithSuite 带 Suite 的 KEK。
func TestNewSoftwareKEKWithSuite(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	suite := crypto.NewStandardSuite()
	kek := NewSoftwareKEKWithSuite(mk, suite)
	if kek == nil {
		t.Fatal("should not be nil")
	}
	t.Log("✅ NewSoftwareKEKWithSuite")
}

// TestKEK_KeySize KeySize 方法。
func TestKEK_KeySize(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	suite := crypto.NewStandardSuite()
	kek := NewSoftwareKEKWithSuite(mk, suite)

	sk := kek.(*softwareKEK)
	size := sk.KeySize()
	if size != 32 {
		t.Fatalf("KeySize = %d, want 32", size)
	}
	t.Logf("✅ KEK.KeySize() = %d", size)
}

// TestVaultState_SetEmergencySealCallback 设置回调。
func TestVaultState_SetEmergencySealCallback(t *testing.T) {
	v := NewVaultState(3, 2, 0)

	called := false
	v.SetEmergencySealCallback(func() {
		called = true
	})

	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	v.DirectUnseal(mk)

	// EmergencySeal 应触发回调。
	v.EmergencySeal(context.Background())

	if !called {
		t.Fatal("callback should be called on EmergencySeal")
	}
	t.Log("✅ SetEmergencySealCallback")
}

// TestVaultState_SetCryptoSuite 设置密码套件。
func TestVaultState_SetCryptoSuite(t *testing.T) {
	v := NewVaultState(3, 2, 0)
	suite := crypto.NewStandardSuite()
	v.SetCryptoSuite(suite)
	t.Log("✅ SetCryptoSuite")
}

// TestHSMUnsealer_Methods HSM unsealer 方法（nil backend 不 panic）。
func TestHSMUnsealer_Methods(t *testing.T) {
	h := &HSMUnsealer{}
	_ = h.IsEmergencySealed()
	_ = h.Threshold()
	_ = h.TotalShares()
	t.Log("✅ HSMUnsealer methods (nil backend)")
}
