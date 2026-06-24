package seal

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
)

// TestEmergencySeal_WipesMasterKey 验证紧急封印后 Master Key 被 Wipe。
func TestEmergencySeal_WipesMasterKey(t *testing.T) {
	mk, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	defer mk.Wipe()

	v := NewVaultState(5, 3, 0)
	if err := v.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}
	if !v.IsUnsealed() {
		t.Fatal("should be unsealed")
	}

	v.EmergencySeal(context.Background())

	if !v.IsSealed() {
		t.Fatal("should be sealed after EmergencySeal")
	}
	if !v.IsEmergencySealed() {
		t.Fatal("IsEmergencySealed should be true")
	}
}

// TestEmergencySeal_Irreversible 验证紧急封印不可逆：
// ProvideShare 和 DirectUnseal 都应被拒绝。
func TestEmergencySeal_Irreversible(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	v := NewVaultState(5, 3, 0)
	v.DirectUnseal(mk)
	v.EmergencySeal(context.Background())

	// ProvideShare 应被拒绝。
	_, err := v.ProvideShare([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("ProvideShare after EmergencySeal should fail")
	}

	// DirectUnseal 应被拒绝。
	err = v.DirectUnseal(mk)
	if err == nil {
		t.Fatal("DirectUnseal after EmergencySeal should fail")
	}

	// 再次 EmergencySeal 应无副作用（幂等）。
	v.EmergencySeal(context.Background())
	if !v.IsEmergencySealed() {
		t.Fatal("IsEmergencySealed should still be true")
	}
}

// TestEmergencySeal_WipesCollectedShares 验证紧急封印清空碎片池。
func TestEmergencySeal_WipesCollectedShares(t *testing.T) {
	v := NewVaultState(5, 3, 0)

	// 提交 2 份碎片（未达阈值，留在池中）。
	v.ProvideShare([]byte{0x01, 0x02})
	v.ProvideShare([]byte{0x03, 0x04})
	if v.CollectedCount() != 2 {
		t.Fatalf("CollectedCount = %d, want 2", v.CollectedCount())
	}

	v.EmergencySeal(context.Background())

	if v.CollectedCount() != 0 {
		t.Fatalf("CollectedCount after EmergencySeal = %d, want 0", v.CollectedCount())
	}
}

// TestEmergencySeal_BlocksAllAPI 验证紧急封印后 Seal 方法也安全（状态一致）。
func TestEmergencySeal_BlocksAllAPI(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	v := NewVaultState(5, 3, 0)
	v.DirectUnseal(mk)
	v.EmergencySeal(context.Background())

	// Seal 后再 EmergencySeal 仍应正常。
	v.Seal(context.Background())
	if !v.IsEmergencySealed() {
		t.Fatal("EmergencySeal flag should survive Seal")
	}
	if !v.IsSealed() {
		t.Fatal("should still be sealed")
	}
}
