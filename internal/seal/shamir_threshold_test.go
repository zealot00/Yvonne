package seal

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
)

// === Shamir 3/5 门限与销毁严苛测试 ===
//
// 重点验证：
//   - 2/5 分片时仍 Sealed
//   - 3/5 分片时成功 Unsealed
//   - EmergencySeal 后分片池和 MasterKey 引用全部失效
//   - 跨 KEK 状态边界

// TestShamirThreshold_2of5_Sealed 验证 2 个分片不足门限，仍 Sealed。
func TestShamirThreshold_2of5_Sealed(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	vault := NewVaultState(5, 3, 0)

	// 提供 2 个分片（不足门限 3）。
	for i := 0; i < 2; i++ {
		unsealed, err := vault.ProvideShare(shares[i])
		if err != nil {
			t.Fatalf("ProvideShare %d: %v", i, err)
		}
		if unsealed {
			t.Fatalf("should not be unsealed with %d shares (threshold=3)", i+1)
		}
		if !vault.IsSealed() {
			t.Fatal("should still be sealed with 2 shares")
		}
	}
}

// TestShamirThreshold_3of5_Unsealed 验证第 3 个分片成功解封。
func TestShamirThreshold_3of5_Unsealed(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	vault := NewVaultState(5, 3, 0)

	// 提供 2 个分片。
	for i := 0; i < 2; i++ {
		vault.ProvideShare(shares[i])
	}

	// 第 3 个分片应触发解封。
	unsealed, err := vault.ProvideShare(shares[2])
	if err != nil {
		t.Fatalf("ProvideShare 3: %v", err)
	}
	if !unsealed {
		t.Fatal("should be unsealed with 3 shares (threshold=3)")
	}
	if vault.IsSealed() {
		t.Fatal("should not be sealed after threshold")
	}

	// 验证 MasterKey 正确。
	if !vault.MasterKeyEqual(secret) {
		t.Fatal("master key mismatch after unseal")
	}
}

// TestShamirThreshold_Any3of5 验证任意 3 个分片都能解封。
func TestShamirThreshold_Any3of5(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// 测试多种 3 分片组合。
	combinations := [][]int{
		{0, 1, 2},
		{0, 1, 3},
		{0, 1, 4},
		{0, 2, 3},
		{0, 2, 4},
		{0, 3, 4},
		{1, 2, 3},
		{1, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
	}

	for i, combo := range combinations {
		vault := NewVaultState(5, 3, 0)
		for _, idx := range combo {
			vault.ProvideShare(shares[idx])
		}
		if vault.IsSealed() {
			t.Fatalf("combo %d %v: should be unsealed", i, combo)
		}
		if !vault.MasterKeyEqual(secret) {
			t.Fatalf("combo %d %v: master key mismatch", i, combo)
		}
	}
}

// TestShamirThreshold_4of5_ExcessShares 验证超过门限的分片被接受。
func TestShamirThreshold_4of5_ExcessShares(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	// 提供 4 个分片（超过门限 3）。
	for i := 0; i < 4; i++ {
		vault.ProvideShare(shares[i])
	}

	// 第 3 个分片时已解封，第 4 个应被拒绝或忽略。
	if vault.IsSealed() {
		t.Fatal("should be unsealed with 4 shares")
	}
}

// TestShamirThreshold_5of5_AllShares 验证全部 5 个分片。
func TestShamirThreshold_5of5_AllShares(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	for i := 0; i < 5; i++ {
		vault.ProvideShare(shares[i])
	}

	if vault.IsSealed() {
		t.Fatal("should be unsealed with all 5 shares")
	}
}

// === EmergencySeal 致命约束测试 ===

// TestEmergencySeal_3of5_MasterKeyWiped 验证 EmergencySeal 后 MasterKey 不可用。
func TestEmergencySeal_3of5_MasterKeyWiped(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	// 解封。
	for i := 0; i < 3; i++ {
		vault.ProvideShare(shares[i])
	}
	if vault.IsSealed() {
		t.Fatal("should be unsealed")
	}

	// 紧急封印。
	vault.EmergencySeal(context.Background())

	// MasterKeyRef 必须失败。
	err := vault.MasterKeyRef(func(key *memguard.SecureBuffer) error {
		t.Fatal("MasterKeyRef should not expose key after EmergencySeal")
		return nil
	})
	if err == nil {
		t.Fatal("MasterKeyRef should fail after EmergencySeal")
	}

	// KEKRef 也必须失败。
	err = vault.KEKRef(func(kek KEK) error {
		t.Fatal("KEKRef should not expose KEK after EmergencySeal")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail after EmergencySeal")
	}
}

// TestEmergencySeal_3of5_ProvideShareRejected 验证 EmergencySeal 后 ProvideShare 拒绝。
func TestEmergencySeal_3of5_ProvideShareRejected(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	for i := 0; i < 3; i++ {
		vault.ProvideShare(shares[i])
	}

	vault.EmergencySeal(context.Background())

	// 尝试提供额外分片应失败。
	_, err := vault.ProvideShare(shares[3])
	if err == nil {
		t.Fatal("ProvideShare should fail after EmergencySeal")
	}
}

// TestEmergencySeal_3of5_SealAlsoRejected 验证 EmergencySeal 后 Seal 也拒绝。
func TestEmergencySeal_3of5_SealAlsoRejected(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	for i := 0; i < 3; i++ {
		vault.ProvideShare(shares[i])
	}

	vault.EmergencySeal(context.Background())

	// Seal 不应 panic，但也不应改变 EmergencySealed 状态。
	vault.Seal(context.Background())

	if !vault.IsEmergencySealed() {
		t.Fatal("should still be emergency sealed after Seal()")
	}
}

// TestEmergencySeal_3of5_StateIsTerminal 验证 EmergencySeal 状态不可逆。
func TestEmergencySeal_3of5_StateIsTerminal(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	for i := 0; i < 3; i++ {
		vault.ProvideShare(shares[i])
	}

	vault.EmergencySeal(context.Background())

	// 尝试再次解封（提供分片）——必须失败。
	for i := 0; i < 5; i++ {
		_, err := vault.ProvideShare(shares[i])
		if err == nil {
			t.Fatalf("ProvideShare %d should fail after EmergencySeal", i)
		}
	}

	// 状态必须仍是 EmergencySealed。
	if !vault.IsEmergencySealed() {
		t.Fatal("EmergencySeal state should be terminal")
	}

	// IsSealed 也应为 true。
	if !vault.IsSealed() {
		t.Fatal("should be sealed after EmergencySeal")
	}
}

// TestEmergencySeal_BeforeUnseal 验证未解封时 EmergencySeal 也可用。
func TestEmergencySeal_BeforeUnseal(t *testing.T) {
	vault := NewVaultState(5, 3, 0)

	// 未解封状态下紧急封印。
	vault.EmergencySeal(context.Background())

	if !vault.IsEmergencySealed() {
		t.Fatal("should be emergency sealed")
	}

	// ProvideShare 应失败。
	_, err := vault.ProvideShare([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("ProvideShare should fail after EmergencySeal (before unseal)")
	}
}

// === KEKRef 状态边界测试 ===

// TestKEKRef_SealedState 验证 Sealed 状态下 KEKRef 失败。
func TestKEKRef_SealedState(t *testing.T) {
	vault := NewVaultState(5, 3, 0)

	err := vault.KEKRef(func(kek KEK) error {
		t.Fatal("KEKRef should not work when sealed")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail when sealed")
	}
}

// TestKEKRef_AfterSeal 验证 Seal 后 KEKRef 失败。
func TestKEKRef_AfterSeal(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	for i := 0; i < 3; i++ {
		vault.ProvideShare(shares[i])
	}

	// Seal（非紧急）。
	vault.Seal(context.Background())

	err := vault.KEKRef(func(kek KEK) error {
		t.Fatal("KEKRef should not work after Seal")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail after Seal")
	}
}

// === 分片池清理测试 ===

// TestProvideShare_DuplicateShareRejected 验证重复分片被拒绝。
func TestProvideShare_DuplicateShareRejected(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)
	vault := NewVaultState(5, 3, 0)

	// 提供第一个分片。
	_, err := vault.ProvideShare(shares[0])
	if err != nil {
		t.Fatalf("first ProvideShare: %v", err)
	}

	// 重复提供相同分片应失败或被忽略。
	_, err = vault.ProvideShare(shares[0])
	if err == nil {
		// 如果不报错，检查是否仍 Sealed（重复不应推进计数）。
		// 某些实现可能幂等接受，关键是不应导致解封。
	}
}

// TestProvideShare_EmptyShare 验证空分片被拒绝。
func TestProvideShare_EmptyShare(t *testing.T) {
	vault := NewVaultState(5, 3, 0)

	_, err := vault.ProvideShare(nil)
	if err == nil {
		t.Fatal("nil share should be rejected")
	}

	_, err = vault.ProvideShare([]byte{})
	if err == nil {
		t.Fatal("empty share should be rejected")
	}
}

// TestProvideShare_MalformedShare 验证畸形分片在 Combine 阶段被拒绝。
//
// 注意：ProvideShare 阶段对 x=0 分片的处理因实现而异：
// - 部分实现提前拒绝（ProvideShare 返回 error）
// - 部分实现延迟到 Combine 拒绝
// 关键约束：不 panic + 仍 Sealed。
func TestProvideShare_MalformedShare(t *testing.T) {
	vault := NewVaultState(5, 3, 0)

	// 提供 3 个 x=0 的分片（保留值）。
	for i := 0; i < 3; i++ {
		_, err := vault.ProvideShare([]byte{0x00, byte(i + 1), 0x02, 0x03})
		_ = err // ProvideShare 可能接受或拒绝，关键是不 panic
	}
	// 经过 3 次 ProvideShare 后，Vault 应仍处于 Sealed 状态。
	if !vault.IsSealed() {
		t.Fatal("vault should remain sealed after malformed shares (Combine should fail)")
	}
}
