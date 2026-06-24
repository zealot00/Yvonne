package seal

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"yvonne/internal/memguard"
)

// helper: 构造一个随机 SecureBuffer 作为测试 secret。
func newTestSecret(t *testing.T, size int) *memguard.SecureBuffer {
	t.Helper()
	sb, err := memguard.NewSecureBufferFromRandom(size)
	if err != nil {
		t.Fatalf("newTestSecret: %v", err)
	}
	t.Cleanup(func() { sb.Wipe() })
	return sb
}

// helper: 重组并返回明文副本用于断言（自动 Wipe 中间 SecureBuffer）。
func combineAndCopy(t *testing.T, shares [][]byte) []byte {
	t.Helper()
	sb, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	defer sb.Wipe()
	var out []byte
	if err := sb.WithKey(func(s []byte) error {
		out = append(out, s...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey: %v", err)
	}
	return out
}

// TestShamirRoundTrip_AllCombinations 验证数学闭环：
// Split 成 5 份，取任意 3 份必须能还原。
// 覆盖 [0,2,4]、[1,2,3]、[0,1,2] 等多种组合。
func TestShamirRoundTrip_AllCombinations(t *testing.T) {
	secret := newTestSecret(t, 32) // 256-bit master key
	var secretCopy []byte
	if err := secret.WithKey(func(s []byte) error {
		secretCopy = append(secretCopy, s...)
		return nil
	}); err != nil {
		t.Fatalf("WithKey: %v", err)
	}
	defer func() {
		for i := range secretCopy {
			secretCopy[i] = 0
		}
	}()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}

	// 列举若干 3-子集组合，逐一验证还原。
	combos := [][]int{
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
	for _, c := range combos {
		sub := [][]byte{shares[c[0]], shares[c[1]], shares[c[2]]}
		got := combineAndCopy(t, sub)
		if !bytes.Equal(got, secretCopy) {
			t.Fatalf("combination %v: mismatch\ngot  = %x\nwant = %x", c, got, secretCopy)
		}
		for i := range got {
			got[i] = 0
		}
	}
}

// TestShamirRoundTrip_MoreThanThreshold 验证用超过 threshold 份数也能还原。
// 4 份（≥3）应该能直接还原。
func TestShamirRoundTrip_MoreThanThreshold(t *testing.T) {
	secret := newTestSecret(t, 16)
	var want []byte
	_ = secret.WithKey(func(s []byte) error { want = append(want, s...); return nil })
	defer func() {
		for i := range want {
			want[i] = 0
		}
	}()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// 用 4 份（超过 threshold）。
	sub := shares[:4]
	got := combineAndCopy(t, sub)
	if !bytes.Equal(got, want) {
		t.Fatalf("4-share combine mismatch")
	}
	for i := range got {
		got[i] = 0
	}
}

// TestShamirSplit_DifferentSecretsDifferentShares 验证不同 secret 产出不同 shares。
func TestShamirSplit_DifferentSecretsDifferentShares(t *testing.T) {
	s1 := newTestSecret(t, 8)
	s2 := newTestSecret(t, 8)

	sh1, err := Split(s1, 3, 2)
	if err != nil {
		t.Fatalf("Split s1: %v", err)
	}
	sh2, err := Split(s2, 3, 2)
	if err != nil {
		t.Fatalf("Split s2: %v", err)
	}

	// 同位置的 share 应不同（极大概率）。
	for i := range sh1 {
		if bytes.Equal(sh1[i], sh2[i]) {
			t.Fatalf("share %d identical between two different secrets", i)
		}
	}
}

// TestCombine_InsufficientShares 验证低于 threshold 报错且不泄露。
// Combine 内部不会输出任何明文（返回 err + nil SecureBuffer）。
func TestCombine_InsufficientShares(t *testing.T) {
	secret := newTestSecret(t, 32)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// 用 2 份去 Combine 不会还原出原 secret。
	// 但 Combine 本身不报错（数学上 2 份能插值出 1 次多项式，但不是原 secret）。
	// 这里验证：2 份还原的结果 ≠ 原 secret（防误以为成功）。
	sub := [][]byte{shares[0], shares[1]}
	sb, err := Combine(sub)
	if err != nil {
		// Combine 直接报错也可接受——但本实现允许 2 份插值（数学合法但语义错误）。
		return
	}
	defer sb.Wipe()

	var got []byte
	_ = sb.WithKey(func(s []byte) error { got = append(got, s...); return nil })
	var want []byte
	_ = secret.WithKey(func(s []byte) error { want = append(want, s...); return nil })

	if bytes.Equal(got, want) {
		t.Fatal("2 shares should not reconstruct the original secret under threshold=3")
	}
	for i := range got {
		got[i] = 0
	}
	for i := range want {
		want[i] = 0
	}
}

// TestCombine_InvalidShares 验证格式非法的 share 报错。
func TestCombine_InvalidShares(t *testing.T) {
	cases := []struct {
		name   string
		shares [][]byte
	}{
		{"empty", nil},
		{"single", [][]byte{{1, 2, 3}}},
		{"zero x", [][]byte{{0, 1}, {2, 3}}},
		{"length mismatch", [][]byte{{1, 2, 3}, {2, 3}}},
		{"duplicate x", [][]byte{{1, 2}, {1, 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sb, err := Combine(c.shares)
			if err == nil {
				if sb != nil {
					sb.Wipe()
				}
				t.Fatalf("expected error, got nil")
			}
			if sb != nil {
				sb.Wipe()
				t.Fatal("expected nil SecureBuffer on error")
			}
		})
	}
}

// TestVaultState_ProvideShare_Lifecycle 验证完整状态机流程。
// 5 份 split，逐个 ProvideShare，达到 3 份时 Unseal。
func TestVaultState_ProvideShare_Lifecycle(t *testing.T) {
	secret := newTestSecret(t, 32)
	var secretCopy []byte
	_ = secret.WithKey(func(s []byte) error { secretCopy = append(secretCopy, s...); return nil })
	defer func() {
		for i := range secretCopy {
			secretCopy[i] = 0
		}
	}()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	v := NewVaultState(5, 3, 0)
	if !v.IsSealed() {
		t.Fatal("initial state should be sealed")
	}

	// 提交 2 份，未达阈值，应仍未 sealed。
	for i := 0; i < 2; i++ {
		unsealed, err := v.ProvideShare(shares[i])
		if err != nil {
			t.Fatalf("ProvideShare %d: %v", i, err)
		}
		if unsealed {
			t.Fatalf("should not be unsealed after %d shares", i+1)
		}
	}
	if !v.IsSealed() {
		t.Fatal("should still be sealed after 2 shares (threshold=3)")
	}
	if v.CollectedCount() != 2 {
		t.Fatalf("collected count = %d, want 2", v.CollectedCount())
	}

	// 提交第 3 份，触发 Unseal。
	unsealed, err := v.ProvideShare(shares[2])
	if err != nil {
		t.Fatalf("ProvideShare #3: %v", err)
	}
	if !unsealed {
		t.Fatal("should be unsealed after 3 shares")
	}
	if !v.IsUnsealed() {
		t.Fatal("state should be Unsealed")
	}
	// 达阈值尝试后池子应被清空。
	if v.CollectedCount() != 0 {
		t.Fatalf("collected shares should be wiped after combine, got %d", v.CollectedCount())
	}

	// 验证 master key 还原正确。
	var got []byte
	err = v.MasterKeyRef(func(k *memguard.SecureBuffer) error {
		return k.WithKey(func(s []byte) error {
			got = append(got, s...)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("MasterKeyRef: %v", err)
	}
	if !bytes.Equal(got, secretCopy) {
		t.Fatal("reconstructed master key mismatch")
	}
	for i := range got {
		got[i] = 0
	}
}

// TestVaultState_ProvideShare_RejectAfterUnseal 验证 Unsealed 后多余 share 被拒绝。
func TestVaultState_ProvideShare_RejectAfterUnseal(t *testing.T) {
	secret := newTestSecret(t, 16)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	v := NewVaultState(5, 3, 0)
	for i := 0; i < 3; i++ {
		_, _ = v.ProvideShare(shares[i])
	}
	if !v.IsUnsealed() {
		t.Fatal("should be unsealed")
	}

	// 提交第 4 份：应被拒绝。
	unsealed, err := v.ProvideShare(shares[3])
	if err == nil {
		t.Fatal("expected error on extra share after unseal")
	}
	if !unsealed {
		t.Fatal("unsealed should be true (already unsealed)")
	}
}

// TestVaultState_ProvideShare_Concurrent 验证多 goroutine 并发 ProvideShare 不死锁，
// 且最终恰好 Unseal 一次。
func TestVaultState_ProvideShare_Concurrent(t *testing.T) {
	secret := newTestSecret(t, 32)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	v := NewVaultState(5, 3, 0)

	// 同时提交 5 份（多于 threshold），期望恰好一次成功触发 Unseal，无死锁。
	var wg sync.WaitGroup
	var (
		mu            sync.Mutex
		successCount  int // 触发 Unseal 的那次
		rejectedCount int // 已 Unsealed 后被拒的
		pendingCount  int // 提交了但未触发（池子未达阈值）
	)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			unsealed, err := v.ProvideShare(shares[idx])
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && unsealed:
				successCount++
			case err == nil && !unsealed:
				pendingCount++
			case err != nil:
				// 已 Unsealed 后再调用会返回 (true, err)；
				// 其他错误也算 reject。
				rejectedCount++
			}
		}(i)
	}

	// 加超时保护，防止死锁挂死测试。
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ProvideShare concurrent test timed out (possible deadlock)")
	}

	if !v.IsUnsealed() {
		t.Fatal("should be unsealed after 5 concurrent shares")
	}
	// 恰好一次成功（第一个达阈值的 goroutine 触发，其余被拒绝）。
	if successCount != 1 {
		t.Fatalf("successCount = %d, want 1", successCount)
	}
	// 其余 4 个：要么被 reject（已 Unsealed 后调用），要么 pending（未达阈值时调用）。
	// 不做精确断言，只验证总和。
	if successCount+rejectedCount+pendingCount != 5 {
		t.Fatalf("total = %d, want 5", successCount+rejectedCount+pendingCount)
	}
}

// TestVaultState_Seal_ClearsMasterKey 验证 Seal() 后 Master Key 被 Wipe。
func TestVaultState_Seal_ClearsMasterKey(t *testing.T) {
	secret := newTestSecret(t, 16)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	v := NewVaultState(5, 3, 0)
	for i := 0; i < 3; i++ {
		_, _ = v.ProvideShare(shares[i])
	}
	if !v.IsUnsealed() {
		t.Fatal("should be unsealed")
	}

	v.Seal(context.Background())
	if !v.IsSealed() {
		t.Fatal("should be sealed after Seal()")
	}
	if v.CollectedCount() != 0 {
		t.Fatal("collected shares should be cleared after Seal()")
	}

	// Seal 后 MasterKeyRef 应返回 error。
	err = v.MasterKeyRef(func(k *memguard.SecureBuffer) error {
		return nil
	})
	if err == nil {
		t.Fatal("MasterKeyRef should fail after Seal()")
	}
}

// TestVaultState_MasterKeyEqual 验证 ConstantTimeCompare 路径。
func TestVaultState_MasterKeyEqual(t *testing.T) {
	secret := newTestSecret(t, 32)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	v := NewVaultState(5, 3, 0)
	for i := 0; i < 3; i++ {
		_, _ = v.ProvideShare(shares[i])
	}

	// 同一 secret 应判等。
	if !v.MasterKeyEqual(secret) {
		t.Fatal("MasterKeyEqual should return true for the same secret")
	}

	// 不同 secret 应判不等。
	other := newTestSecret(t, 32)
	if v.MasterKeyEqual(other) {
		t.Fatal("MasterKeyEqual should return false for a different secret")
	}

	// Seal 后应判不等。
	v.Seal(context.Background())
	if v.MasterKeyEqual(secret) {
		t.Fatal("MasterKeyEqual should return false after Seal()")
	}
}

// 编译期保证 errors 包被使用（供未来错误断言扩展）。
var _ = errors.New
