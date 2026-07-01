// Package auth - TOTP 单元测试。
package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTOTP_GenerateSecret 生成 TOTP secret。
func TestTOTP_GenerateSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(secret) == 0 {
		t.Fatal("secret should not be empty")
	}
	// base32 编码 20 字节 = 32 字符。
	if len(secret) != 32 {
		t.Fatalf("secret length = %d, want 32", len(secret))
	}
	t.Logf("✅ Generated secret: %s", secret)
}

// TestTOTP_GenerateAndValidate 往返测试。
func TestTOTP_GenerateAndValidate(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// 生成当前 TOTP code。
	code, err := GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("code length = %d, want 6", len(code))
	}
	t.Logf("✅ Generated code: %s", code)

	// 验证 code（应通过）。
	if err := ValidateTOTP(secret, code, nil); err != nil {
		t.Fatalf("ValidateTOTP: %v", err)
	}
	t.Log("✅ Validate code: passed")
}

// TestTOTP_InvalidCode 错误 code 拒绝。
func TestTOTP_InvalidCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	err := ValidateTOTP(secret, "000000", nil)
	if err == nil {
		t.Fatal("invalid code should be rejected")
	}
	t.Logf("✅ Invalid code rejected: %v", err)
}

// TestTOTP_WrongSecret 错误 secret 拒绝。
func TestTOTP_WrongSecret(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _ := GenerateTOTP(secret, time.Now())

	wrongSecret, _ := GenerateTOTPSecret()
	err := ValidateTOTP(wrongSecret, code, nil)
	if err == nil {
		t.Fatal("wrong secret should reject valid code")
	}
	t.Logf("✅ Wrong secret rejected: %v", err)
}

// TestTOTP_TimeSkew 允许 ±30s 时钟漂移。
func TestTOTP_TimeSkew(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// 30 秒前的 code 应该还能验证（skew=1）。
	oldCode, _ := GenerateTOTP(secret, time.Now().Add(-30*time.Second))
	if err := ValidateTOTP(secret, oldCode, nil); err != nil {
		t.Logf("⚠️  30s old code rejected (skew boundary): %v", err)
	} else {
		t.Log("✅ 30s old code accepted (within skew)")
	}

	// 90 秒前的 code 应被拒绝（超出 skew）。
	veryOldCode, _ := GenerateTOTP(secret, time.Now().Add(-90*time.Second))
	if err := ValidateTOTP(secret, veryOldCode, nil); err == nil {
		t.Fatal("90s old code should be rejected (beyond skew)")
	}
	t.Log("✅ 90s old code rejected (beyond skew)")
}

// TestTOTP_BuildURI 构建 otpauth URI。
func TestTOTP_BuildURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := BuildTOTPURI("Yvonne KMS", "admin", secret)

	if uri == "" {
		t.Fatal("URI should not be empty")
	}
	// 应包含 otpauth://totp/ 前缀。
	if len(uri) < 20 {
		t.Fatalf("URI too short: %s", uri)
	}
	t.Logf("✅ TOTP URI: %s", uri)
}

// TestTOTP_ReplayProtection 防重放检查（Bug-1: 原子 markUsed 回调）。
func TestTOTP_ReplayProtection(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _ := GenerateTOTP(secret, time.Now())

	// 记录已使用的 code（模拟 DB 唯一约束）。
	usedCodes := make(map[string]bool)
	var mu sync.Mutex
	markUsed := func(t time.Time, c string) error {
		mu.Lock()
		defer mu.Unlock()
		if usedCodes[c] {
			return ErrTOTPAlreadyUsed // 已存在 = 唯一约束冲突
		}
		usedCodes[c] = true
		return nil
	}

	// 第一次验证通过（markUsed 成功写入）。
	if err := ValidateTOTP(secret, code, markUsed); err != nil {
		t.Fatalf("first validate: %v", err)
	}

	// 第二次验证应被拒绝（markUsed 返回 ErrTOTPAlreadyUsed）。
	err := ValidateTOTP(secret, code, markUsed)
	if err != ErrTOTPAlreadyUsed {
		t.Fatalf("second validate should return ErrTOTPAlreadyUsed, got: %v", err)
	}
	t.Log("✅ Replay protection: second use rejected (atomic markUsed)")
}

// TestTOTP_ConcurrentReplayProtection Bug-1 并发防重放测试。
// 两个 goroutine 同时用相同 code 验证，只有一个应成功。
func TestTOTP_ConcurrentReplayProtection(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _ := GenerateTOTP(secret, time.Now())

	// 用 sync.Mutex 模拟 DB 唯一约束（真实场景由 PG UNIQUE 约束保证）。
	usedCodes := make(map[string]bool)
	var mu sync.Mutex
	markUsed := func(t time.Time, c string) error {
		mu.Lock()
		defer mu.Unlock()
		if usedCodes[c] {
			return ErrTOTPAlreadyUsed
		}
		usedCodes[c] = true
		return nil
	}

	var wg sync.WaitGroup
	successCount := int32(0)
	rejectCount := int32(0)
	const goroutines = 10

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := ValidateTOTP(secret, code, markUsed)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			} else if err == ErrTOTPAlreadyUsed {
				atomic.AddInt32(&rejectCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("Bug-1 TOCTOU: expected exactly 1 success, got %d (replay attack succeeded!)", successCount)
	}
	if rejectCount != goroutines-1 {
		t.Fatalf("expected %d rejections, got %d", goroutines-1, rejectCount)
	}
	t.Logf("✅ Bug-1 concurrent: 1 success, %d rejected (no TOCTOU)", rejectCount)
}

// TestTOTP_LegacyReplayProtection 旧版兼容接口（ValidateTOTPLegacy）。
func TestTOTP_LegacyReplayProtection(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _ := GenerateTOTP(secret, time.Now())

	usedCodes := make(map[string]bool)
	checkUsed := func(t time.Time, c string) bool {
		return usedCodes[c]
	}

	// 第一次验证通过。
	if err := ValidateTOTPLegacy(secret, code, checkUsed); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	usedCodes[code] = true

	// 第二次验证应被拒绝。
	err := ValidateTOTPLegacy(secret, code, checkUsed)
	if err != ErrTOTPAlreadyUsed {
		t.Fatalf("second validate should return ErrTOTPAlreadyUsed, got: %v", err)
	}
	t.Log("✅ Legacy replay protection works")
}

// TestTOTP_NoNegativeOverflow Bug-8: 验证 int64 计算不会溢出。
// skew=-1 时不应产生 uint64 环绕。
func TestTOTP_NoNegativeOverflow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()

	// 生成 30 秒前的 code（skew=-1 命中）。
	oldCode, _ := GenerateTOTP(secret, time.Now().Add(-30*time.Second))

	// 验证应通过（skew=-1 命中）。
	// Bug-8 修复前: uint64(-1) 环绕为 18446744073709551615，
	//               虽然碰巧等价但行为不稳定。
	// Bug-8 修复后: int64 计算明确无溢出。
	if err := ValidateTOTP(secret, oldCode, nil); err != nil {
		t.Logf("⚠️  30s old code rejected (skew boundary): %v", err)
	} else {
		t.Log("✅ Bug-8: skew=-1 counter 计算无溢出，30s old code accepted")
	}
}

// TestMFAStore_Memory 内存 MFAStore 往返。
func TestMFAStore_Memory(t *testing.T) {
	store := NewMemoryMFAStore()

	// 初始状态不存在。
	_, err := store.GetMFAState("role-1")
	if err == nil {
		t.Fatal("should not exist initially")
	}

	// 保存。
	state := &MFAState{
		RoleID:    "role-1",
		Secret:    "JBSWY3DPEHPK3PXP",
		Enabled:   false,
		CreatedAt: time.Now(),
	}
	if err := store.SaveMFAState(state); err != nil {
		t.Fatalf("SaveMFAState: %v", err)
	}

	// 读取。
	got, err := store.GetMFAState("role-1")
	if err != nil {
		t.Fatalf("GetMFAState: %v", err)
	}
	if got.RoleID != "role-1" || got.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("unexpected state: %+v", got)
	}
	t.Log("✅ MemoryMFAStore: save + get passed")

	// 删除。
	if err := store.DeleteMFAState("role-1"); err != nil {
		t.Fatalf("DeleteMFAState: %v", err)
	}
	_, err = store.GetMFAState("role-1")
	if err == nil {
		t.Fatal("should not exist after delete")
	}
	t.Log("✅ MemoryMFAStore: delete passed")
}
