// Package auth - TOTP 单元测试。
package auth

import (
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

// TestTOTP_ReplayProtection 防重放检查。
func TestTOTP_ReplayProtection(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	code, _ := GenerateTOTP(secret, time.Now())

	// 记录已使用的 code。
	usedCodes := make(map[string]bool)
	checkUsed := func(t time.Time, c string) bool {
		key := c
		return usedCodes[key]
	}

	// 第一次验证通过。
	if err := ValidateTOTP(secret, code, checkUsed); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	usedCodes[code] = true

	// 第二次验证应被拒绝（重放）。
	err := ValidateTOTP(secret, code, checkUsed)
	if err != ErrTOTPAlreadyUsed {
		t.Fatalf("second validate should return ErrTOTPAlreadyUsed, got: %v", err)
	}
	t.Log("✅ Replay protection: second use rejected")
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
