// KAE 套件 stub 测试（无 kae 构建标签时验证回退行为）。
package crypto

import (
	"testing"
)

// TestKAESuite_Unavailable 无 kae 标签时 NewKAESuite 返回 error。
func TestKAESuite_Unavailable(t *testing.T) {
	_, err := NewKAESuite(SuiteGMSM)
	if err == nil {
		t.Fatal("NewKAESuite should error without -tags kae")
	}
	t.Logf("✅ KAE stub correctly errors: %v", err)
}

// TestEnsureKAAvailable_Unavailable 无 kae 标签时返回 error。
func TestEnsureKAAvailable_Unavailable(t *testing.T) {
	err := EnsureKAAvailable()
	if err == nil {
		t.Fatal("EnsureKAAvailable should error without -tags kae")
	}
	t.Logf("✅ EnsureKAAvailable correctly errors: %v", err)
}

// TestNewSuite_KAE_Fallback suite="kae" 无 kae 标签时回退失败。
func TestNewSuite_KAE_Fallback(t *testing.T) {
	_, err := NewSuite(SuiteKAE)
	if err == nil {
		t.Fatal("NewSuite(kae) should error without -tags kae")
	}
	t.Logf("✅ NewSuite(kae) correctly errors without kae tag: %v", err)
}

// TestNewSuite_Standard 仍可正常工作（KAE 不影响标准套件）。
func TestNewSuite_Standard(t *testing.T) {
	suite, err := NewSuite(SuiteStandard)
	if err != nil {
		t.Fatalf("NewSuite(standard): %v", err)
	}
	if suite == nil {
		t.Fatal("standard suite should not be nil")
	}
	if suite.Name() != "standard" {
		t.Fatalf("expected 'standard', got %q", suite.Name())
	}
	t.Logf("✅ Standard suite works alongside KAE stub")
}
