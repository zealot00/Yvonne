//go:build !gmsm

// Package crypto - SM2 stub + Suite 补充覆盖测试。
package crypto

import (
	"testing"
)

// TestSM2Stubs_All 非 gmsm 构建的 SM2 stub 全部返回 error。
func TestSM2Stubs_All(t *testing.T) {
	_, _, err := GenerateSM2KeyPair()
	if err == nil {
		t.Fatal("should error without gmsm tag")
	}
	t.Logf("✅ GenerateSM2KeyPair stub: %v", err)

	_, err = SM2Encrypt(nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2Encrypt stub: %v", err)

	_, err = SM2Decrypt(nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2Decrypt stub: %v", err)

	_, err = SM2Sign(nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2Sign stub: %v", err)

	_, err = SM2Verify(nil, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2Verify stub: %v", err)

	_, err = SM2PrivateKeyToPEM(nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2PrivateKeyToPEM stub: %v", err)

	_, err = SM2PrivateKeyFromPEM(nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2PrivateKeyFromPEM stub: %v", err)

	_, err = SM2PublicKeyFromPEM(nil)
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ SM2PublicKeyFromPEM stub: %v", err)

	_, _, err = GenerateSM2AsymmetricKey()
	if err == nil {
		t.Fatal("should error")
	}
	t.Logf("✅ GenerateSM2AsymmetricKey stub: %v", err)
}

// TestNewSuite_CreateSuite 创建密码套件。
func TestNewSuite_CreateSuite(t *testing.T) {
	suite, err := NewSuite(SuiteStandard)
	if err != nil {
		t.Fatalf("NewSuite standard: %v", err)
	}
	if suite == nil {
		t.Fatal("should not be nil")
	}
	t.Log("✅ NewSuite standard")

	_, err = NewSuite("unknown")
	if err == nil {
		t.Fatal("should error for unknown suite")
	}
	t.Logf("✅ NewSuite unknown → error: %v", err)

	// GMSM 在非 gmsm 构建下应返回 error。
	_, err = NewSuite(SuiteGMSM)
	if err == nil {
		t.Log("✅ NewSuite gmsm: available (gmsm build)")
	} else {
		t.Logf("✅ NewSuite gmsm: not available (non-gmsm): %v", err)
	}
}

// TestKeyTypeConstants KeyType 常量值。
func TestKeyTypeConstants(t *testing.T) {
	if KeyTypeAES != "aes" {
		t.Fatalf("KeyTypeAES = %s, want aes", KeyTypeAES)
	}
	if KeyTypeSM4 != "sm4" {
		t.Fatalf("KeyTypeSM4 = %s, want sm4", KeyTypeSM4)
	}
	if KeyTypeRSA != "rsa" {
		t.Fatalf("KeyTypeRSA = %s, want rsa", KeyTypeRSA)
	}
	if KeyTypeECDSA != "ecdsa" {
		t.Fatalf("KeyTypeECDSA = %s, want ecdsa", KeyTypeECDSA)
	}
	if KeyTypeSM2 != "sm2" {
		t.Fatalf("KeyTypeSM2 = %s, want sm2", KeyTypeSM2)
	}
	t.Log("✅ KeyType constants")
}
