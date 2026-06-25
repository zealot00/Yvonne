package seal

import (
	"bytes"
	"context"
	"testing"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
)

// TestSoftwareKEK_RoundTrip 验证 softwareKEK 加解密往返。
func TestSoftwareKEK_RoundTrip(t *testing.T) {
	cmk, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk.Wipe()
	kek := NewSoftwareKEK(cmk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	// 保存明文副本用于验证。
	var plainCopy []byte
	_ = plainDEK.WithKey(func(d []byte) error {
		plainCopy = make([]byte, len(d))
		copy(plainCopy, d)
		return nil
	})
	defer func() {
		for i := range plainCopy {
			plainCopy[i] = 0
		}
	}()

	ciphertext, err := kek.WrapDEK(plainDEK)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(ciphertext) < 24 {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}

	decrypted, err := kek.UnwrapDEK(ciphertext)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer decrypted.Wipe()

	var decCopy []byte
	_ = decrypted.WithKey(func(d []byte) error {
		decCopy = make([]byte, len(d))
		copy(decCopy, d)
		return nil
	})
	defer func() {
		for i := range decCopy {
			decCopy[i] = 0
		}
	}()

	if !bytes.Equal(plainCopy, decCopy) {
		t.Fatal("round-trip mismatch")
	}
}

// TestSoftwareKEK_Type 验证类型。
func TestSoftwareKEK_Type(t *testing.T) {
	cmk, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk.Wipe()
	kek := NewSoftwareKEK(cmk)
	if kek.Type() != KEKTypeSoftware {
		t.Fatalf("Type = %v, want software", kek.Type())
	}
}

// TestSoftwareKEK_TamperedCiphertext 验证篡改密文解密失败。
func TestSoftwareKEK_TamperedCiphertext(t *testing.T) {
	cmk, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk.Wipe()
	kek := NewSoftwareKEK(cmk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	ct, _ := kek.WrapDEK(plainDEK)
	ct[len(ct)-1] ^= 0xFF

	_, err := kek.UnwrapDEK(ct)
	if err == nil {
		t.Fatal("tampered ciphertext should fail")
	}
}

// TestSoftwareKEK_WrongKey 验证错误 CMK 解密失败。
func TestSoftwareKEK_WrongKey(t *testing.T) {
	cmk1, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk1.Wipe()
	cmk2, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk2.Wipe()

	kek1 := NewSoftwareKEK(cmk1)
	kek2 := NewSoftwareKEK(cmk2)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	ct, _ := kek1.WrapDEK(plainDEK)

	_, err := kek2.UnwrapDEK(ct)
	if err == nil {
		t.Fatal("wrong key should fail")
	}
}

// TestHSMKEK_RoundTrip 验证 hsmKEK 加解密往返。
func TestHSMKEK_RoundTrip(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()
	kek := NewHSMKEK(backend)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	var plainCopy []byte
	_ = plainDEK.WithKey(func(d []byte) error {
		plainCopy = make([]byte, len(d))
		copy(plainCopy, d)
		return nil
	})
	defer func() {
		for i := range plainCopy {
			plainCopy[i] = 0
		}
	}()

	ct, err := kek.WrapDEK(plainDEK)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	decrypted, err := kek.UnwrapDEK(ct)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer decrypted.Wipe()

	var decCopy []byte
	_ = decrypted.WithKey(func(d []byte) error {
		decCopy = make([]byte, len(d))
		copy(decCopy, d)
		return nil
	})
	defer func() {
		for i := range decCopy {
			decCopy[i] = 0
		}
	}()

	if !bytes.Equal(plainCopy, decCopy) {
		t.Fatal("HSM KEK round-trip mismatch")
	}
}

// TestHSMKEK_Type 验证 HSM KEK 类型。
func TestHSMKEK_Type(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()
	kek := NewHSMKEK(backend)
	if kek.Type() != KEKTypeHSM {
		t.Fatalf("Type = %v, want hsm", kek.Type())
	}
}

// TestHSMKEK_TamperedCiphertext 验证 HSM 篡改检测。
func TestHSMKEK_TamperedCiphertext(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()
	kek := NewHSMKEK(backend)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	ct, _ := kek.WrapDEK(plainDEK)
	ct[len(ct)-1] ^= 0xFF

	_, err := kek.UnwrapDEK(ct)
	if err == nil {
		t.Fatal("HSM tampered ciphertext should fail")
	}
}

// TestVaultState_KEKRef 验证 VaultState.KEKRef 在 Unsealed/Sealed 状态。
func TestVaultState_KEKRef(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	v := NewVaultState(1, 1, 0)
	if err := v.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	// Unsealed → KEKRef 可用。
	called := false
	err := v.KEKRef(func(kek KEK) error {
		called = true
		if kek.Type() != KEKTypeSoftware {
			t.Fatalf("Type = %v, want software", kek.Type())
		}
		// 验证 KEK 可用。
		plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
		defer plainDEK.Wipe()
		ct, e := kek.WrapDEK(plainDEK)
		if e != nil {
			return e
		}
		_, e = kek.UnwrapDEK(ct)
		return e
	})
	if err != nil {
		t.Fatalf("KEKRef: %v", err)
	}
	if !called {
		t.Fatal("KEKRef action not called")
	}

	// Seal → KEKRef 返回 error。
	v.Seal(context.TODO())
	err = v.KEKRef(func(kek KEK) error {
		t.Fatal("should not be called when sealed")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail when sealed")
	}
}

// TestHSMUnsealer_KEKRef 验证 HSMUnsealer.KEKRef。
func TestHSMUnsealer_KEKRef(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	called := false
	err := unsealer.KEKRef(func(kek KEK) error {
		called = true
		if kek.Type() != KEKTypeHSM {
			t.Fatalf("Type = %v, want hsm", kek.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("KEKRef: %v", err)
	}
	if !called {
		t.Fatal("KEKRef action not called")
	}

	// Seal 后 KEKRef 失败。
	unsealer.Seal(context.TODO())
	err = unsealer.KEKRef(func(kek KEK) error {
		t.Fatal("should not be called after seal")
		return nil
	})
	if err == nil {
		t.Fatal("KEKRef should fail after seal")
	}
}

// TestSoftwareKEK_FormatCompatibility 验证 softwareKEK 与 crypto.EncryptGCM 密文格式兼容。
func TestSoftwareKEK_FormatCompatibility(t *testing.T) {
	cmk, _ := memguard.NewSecureBufferFromRandom(32)
	defer cmk.Wipe()
	kek := NewSoftwareKEK(cmk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	// 用 KEK wrap。
	ctKEK, err := kek.WrapDEK(plainDEK)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// 用 crypto.DecryptGCM 解（应成功，格式一致）。
	dec, err := decryptGCMForTest(cmk, ctKEK)
	if err != nil {
		t.Fatalf("crypto.DecryptGCM should accept softwareKEK ciphertext: %v", err)
	}
	defer dec.Wipe()
}

// decryptGCMForTest 直接调 crypto.DecryptGCM（用于格式兼容性验证）。
func decryptGCMForTest(key *memguard.SecureBuffer, ct []byte) (*memguard.SecureBuffer, error) {
	return crypto.DecryptGCM(key, ct)
}
