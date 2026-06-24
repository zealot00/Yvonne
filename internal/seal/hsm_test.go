package seal

import (
	"context"
	"testing"

	"yvonne/internal/memguard"
)

// TestMockHSMBackend_WrapUnwrap 验证 Mock HSM 加解密往返。
func TestMockHSMBackend_WrapUnwrap(t *testing.T) {
	backend, err := NewMockHSMBackend()
	if err != nil {
		t.Fatalf("NewMockHSMBackend: %v", err)
	}
	defer backend.Close()

	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext, err := backend.Wrap(plaintext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	decrypted, err := backend.Unwrap(ciphertext)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestMockHSMBackend_DifferentCiphertext 验证同一明文每次加密产生不同密文（随机 Nonce）。
func TestMockHSMBackend_DifferentCiphertext(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	pt := []byte("same-plaintext-32-bytes-exactly!!")

	ct1, _ := backend.Wrap(pt)
	ct2, _ := backend.Wrap(pt)

	if string(ct1) == string(ct2) {
		t.Fatal("same plaintext should produce different ciphertext (random nonce)")
	}
}

// TestMockHSMBackend_TamperedCiphertext 验证篡改密文后解密失败。
func TestMockHSMBackend_TamperedCiphertext(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	pt := []byte("tamper-test-32-bytes-exactly-here")
	ct, _ := backend.Wrap(pt)

	ct[len(ct)-1] ^= 0xFF
	_, err := backend.Unwrap(ct)
	if err == nil {
		t.Fatal("tampered ciphertext should fail unwrap")
	}
}

// TestHSMUnsealer_BackendRef 验证通过 BackendRef 访问 CryptoBackend。
func TestHSMUnsealer_BackendRef(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	plaintext := []byte("backend-ref-test-32-bytes-here!!")

	var wrapped []byte
	err := unsealer.BackendRef(func(b CryptoBackend) error {
		var e error
		wrapped, e = b.Wrap(plaintext)
		return e
	})
	if err != nil {
		t.Fatalf("BackendRef Wrap: %v", err)
	}

	var unwrapped []byte
	err = unsealer.BackendRef(func(b CryptoBackend) error {
		var e error
		unwrapped, e = b.Unwrap(wrapped)
		return e
	})
	if err != nil {
		t.Fatalf("BackendRef Unwrap: %v", err)
	}

	if string(unwrapped) != string(plaintext) {
		t.Fatal("BackendRef round-trip mismatch")
	}
}

// TestHSMUnsealer_MasterKeyRefRejected 验证 HSM 模式下 MasterKeyRef 返回 error。
func TestHSMUnsealer_MasterKeyRefRejected(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	err := unsealer.MasterKeyRef(func(key *memguard.SecureBuffer) error {
		t.Fatal("should not be called in HSM mode")
		return nil
	})
	if err == nil {
		t.Fatal("MasterKeyRef should fail in HSM mode")
	}
}

// TestHSMUnsealer_SealBreaksSession 验证 Seal 后 BackendRef 失败。
func TestHSMUnsealer_SealBreaksSession(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	if unsealer.IsSealed() {
		t.Fatal("should start unsealed")
	}

	unsealer.Seal(context.Background())

	if !unsealer.IsSealed() {
		t.Fatal("should be sealed after Seal")
	}

	err := unsealer.BackendRef(func(b CryptoBackend) error {
		return nil
	})
	if err == nil {
		t.Fatal("BackendRef should fail after Seal")
	}
}

// TestHSMUnsealer_ProvideShareRejected 验证 HSM 模式拒绝 Shamir。
func TestHSMUnsealer_ProvideShareRejected(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	_, err := unsealer.ProvideShare([]byte{0x01})
	if err == nil {
		t.Fatal("ProvideShare should fail in HSM mode")
	}
}

// TestHSMUnsealer_State 验证状态返回。
func TestHSMUnsealer_State(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	if unsealer.State() != StateUnsealed {
		t.Fatalf("State = %v, want Unsealed", unsealer.State())
	}

	unsealer.Seal(context.Background())

	if unsealer.State() != StateSealed {
		t.Fatalf("State after Seal = %v, want Sealed", unsealer.State())
	}
}

// TestHSMUnsealer_EmergencySeal 验证紧急封印断开会话。
func TestHSMUnsealer_EmergencySeal(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)
	unsealer.EmergencySeal(context.Background())

	if !unsealer.IsSealed() {
		t.Fatal("should be sealed after EmergencySeal")
	}
}

// TestHSMUnsealer_ConcurrentWrapUnwrap 验证并发安全。
func TestHSMUnsealer_ConcurrentWrapUnwrap(t *testing.T) {
	backend, _ := NewMockHSMBackend()
	defer backend.Close()

	unsealer := NewHSMUnsealer(backend)

	done := make(chan error, 20)
	for i := 0; i < 10; i++ {
		go func() {
			pt := []byte("concurrent-wrap-test-32-bytes!!!")
			err := unsealer.BackendRef(func(b CryptoBackend) error {
				ct, e := b.Wrap(pt)
				if e != nil {
					return e
				}
				_, e = b.Unwrap(ct)
				return e
			})
			done <- err
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent error: %v", err)
		}
	}
}
