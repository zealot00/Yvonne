package memguard

import (
	"bytes"
	"errors"
	"testing"
)

// TestGenerateSecureRandom_Distinct 验证 CSPRNG 连续两次输出不相同。
// 若失败，说明熵源可能被降级、缓存或破坏——对 KMS 而言是致命的。
func TestGenerateSecureRandom_Distinct(t *testing.T) {
	a, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom(32): unexpected error: %v", err)
	}
	b, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom(32): unexpected error: %v", err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("unexpected lengths: len(a)=%d len(b)=%d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two consecutive 32-byte CSPRNG outputs are identical; entropy source may be compromised")
	}
}

// TestSecureBuffer_WipeZeroesMemory 验证 Wipe 后底层内存全部被清零。
//
// 验证思路：在 Wipe 之前通过 WithKey 拿到底层数组的引用（切片是引用类型），
// Wipe 之后该引用仍指向同一段底层数组，遍历检查应全为 0x00。
// 同时验证 NewSecureBuffer 已清零入参 src。
func TestSecureBuffer_WipeZeroesMemory(t *testing.T) {
	// 用固定明文便于事后检查长度与清零效果。
	plaintext := []byte("super-secret-master-key-value!!") // 30 bytes
	originalLen := len(plaintext)

	sb := NewSecureBuffer(plaintext)

	// 断言 1：入参 src 已被 NewSecureBuffer 清零。
	for i, b := range plaintext {
		if b != 0 {
			t.Fatalf("source slice not zeroed at index %d (got 0x%x); plaintext may linger outside SecureBuffer", i, b)
		}
	}

	// 在 Wipe 之前，通过 WithKey 拿到底层数组引用，用于事后验证。
	var ref []byte
	if err := sb.WithKey(func(secret []byte) error {
		ref = secret // ref 与 sb.data 共享底层数组
		return nil
	}); err != nil {
		t.Fatalf("WithKey returned error: %v", err)
	}
	if len(ref) != originalLen {
		t.Fatalf("ref length = %d, want %d", len(ref), originalLen)
	}

	sb.Wipe()

	if !sb.IsDestroyed() {
		t.Fatal("IsDestroyed() = false after Wipe, want true")
	}
	for i, b := range ref {
		if b != 0 {
			t.Fatalf("byte at index %d = 0x%x after Wipe, expected 0x00", i, b)
		}
	}
}

// TestSecureBuffer_WithKeyAfterWipePanics 验证 Wipe 之后再调用 WithKey
// 必然触发 panic（use-after-free 防御）。
func TestSecureBuffer_WithKeyAfterWipePanics(t *testing.T) {
	sb, err := NewSecureBufferFromRandom(16)
	if err != nil {
		t.Fatalf("NewSecureBufferFromRandom(16): %v", err)
	}
	sb.Wipe()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on use-after-free, but WithKey did not panic")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is not string: %T (%v)", r, r)
		}
		const want = "FATAL: Use after free in SecureBuffer"
		if msg != want {
			t.Fatalf("panic message = %q, want %q", msg, want)
		}
	}()

	_ = sb.WithKey(func(secret []byte) error {
		t.Fatal("action must never be invoked on a wiped SecureBuffer")
		return nil
	})
}

// TestGenerateSecureRandom_NegativeSize 验证负数 size 报错。
func TestGenerateSecureRandom_NegativeSize(t *testing.T) {
	_, err := GenerateSecureRandom(-1)
	if err == nil {
		t.Fatal("GenerateSecureRandom(-1) should fail")
	}
}

// TestGenerateSecureRandom_ZeroSize 验证 size=0 返回空切片。
func TestGenerateSecureRandom_ZeroSize(t *testing.T) {
	b, err := GenerateSecureRandom(0)
	if err != nil {
		t.Fatalf("GenerateSecureRandom(0): %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("len = %d, want 0", len(b))
	}
}

// TestSecureBuffer_Len 验证 Len 方法。
func TestSecureBuffer_Len(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(32)
	defer sb.Wipe()
	if sb.Len() != 32 {
		t.Fatalf("Len = %d, want 32", sb.Len())
	}
	sb.Wipe()
	if sb.Len() != 0 {
		t.Fatalf("Len after Wipe = %d, want 0", sb.Len())
	}
}

// TestSecureBuffer_Wipe_Idempotent 验证 Wipe 可重入。
func TestSecureBuffer_Wipe_Idempotent(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(16)
	sb.Wipe()
	sb.Wipe() // 不应 panic
	if !sb.IsDestroyed() {
		t.Fatal("should be destroyed after double Wipe")
	}
}

// TestSecureBuffer_WithKey_Error 验证闭包返回 error 透传。
func TestSecureBuffer_WithKey_Error(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(8)
	defer sb.Wipe()
	wantErr := errors.New("sentinel")
	err := sb.WithKey(func(secret []byte) error {
		return wantErr
	})
	if err != wantErr {
		t.Fatalf("WithKey should propagate error: got %v, want %v", err, wantErr)
	}
}
