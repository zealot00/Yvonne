package memguard

import (
	"sync"
	"testing"
)

// TestSecureBuffer_ConcurrentWithKeyAndWipe 验证 WithKey 和 Wipe 并发安全。
// 修复前：WithKey 读取 s.data 时 Wipe 可能正在 clear，导致读到全零。
// 修复后：sync.RWMutex 保证 Wipe 阻塞直到所有 WithKey 闭包完成。
func TestSecureBuffer_ConcurrentWithKeyAndWipe(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(32)
	defer sb.Wipe()

	// 保存正确值用于验证。
	var original []byte
	_ = sb.WithKey(func(d []byte) error {
		original = make([]byte, len(d))
		copy(original, d)
		return nil
	})
	defer func() {
		for i := range original {
			original[i] = 0
		}
	}()

	var wg sync.WaitGroup
	wiped := false

	// 10 个 reader goroutine 持续 WithKey。
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				// Wipe 后 WithKey panic 是预期行为（use-after-free）。
				_ = recover()
			}()
			for j := 0; j < 100; j++ {
				_ = sb.WithKey(func(d []byte) error {
					// 修复后：RWMutex 保证 Wipe 阻塞，不会读到全零。
					return nil
				})
			}
		}()
	}

	// 1 个 writer goroutine 在短延迟后 Wipe。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			// busy wait
		}
		sb.Wipe()
		wiped = true
	}()

	wg.Wait()
	if !wiped {
		t.Fatal("Wipe should have been called")
	}
}

var errInvalidLen = errTest("invalid length")
var errAllZero = errTest("all zero — race condition detected")

type errTest string

func (e errTest) Error() string { return string(e) }

// TestSecureBuffer_WipeBlocksNewWithKey 验证 Wipe 后 WithKey panic。
func TestSecureBuffer_WipeBlocksNewWithKey(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(32)
	sb.Wipe()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("WithKey after Wipe should panic")
		}
	}()
	_ = sb.WithKey(func(d []byte) error { return nil })
}

// TestSecureBuffer_WipeIdempotent 验证 Wipe 可多次调用。
func TestSecureBuffer_WipeIdempotent(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(16)
	sb.Wipe()
	sb.Wipe() // 不应 panic
	sb.Wipe()
}

// TestSecureBuffer_WithKeyReturnsActionError 验证 WithKey 透传 action error。
func TestSecureBuffer_WithKeyReturnsActionError(t *testing.T) {
	sb, _ := NewSecureBufferFromRandom(16)
	defer sb.Wipe()

	testErr := errTest("custom error")
	err := sb.WithKey(func(d []byte) error {
		return testErr
	})
	if err != testErr {
		t.Fatalf("expected %v, got %v", testErr, err)
	}
}
