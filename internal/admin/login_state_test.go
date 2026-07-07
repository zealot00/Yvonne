// Package admin - 登录失败计数 + 锁定 单元测试（v1.4.2）。
//
// 验证：
//  1. IncFailed 累加到 3 后 IsLocked 返回 true
//  2. ResetFailed 清零失败计数
//  3. 锁定 30 min 后自动解锁
//  4. IncFailed 线程安全（并发原子）
//  5. 不同 key 互不干扰
package admin

import (
	"sync"
	"testing"
	"time"
)

func TestLoginState_FirstFailure(t *testing.T) {
	store := NewMemoryLoginStateStore()
	if store.IsLocked("user1@1.2.3.4") {
		t.Fatal("fresh state should not be locked")
	}
	count := store.IncFailed("user1@1.2.3.4")
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
	if store.IsLocked("user1@1.2.3.4") {
		t.Fatal("1 failure should not lock")
	}
}

func TestLoginState_ThirdFailure_Locks(t *testing.T) {
	store := NewMemoryLoginStateStore()
	key := "user1@1.2.3.4"
	for i := 0; i < 3; i++ {
		store.IncFailed(key)
	}
	if !store.IsLocked(key) {
		t.Fatal("3 failures should lock")
	}
	state, ok := store.Get(key)
	if !ok {
		t.Fatal("state should exist after 3 failures")
	}
	if state.FailedCount != 3 {
		t.Fatalf("expected FailedCount 3, got %d", state.FailedCount)
	}
	if state.LockedUntil.IsZero() {
		t.Fatal("LockedUntil should be set")
	}
	// 锁定时间应该在未来 29-31 min
	delta := state.LockedUntil.Sub(time.Now())
	if delta < 29*time.Minute || delta > 31*time.Minute {
		t.Fatalf("lock duration not ~30min: %v", delta)
	}
}

func TestLoginState_Reset(t *testing.T) {
	store := NewMemoryLoginStateStore()
	key := "user1@1.2.3.4"
	store.IncFailed(key)
	store.IncFailed(key)
	store.ResetFailed(key)

	state, ok := store.Get(key)
	if !ok {
		t.Fatal("state should exist after Reset")
	}
	if state.FailedCount != 0 {
		t.Fatalf("expected FailedCount 0 after reset, got %d", state.FailedCount)
	}
	if !state.LockedUntil.IsZero() {
		t.Fatal("LockedUntil should be cleared after reset")
	}
	if store.IsLocked(key) {
		t.Fatal("should not be locked after reset")
	}
}

func TestLoginState_LockExpiresAfter30Min(t *testing.T) {
	store := NewMemoryLoginStateStore()
	key := "user1@1.2.3.4"
	for i := 0; i < 3; i++ {
		store.IncFailed(key)
	}
	if !store.IsLocked(key) {
		t.Fatal("should be locked")
	}

	// 把 LockedUntil 拨到 31 分钟前（已过期）
	state, _ := store.Get(key)
	state.LockedUntil = time.Now().Add(-31 * time.Minute)

	if store.IsLocked(key) {
		t.Fatal("lock should expire after 30 min")
	}
}

func TestLoginState_DifferentKeysIndependent(t *testing.T) {
	store := NewMemoryLoginStateStore()
	for i := 0; i < 3; i++ {
		store.IncFailed("user1@1.2.3.4")
	}
	// user2 仍然是干净的
	if store.IsLocked("user2@5.6.7.8") {
		t.Fatal("user2 should not be locked by user1's failures")
	}
	count := store.IncFailed("user2@5.6.7.8")
	if count != 1 {
		t.Fatalf("user2 count should be 1, got %d", count)
	}
}

func TestLoginState_ConcurrentIncFailed(t *testing.T) {
	store := NewMemoryLoginStateStore()
	key := "concurrent@user"
	const goroutines = 50
	const incPerGoroutine = 10

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incPerGoroutine; j++ {
				store.IncFailed(key)
			}
		}()
	}
	wg.Wait()

	state, ok := store.Get(key)
	if !ok {
		t.Fatal("state should exist")
	}
	expected := goroutines * incPerGoroutine
	if state.FailedCount != expected {
		t.Fatalf("expected %d failures, got %d (lost updates!)", expected, state.FailedCount)
	}
}
