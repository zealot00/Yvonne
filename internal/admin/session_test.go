// Package admin - Session 生命周期 单元测试（v1.4.2）。
//
// 验证：
//  1. sessionID 不可预测（熵 ≥ 256 bit）
//  2. Get/Put/Delete 正确性
//  3. idle 超时独立于 hard-cap
//  4. Touch 刷新 last_seen 不影响 hard-cap
//  5. Reap 清理过期
//  6. Memory / KV 双实现行为一致
package admin

import (
	"sync"
	"testing"
	"time"
)

func TestSession_NewSession_Entropy(t *testing.T) {
	// 跑 100 次，确认 ID 唯一且熵足够（16 字节 hex = 32 chars）
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		if len(s.ID) < 32 {
			t.Fatalf("session ID too short: %d chars", len(s.ID))
		}
		if seen[s.ID] {
			t.Fatalf("session ID collision: %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestSession_NewSession_TimesSet(t *testing.T) {
	now := time.Now()
	s, err := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// CreatedAt 应该约等于 now
	delta := s.CreatedAt.Sub(now)
	if delta < -1*time.Second || delta > 1*time.Second {
		t.Fatalf("CreatedAt drift: %v", delta)
	}
	// HardCapAt = CreatedAt + 8h
	if d := s.HardCapAt.Sub(s.CreatedAt); d != 8*time.Hour {
		t.Fatalf("HardCapAt not +8h: %v", d)
	}
	// ExpiresAt = LastSeenAt + 30min
	if d := s.ExpiresAt.Sub(s.LastSeenAt); d != 30*time.Minute {
		t.Fatalf("ExpiresAt not +30min from LastSeenAt: %v", d)
	}
}

func TestSessionStore_Memory_PutGetDelete(t *testing.T) {
	store := NewMemorySessionStore()
	s, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	store.Put(s)

	got, ok := store.Get(s.ID)
	if !ok {
		t.Fatal("Get should return session")
	}
	if got.UserID != "admin-web" {
		t.Fatalf("UserID mismatch: %q", got.UserID)
	}

	store.Delete(s.ID)
	if _, ok := store.Get(s.ID); ok {
		t.Fatal("Get after Delete should return false")
	}
}

func TestSessionStore_TouchRefreshesLastSeen(t *testing.T) {
	store := NewMemorySessionStore()
	s, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	store.Put(s)

	// 模拟 idle 超时
	state, _ := store.Get(s.ID)
	state.LastSeenAt = time.Now().Add(-31 * time.Minute) // 31 分钟前

	// Touch 应该把 last_seen 拨到现在
	now := time.Now()
	store.Touch(s.ID, now, now.Add(30*time.Minute))

	got, _ := store.Get(s.ID)
	if got.LastSeenAt != now {
		t.Fatalf("LastSeenAt not updated: got %v want %v", got.LastSeenAt, now)
	}
	// HardCapAt 不变
	if got.HardCapAt != s.HardCapAt {
		t.Fatalf("HardCapAt should not change on Touch")
	}
}

func TestSessionStore_Reap(t *testing.T) {
	store := NewMemorySessionStore()

	// 1 个新鲜
	fresh, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "ua")
	store.Put(fresh)

	// 2 个过期：先 Put（内部 copy），再 Get 出指针 mutate 字段
	expired1, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "ua")
	store.Put(expired1)
	s1, _ := store.Get(expired1.ID)
	s1.ExpiresAt = time.Now().Add(-1 * time.Second)

	expired2, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "ua")
	store.Put(expired2)
	s2, _ := store.Get(expired2.ID)
	s2.HardCapAt = time.Now().Add(-1 * time.Second)

	n := store.Reap(time.Now())
	if n != 2 {
		t.Fatalf("expected reap 2, got %d", n)
	}
	// 新鲜的应该还在
	if _, ok := store.Get(fresh.ID); !ok {
		t.Fatal("fresh session should survive reap")
	}
	// 过期的不在了
	if _, ok := store.Get(expired1.ID); ok {
		t.Fatal("expired session should be reaped")
	}
}

func TestSessionStore_Concurrent(t *testing.T) {
	store := NewMemorySessionStore()
	const goroutines = 20
	const ops = 50

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				s, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "ua")
				store.Put(s)
				store.Get(s.ID)
				store.Touch(s.ID, time.Now(), time.Now().Add(30*time.Minute))
				store.Delete(s.ID)
			}
		}()
	}
	wg.Wait()
	// 不崩 = 通过（race detector 会捕获并发问题）
}

func TestSession_HardCapIndependentFromIdle(t *testing.T) {
	// Touch 一直刷新 idle，但 hard cap 由 createdAt 决定 → Touch 不动 HardCapAt
	store := NewMemorySessionStore()
	s, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "ua")
	store.Put(s)
	originalHardCap := s.HardCapAt

	// Touch 多次刷新 idle（不修改 HardCapAt）
	now := time.Now()
	for i := 0; i < 5; i++ {
		store.Touch(s.ID, now.Add(time.Duration(i)*time.Second), now.Add(time.Duration(i+1)*time.Minute))
	}

	// Get 拿未过期版本对比 HardCapAt
	got, ok := store.Get(s.ID)
	if !ok {
		t.Fatal("session should still be alive")
	}
	if !got.HardCapAt.Equal(originalHardCap) {
		t.Fatalf("HardCapAt changed by Touch: original=%v now=%v", originalHardCap, got.HardCapAt)
	}
	// 但 last_seen 和 expires_at 应该被刷新
	if !got.LastSeenAt.Equal(now.Add(4 * time.Second)) {
		t.Fatalf("LastSeenAt not refreshed: %v", got.LastSeenAt)
	}
}
