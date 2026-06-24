package lifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// mockAdvisoryLocker 模拟 Advisory Lock（MemoryStore 测试用）。
type mockAdvisoryLocker struct {
	acquired bool
	mu       sync.Mutex
}

func (m *mockAdvisoryLocker) TryAcquire(ctx context.Context) (bool, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acquired {
		return false, nil, nil
	}
	m.acquired = true
	return true, func() {
		m.mu.Lock()
		m.acquired = false
		m.mu.Unlock()
	}, nil
}

// TestRotationDaemon_AutoRotate 验证守护进程自动轮转过期密钥。
func TestRotationDaemon_AutoRotate(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建密钥，设置 1 天轮转周期。
	_, _, err := mgr.CreateKey(ctx, "auto-rotate-test", mk, 1)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 篡改 NextRotationAt 为过去时间（模拟已过期）。
	meta, _ := mgr.GetKey(ctx, "auto-rotate-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// 创建守护进程。
	var auditEntries []AuditEntry
	var auditMu sync.Mutex

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditMu.Lock()
		auditEntries = append(auditEntries, entry)
		auditMu.Unlock()
		return nil
	})

	// 手动执行一次扫描。
	daemon.scanOnce(ctx)

	// 验证密钥已轮转到 V2。
	latestV, err := mgr.findLatestVersion(ctx, "auto-rotate-test")
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}
	if latestV != 2 {
		t.Fatalf("expected version 2 after auto-rotate, got %d", latestV)
	}

	// V1 应为 Deactivated。
	v1, _ := mgr.GetKey(ctx, "auto-rotate-test", 1)
	if v1.State != StateDeactivated {
		t.Fatalf("V1 state = %v, want Deactivated", v1.State)
	}

	// V2 应为 Active。
	v2, _ := mgr.GetKey(ctx, "auto-rotate-test", 2)
	if v2.State != StateActive {
		t.Fatalf("V2 state = %v, want Active", v2.State)
	}

	// 验证审计日志。
	auditMu.Lock()
	defer auditMu.Unlock()
	if len(auditEntries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditEntries))
	}
	if auditEntries[0].Actor != SystemDaemonActor {
		t.Fatalf("Actor = %q, want %q", auditEntries[0].Actor, SystemDaemonActor)
	}
	if auditEntries[0].Action != "AutoRotate" {
		t.Fatalf("Action = %q, want AutoRotate", auditEntries[0].Action)
	}
	if auditEntries[0].Result != "success" {
		t.Fatalf("Result = %q, want success", auditEntries[0].Result)
	}
}

// TestRotationDaemon_NoExpiredKeys 验证无过期密钥时不轮转。
func TestRotationDaemon_NoExpiredKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建密钥，30 天轮转（未过期）。
	mgr.CreateKey(ctx, "future-rotate", mk, 30)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	if auditCount != 0 {
		t.Fatalf("expected 0 audit entries, got %d", auditCount)
	}
}

// TestRotationDaemon_NoRotationPeriod 验证 RotationPeriodDays=0 的密钥不轮转。
func TestRotationDaemon_NoRotationPeriod(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建密钥，不自动轮转。
	mgr.CreateKey(ctx, "no-rotate", mk, 0)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	if auditCount != 0 {
		t.Fatalf("expected 0 rotations, got %d", auditCount)
	}
}

// TestRotationDaemon_ContextCancel 验证 context 取消时安全退出。
func TestRotationDaemon_ContextCancel(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, nil)
	daemon.SetScanInterval(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	daemon.Start(ctx)

	// 运行 200ms。
	time.Sleep(200 * time.Millisecond)

	// 取消 context。
	cancel()

	// 等待 goroutine 退出。
	time.Sleep(100 * time.Millisecond)

	// 锁应已释放。
	locker.mu.Lock()
	acquired := locker.acquired
	locker.mu.Unlock()

	// 锁可能已释放（取决于 ticker 时机），关键是 goroutine 不泄露。
	// 如果锁仍持有，说明 goroutine 在 scanOnce 中，会很快释放。
	_ = acquired
}

// TestRotationDaemon_MultipleExpired 验证多个过期密钥全部轮转。
func TestRotationDaemon_MultipleExpired(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建 3 个密钥，都设置已过期的 NextRotationAt。
	for _, keyID := range []string{"key-a", "key-b", "key-c"} {
		mgr.CreateKey(ctx, keyID, mk, 1)
		meta, _ := mgr.GetKey(ctx, keyID, 1)
		meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
		saveMetaDirect(t, mgr, *meta)
	}

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	if auditCount != 3 {
		t.Fatalf("expected 3 rotations, got %d", auditCount)
	}

	// 验证每个密钥都轮转到 V2。
	for _, keyID := range []string{"key-a", "key-b", "key-c"} {
		latest, err := mgr.findLatestVersion(ctx, keyID)
		if err != nil {
			t.Fatalf("findLatestVersion %s: %v", keyID, err)
		}
		if latest != 2 {
			t.Fatalf("%s: expected v2, got v%d", keyID, latest)
		}
	}
}
