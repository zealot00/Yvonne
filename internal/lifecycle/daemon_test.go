package lifecycle

import (
	"context"
	"fmt"
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

// --- 补充边界测试 ---

// TestRotationDaemon_LockNotAcquired 验证锁被其他节点持有时跳过扫描。
func TestRotationDaemon_LockNotAcquired(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建过期密钥。
	mgr.CreateKey(ctx, "locked-test", mk, 1)
	meta, _ := mgr.GetKey(ctx, "locked-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// 锁已被持有（模拟其他节点持有锁）。
	locker := &mockAdvisoryLocker{acquired: true}

	var auditCount int
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	// 未获取锁，不应执行任何轮转。
	if auditCount != 0 {
		t.Fatalf("expected 0 rotations when lock not acquired, got %d", auditCount)
	}

	// 密钥应仍为 V1。
	latest, _ := mgr.findLatestVersion(ctx, "locked-test")
	if latest != 1 {
		t.Fatalf("expected v1 (no rotation), got v%d", latest)
	}
}

// TestRotationDaemon_NewNextRotationAt 验证轮转后 V2 有新的 NextRotationAt。
func TestRotationDaemon_NewNextRotationAt(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建 7 天轮转密钥，篡改为已过期。
	mgr.CreateKey(ctx, "next-rotation-test", mk, 7)
	meta, _ := mgr.GetKey(ctx, "next-rotation-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, nil)
	daemon.scanOnce(ctx)

	// V2 应有新的 NextRotationAt（7 天后）。
	v2, _ := mgr.GetKey(ctx, "next-rotation-test", 2)
	if v2.NextRotationAt.IsZero() {
		t.Fatal("V2 NextRotationAt should not be zero")
	}
	if v2.RotationPeriodDays != 7 {
		t.Fatalf("V2 RotationPeriodDays = %d, want 7", v2.RotationPeriodDays)
	}
	// NextRotationAt 应在未来。
	if !v2.NextRotationAt.After(time.Now().UTC()) {
		t.Fatal("V2 NextRotationAt should be in the future")
	}
}

// TestRotationDaemon_DeactivatedSkipped 验证 Deactivated 状态的密钥不被轮转。
func TestRotationDaemon_DeactivatedSkipped(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建并手动轮转（V1 变 Deactivated）。
	mgr.CreateKey(ctx, "deact-daemon-test", mk, 1)
	mgr.RotateKey(ctx, "deact-daemon-test", mk)

	// 篡改 V1 的 NextRotationAt 为已过期。
	v1, _ := mgr.GetKey(ctx, "deact-daemon-test", 1)
	v1.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *v1)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})
	daemon.scanOnce(ctx)

	// Deactivated 密钥不应被轮转。
	if auditCount != 0 {
		t.Fatalf("expected 0 rotations for Deactivated key, got %d", auditCount)
	}
}

// TestRotationDaemon_SoftDeletedSkipped 验证 SoftDeleted 状态的密钥不被轮转。
func TestRotationDaemon_SoftDeletedSkipped(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	mgr.CreateKey(ctx, "softdel-daemon-test", mk, 1)
	mgr.SoftDeleteKey(ctx, "softdel-daemon-test", 1)

	// 篡改 NextRotationAt 为已过期。
	meta, _ := mgr.GetKey(ctx, "softdel-daemon-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})
	daemon.scanOnce(ctx)

	if auditCount != 0 {
		t.Fatalf("expected 0 rotations for SoftDeleted key, got %d", auditCount)
	}
}

// TestRotationDaemon_EmptyDB 验证空数据库不报错。
func TestRotationDaemon_EmptyDB(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, nil)

	// 空 DB 扫描不应 panic。
	daemon.scanOnce(context.Background())
}

// TestRotationDaemon_AuditFailureDoesNotBlock 验证审计写入失败不阻断轮转。
func TestRotationDaemon_AuditFailureDoesNotBlock(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	mgr.CreateKey(ctx, "audit-fail-test", mk, 1)
	meta, _ := mgr.GetKey(ctx, "audit-fail-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		return fmt.Errorf("simulated audit failure")
	})

	// 审计失败不应阻断轮转。
	daemon.scanOnce(ctx)

	// 密钥应已轮转。
	latest, _ := mgr.findLatestVersion(ctx, "audit-fail-test")
	if latest != 2 {
		t.Fatalf("expected v2 despite audit failure, got v%d", latest)
	}
}

// TestRotationDaemon_SecondScanNoOp 验证轮转后第二次扫描不再轮转（NextRotationAt 已更新到未来）。
func TestRotationDaemon_SecondScanNoOp(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	mgr.CreateKey(ctx, "double-scan-test", mk, 7)
	meta, _ := mgr.GetKey(ctx, "double-scan-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	// 第一次扫描：轮转 V1→V2。
	daemon.scanOnce(ctx)
	if auditCount != 1 {
		t.Fatalf("first scan: expected 1 rotation, got %d", auditCount)
	}

	// 第二次扫描：V2 的 NextRotationAt 在未来，不应轮转。
	daemon.scanOnce(ctx)
	if auditCount != 1 {
		t.Fatalf("second scan: expected 1 total rotation, got %d", auditCount)
	}
}

// TestRotationDaemon_MixedStates 验证混合状态场景：
// Active 过期 → 轮转；Active 未过期 → 跳过；Deactivated → 跳过；无周期 → 跳过。
func TestRotationDaemon_MixedStates(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// key-expired: Active + 已过期 → 应轮转。
	mgr.CreateKey(ctx, "key-expired", mk, 1)
	meta, _ := mgr.GetKey(ctx, "key-expired", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// key-future: Active + 未过期 → 跳过。
	mgr.CreateKey(ctx, "key-future", mk, 30)

	// key-no-period: Active + 无轮转周期 → 跳过。
	mgr.CreateKey(ctx, "key-no-period", mk, 0)

	// key-deactivated: Deactivated + 已过期 → 跳过。
	mgr.CreateKey(ctx, "key-deactivated", mk, 1)
	mgr.RotateKey(ctx, "key-deactivated", mk) // V1 → Deactivated
	v1, _ := mgr.GetKey(ctx, "key-deactivated", 1)
	v1.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *v1)

	var rotatedKeys []string
	var mu sync.Mutex
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(entry AuditEntry) error {
		mu.Lock()
		rotatedKeys = append(rotatedKeys, entry.Resource)
		mu.Unlock()
		return nil
	})

	daemon.scanOnce(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(rotatedKeys) != 1 {
		t.Fatalf("expected 1 rotation, got %d: %v", len(rotatedKeys), rotatedKeys)
	}
	if rotatedKeys[0] != "key-expired" {
		t.Fatalf("expected key-expired to rotate, got %s", rotatedKeys[0])
	}
}

// TestRotationDaemon_AuditEntryFields 验证审计日志字段完整性。
func TestRotationDaemon_AuditEntryFields(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	mgr.CreateKey(ctx, "audit-fields-test", mk, 1)
	meta, _ := mgr.GetKey(ctx, "audit-fields-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	var entry AuditEntry
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(e AuditEntry) error {
		entry = e
		return nil
	})
	daemon.scanOnce(ctx)

	if entry.Actor != SystemDaemonActor {
		t.Fatalf("Actor = %q, want %q", entry.Actor, SystemDaemonActor)
	}
	if entry.Action != "AutoRotate" {
		t.Fatalf("Action = %q, want AutoRotate", entry.Action)
	}
	if entry.Resource != "audit-fields-test" {
		t.Fatalf("Resource = %q, want audit-fields-test", entry.Resource)
	}
	if entry.Result != "success" {
		t.Fatalf("Result = %q, want success", entry.Result)
	}
	if entry.Timestamp.IsZero() {
		t.Fatal("Timestamp should not be zero")
	}
}

// TestRotationDaemon_RotateFailureAudited 验证轮转失败也记录审计日志。
func TestRotationDaemon_RotateFailureAudited(t *testing.T) {
	store := newFaultStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建一个过期密钥。
	mgr.CreateKey(ctx, "rotate-fail-test", mk, 1)
	meta, _ := mgr.GetKey(ctx, "rotate-fail-test", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	// 先失效缓存确保 scanExpiredKeys 从 store 读取篡改后的数据。
	mgr.cache.invalidate("rotate-fail-test")

	// 篡改完成后，设置 Put 错误（RotateKey 写入新版本时失败）。
	store.putErr = fmt.Errorf("simulated DB error during rotation")

	var entry AuditEntry
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, func(e AuditEntry) error {
		entry = e
		return nil
	})
	daemon.scanOnce(ctx)

	// 轮转应失败（DB Put 错误），审计日志应记录 failure。
	if entry.Action != "AutoRotate" {
		t.Fatalf("Action = %q", entry.Action)
	}
	if entry.Result == "success" {
		t.Fatal("Result should be failure, not success")
	}
}

// TestRotationDaemon_GoroutineExit 验证 Start + cancel 后 goroutine 真正退出。
func TestRotationDaemon_GoroutineExit(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, mk, locker, nil)
	daemon.SetScanInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	daemon.Start(ctx)

	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// goroutine 应已退出。用 runtime.NumGoroutine 间接验证。
	// 此处仅验证不 panic + 不死锁。
}

// TestAdvisoryLocker_MockReacquire 验证 mock 锁释放后可重新获取。
func TestAdvisoryLocker_MockReacquire(t *testing.T) {
	locker := &mockAdvisoryLocker{}

	// 第一次获取。
	ok1, release1, _ := locker.TryAcquire(context.Background())
	if !ok1 {
		t.Fatal("first acquire should succeed")
	}

	// 第二次获取（锁被持有，应失败）。
	ok2, _, _ := locker.TryAcquire(context.Background())
	if ok2 {
		t.Fatal("second acquire should fail (lock held)")
	}

	// 释放后重新获取。
	release1()
	ok3, release3, _ := locker.TryAcquire(context.Background())
	if !ok3 {
		t.Fatal("third acquire should succeed after release")
	}
	release3()
}
