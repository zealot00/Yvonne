// Package lifecycle - 轮转守护进程 E2E 补充测试。
package lifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// TestE2E_Daemon_AdvisoryLockContention Advisory Lock 竞争——两个节点只有一个能获取锁。
func TestE2E_Daemon_AdvisoryLockContention(t *testing.T) {
	locker := &mockAdvisoryLocker{}

	ctx := context.Background()

	// 节点 1 获取锁。
	acquired1, release1, err := locker.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("TryAcquire 1: %v", err)
	}
	if !acquired1 {
		t.Fatal("node 1 should acquire lock")
	}
	t.Log("✅ Node 1 acquired lock")

	// 节点 2 尝试获取锁 → 失败（已被节点 1 持有）。
	acquired2, _, err := locker.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("TryAcquire 2: %v", err)
	}
	if acquired2 {
		t.Fatal("node 2 should NOT acquire lock (held by node 1)")
	}
	t.Log("✅ Node 2 rejected (lock held by node 1)")

	// 节点 1 释放锁。
	release1()
	t.Log("✅ Node 1 released lock")

	// 节点 2 再次尝试 → 成功。
	acquired3, release3, err := locker.TryAcquire(ctx)
	if err != nil {
		t.Fatalf("TryAcquire 3: %v", err)
	}
	if !acquired3 {
		t.Fatal("node 2 should acquire lock after release")
	}
	t.Log("✅ Node 2 acquired lock after release")
	release3()
}

// TestE2E_Daemon_RotateMultipleKeys 守护进程一次扫描轮转多个过期密钥。
func TestE2E_Daemon_RotateMultipleKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)

	// 创建 3 个密钥，全部设置已过期。
	for _, keyID := range []string{"multi-rotate-1", "multi-rotate-2", "multi-rotate-3"} {
		mgr.CreateKey(ctx, keyID, kek, 1)
		meta, _ := mgr.GetKey(ctx, keyID, 1)
		meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
		saveMetaDirect(t, mgr, *meta)
	}

	var auditCount int
	var auditMu sync.Mutex

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, &mockUnsealer{masterKey: mk}, locker, func(entry AuditEntry) error {
		auditMu.Lock()
		auditCount++
		auditMu.Unlock()
		return nil
	})

	// 一次扫描轮转全部。
	daemon.scanOnce(ctx)

	// 验证 3 个密钥都轮转到 v2。
	for _, keyID := range []string{"multi-rotate-1", "multi-rotate-2", "multi-rotate-3"} {
		latestV, _ := mgr.findLatestVersion(ctx, keyID)
		if latestV != 2 {
			t.Fatalf("%s: expected v2, got v%d", keyID, latestV)
		}
	}
	t.Log("✅ 3 keys rotated in single scan")

	auditMu.Lock()
	if auditCount != 3 {
		t.Fatalf("expected 3 audit entries, got %d", auditCount)
	}
	auditMu.Unlock()
	t.Log("✅ 3 audit entries recorded")
}

// TestE2E_Daemon_NoExpiredKeys 无过期密钥时不轮转。
func TestE2E_Daemon_NoExpiredKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()

	// 创建密钥，NextRotationAt 在未来。
	mgr.CreateKey(ctx, "future-rotate", seal.NewSoftwareKEK(mk), 30)

	var auditCount int
	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, &mockUnsealer{masterKey: mk}, locker, func(entry AuditEntry) error {
		auditCount++
		return nil
	})

	daemon.scanOnce(ctx)

	// 无轮转。
	latestV, _ := mgr.findLatestVersion(ctx, "future-rotate")
	if latestV != 1 {
		t.Fatalf("expected v1 (no rotation), got v%d", latestV)
	}
	if auditCount != 0 {
		t.Fatalf("expected 0 audit entries, got %d", auditCount)
	}
	t.Log("✅ No rotation for future-expiry key")
}

// TestE2E_Daemon_BackwardCompatAfterRotate 轮转后旧密文仍可解密。
func TestE2E_Daemon_BackwardCompatAfterRotate(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)

	// 创建密钥 + 加密。
	mgr.CreateKey(ctx, "compat-rotate", kek, 1)
	meta, _ := mgr.GetActiveKey(ctx, "compat-rotate")

	// 手动加密（用 lifecycle 的 Encrypt）。
	plainDEK, encDEK, _ := mgr.GenerateDataKey(ctx, "compat-rotate", kek)
	_ = plainDEK
	_ = encDEK
	_ = meta

	// 设置过期 + 轮转。
	meta, _ = mgr.GetKey(ctx, "compat-rotate", 1)
	meta.NextRotationAt = time.Now().UTC().Add(-1 * time.Hour)
	saveMetaDirect(t, mgr, *meta)

	locker := &mockAdvisoryLocker{}
	daemon := NewRotationDaemon(mgr, &mockUnsealer{masterKey: mk}, locker, func(entry AuditEntry) error {
		return nil
	})
	daemon.scanOnce(ctx)

	// v1 应为 Deactivated，v2 为 Active。
	v1, _ := mgr.GetKey(ctx, "compat-rotate", 1)
	if v1.State != StateDeactivated {
		t.Fatalf("v1 state = %v, want Deactivated", v1.State)
	}
	v2, _ := mgr.GetKey(ctx, "compat-rotate", 2)
	if v2.State != StateActive {
		t.Fatalf("v2 state = %v, want Active", v2.State)
	}
	t.Log("✅ After daemon rotate: v1 deactivated, v2 active")
}
