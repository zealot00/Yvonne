// Package lifecycle - 自动密钥轮转守护进程。
//
// 基于 PostgreSQL Advisory Lock 实现集群选主：
//   - 每小时只有一个节点获取锁并扫描过期密钥
//   - 扫描 NextRotationAt <= Now() 且 State=Active 的密钥
//   - 逐个调用 RotateKey 自动轮转
//   - 审计日志 Actor=SYSTEM_DAEMON
//   - context 取消时释放锁 + 退出 goroutine
//
// 安全：
//   - 严格遵守 context.Context 生命周期
//   - SIGTERM 时 context 取消 → 释放 Advisory Lock → goroutine 退出
//   - 无 goroutine 泄露
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// SystemDaemonActor 是自动轮转审计日志中的 Actor 标识。
const SystemDaemonActor = "SYSTEM_DAEMON"

// AuditEntry 是轮转守护进程传给审计回调的日志结构。
// 避免直接依赖 audit 包（防循环依赖）。
type AuditEntry struct {
	Timestamp time.Time
	Actor     string
	Action    string
	Resource  string
	Result    string
}

// LockAcquirer 是分布式锁的抽象接口。
type LockAcquirer interface {
	TryAcquire(ctx context.Context) (acquired bool, release func(), err error)
}

// RotationDaemon 是自动密钥轮转守护进程。
type RotationDaemon struct {
	manager      *Manager
	seal         seal.Unsealer // 通过 MasterKeyRef 获取 CMK，避免明文密钥离开 VaultState
	locker       LockAcquirer
	auditFn      func(entry AuditEntry) error
	scanInterval time.Duration
}

// NewRotationDaemon 创建轮转守护进程。
func NewRotationDaemon(manager *Manager, seal seal.Unsealer, locker LockAcquirer, auditFn func(entry AuditEntry) error) *RotationDaemon {
	return &RotationDaemon{
		manager:      manager,
		seal:         seal,
		locker:       locker,
		auditFn:      auditFn,
		scanInterval: 1 * time.Hour,
	}
}

// Start 启动守护进程 goroutine，绑定 ctx。
// ctx 取消时释放锁 + 退出。
func (d *RotationDaemon) Start(ctx context.Context) {
	go d.loop(ctx)
}

func (d *RotationDaemon) loop(ctx context.Context) {
	ticker := time.NewTicker(d.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("rotation daemon: context cancelled, stopping")
			return
		case <-ticker.C:
			d.scanOnce(ctx)
		}
	}
}

// scanOnce 执行一次扫描+轮转。
func (d *RotationDaemon) scanOnce(ctx context.Context) {
	// 1. 尝试获取分布式锁。
	acquired, release, err := d.locker.TryAcquire(ctx)
	if err != nil {
		log.Printf("rotation daemon: acquire lock failed: %v", err)
		return
	}
	if !acquired {
		return // 其他节点已获取锁，跳过
	}
	defer release()

	// 2. 扫描过期密钥。
	expired, err := d.scanExpiredKeys(ctx)
	if err != nil {
		log.Printf("rotation daemon: scan failed: %v", err)
		return
	}

	if len(expired) == 0 {
		return
	}

	log.Printf("rotation daemon: found %d keys due for rotation", len(expired))

	// 3. 逐个轮转。
	for _, meta := range expired {
		if ctx.Err() != nil {
			return
		}
		d.rotateAndAudit(ctx, meta)
	}
}

// scanExpiredKeys 扫描所有 NextRotationAt <= Now() 且 State=Active 的密钥。
func (d *RotationDaemon) scanExpiredKeys(ctx context.Context) ([]KeyMetadata, error) {
	scanner, ok := d.manager.store.(storage.PrefixScanner)
	if !ok {
		return nil, fmt.Errorf("rotation daemon: store does not support ScanPrefix")
	}

	items, err := scanner.ScanPrefix(ctx, "key:")
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var expired []KeyMetadata

	for _, data := range items {
		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		if meta.State != StateActive {
			continue
		}
		if meta.RotationPeriodDays <= 0 {
			continue
		}
		if meta.NextRotationAt.IsZero() {
			continue
		}
		if !meta.NextRotationAt.After(now) {
			expired = append(expired, meta)
		}
	}

	return expired, nil
}

// rotateAndAudit 执行轮转 + 写审计日志。
func (d *RotationDaemon) rotateAndAudit(ctx context.Context, meta KeyMetadata) {
	var rotateErr error
	var newMeta *KeyMetadata
	_ = d.seal.KEKRef(func(kek seal.KEK) error {
		newMeta, _, rotateErr = d.manager.RotateKey(ctx, meta.KeyID, kek)
		return rotateErr
	})

	// 审计日志（无论成败都记录）。
	entry := AuditEntry{
		Timestamp: time.Now().UTC(),
		Actor:     SystemDaemonActor,
		Action:    "AutoRotate",
		Resource:  meta.KeyID,
		Result:    "success",
	}
	if rotateErr != nil {
		entry.Result = fmt.Sprintf("failure: %v", rotateErr)
		log.Printf("rotation daemon: rotate %s failed: %v", meta.KeyID, rotateErr)
	} else {
		log.Printf("rotation daemon: rotated %s v%d → v%d", meta.KeyID, meta.Version, newMeta.Version)
	}

	if d.auditFn != nil {
		if auditErr := d.auditFn(entry); auditErr != nil {
			log.Printf("rotation daemon: audit log failed: %v", auditErr)
		}
	}
}

// SetScanInterval 设置扫描间隔（用于测试）。
func (d *RotationDaemon) SetScanInterval(interval time.Duration) {
	d.scanInterval = interval
}
