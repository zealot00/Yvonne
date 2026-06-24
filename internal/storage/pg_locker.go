// Package storage - PostgreSQL Advisory Lock 集群选主。
//
// 基于 pg_try_advisory_lock 实现轻量级分布式锁。
// 多节点部署时，只有一个节点能获取锁并执行定时任务（如密钥轮转守护进程）。
//
// 特性：
//   - 非阻塞获取（pg_try_advisory_lock 立即返回）
//   - 会话级锁（连接断开自动释放）
//   - context 取消时主动释放（pg_advisory_unlock）
package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AdvisoryLocker 基于 PostgreSQL Advisory Lock 的分布式锁。
type AdvisoryLocker struct {
	pool  *pgxpool.Pool
	keyID int64 // 锁的数字标识
}

// NewAdvisoryLocker 创建 Advisory 锁管理器。
// keyID 是全局唯一的锁标识（如 0x796F6E6E65 = "yonne" 的 int64 表示）。
func NewAdvisoryLocker(pool *pgxpool.Pool, keyID int64) *AdvisoryLocker {
	return &AdvisoryLocker{pool: pool, keyID: keyID}
}

// TryAcquire 尝试获取 Advisory Lock（非阻塞）。
// 成功返回 true + 一个 release 函数；失败返回 false。
//
// 获取的锁在以下情况自动释放：
//   - 调用 release 函数
//   - 数据库连接断开
//   - 数据库会话结束
func (l *AdvisoryLocker) TryAcquire(ctx context.Context) (acquired bool, release func(), err error) {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("advisory lock: acquire connection: %w", err)
	}

	var ok bool
	err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", l.keyID).Scan(&ok)
	if err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("advisory lock: pg_try_advisory_lock: %w", err)
	}

	if !ok {
		conn.Release()
		return false, nil, nil
	}

	release = func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", l.keyID)
		conn.Release()
	}
	return true, release, nil
}
