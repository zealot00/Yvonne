// Package storage - Postgres LISTEN/NOTIFY 监听器。
//
// 用于实现集群缓存失效：当某个节点执行 Rotate/Shred 后，
// 通过 NOTIFY yvonne_cache_invalidation 通知所有节点清空对应缓存。
//
// 生命周期：
//   - Start 启动监听 goroutine（绑定 context）。
//   - 收到通知后调用 onNotify 回调（即 Manager.InvalidateCache）。
//   - 断线重连后调用 onReconnect 回调（清空整个缓存池）。
//   - context 取消时安全退出，无 goroutine 泄露。
package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CacheInvalidationListener 是 Postgres LISTEN/NOTIFY 监听器。
type CacheInvalidationListener struct {
	pool        *pgxpool.Pool
	channel     string
	onNotify    func(keyID string) // 收到通知时调用
	onReconnect func()             // 断线重连后调用（清空整个缓存）
}

// NewCacheInvalidationListener 创建监听器。
// onNotify: 收到 KeyID 通知时调用（调 Manager.InvalidateCache）。
// onReconnect: 断线重连后调用（调 Manager.ClearCache）。
func NewCacheInvalidationListener(pool *pgxpool.Pool, onNotify func(keyID string), onReconnect func()) *CacheInvalidationListener {
	return &CacheInvalidationListener{
		pool:        pool,
		channel:     "yvonne_cache_invalidation",
		onNotify:    onNotify,
		onReconnect: onReconnect,
	}
}

// Start 启动监听 goroutine，绑定 ctx。
// ctx 取消时 goroutine 安全退出。
// 必须在优雅停机时 cancel ctx 以防 goroutine 泄露。
func (l *CacheInvalidationListener) Start(ctx context.Context) {
	go l.listenLoop(ctx)
}

// listenLoop 是主监听循环，含断线重连逻辑。
func (l *CacheInvalidationListener) listenLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Printf("cache listener: context cancelled, stopping")
			return
		default:
		}

		err := l.listenOnce(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// 连接断开：等待重连，避免 tight loop。
			log.Printf("cache listener: disconnected (%v), reconnecting in 2s...", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}

			// 重连后强制清空整个缓存（防期间错失通知）。
			if l.onReconnect != nil {
				l.onReconnect()
			}
		}
	}
}

// listenOnce 执行一次 LISTEN 会话，直到连接断开或 ctx 取消。
func (l *CacheInvalidationListener) listenOnce(ctx context.Context) error {
	// 从连接池获取一个专用连接（LISTEN 需要独占连接）。
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// 执行 LISTEN。
	_, err = conn.Exec(ctx, fmt.Sprintf("LISTEN %s", l.channel))
	if err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}
	log.Printf("cache listener: LISTEN %s started", l.channel)

	// 等待通知。
	for {
		// WaitForNotification 阻塞直到收到通知或连接断开。
		// 用 ctx 控制超时，定期检查 ctx 是否已取消。
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("wait for notification: %w", err)
		}

		// 收到通知：payload 是 KeyID。
		keyID := notification.Payload
		if keyID != "" && l.onNotify != nil {
			l.onNotify(keyID)
		}
	}
}

// NotifyInvalidation 向所有监听节点发送缓存失效通知。
// 在 RotateKey/ShredKey 事务提交后调用。
func NotifyInvalidation(pool *pgxpool.Pool, keyID string) error {
	_, err := pool.Exec(context.Background(),
		`SELECT pg_notify('yvonne_cache_invalidation', $1)`, keyID)
	if err != nil {
		return fmt.Errorf("pg_notify: %w", err)
	}
	return nil
}
