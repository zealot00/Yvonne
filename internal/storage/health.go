// Package storage - 数据库健康检查 + degraded 模式。
//
// PG 断连时不 panic，进入 degraded 模式：
//   - 缓存中的 DEK 元数据仍可用于 Decrypt
//   - 新写操作（CreateKey/RotateKey/ShredKey）返回 ErrDegraded
//   - 后台 goroutine 定期 ping，恢复后退出 degraded
package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrDegraded 表示数据库不可用，系统处于 degraded 模式。
var ErrDegraded = errors.New("storage: database unavailable (degraded mode)")

// HealthChecker 是支持健康检查的存储后端接口。
type HealthChecker interface {
	// Ping 检查数据库连接是否正常。
	Ping(ctx context.Context) error
	// IsHealthy 返回当前健康状态。
	IsHealthy() bool
	// StartHealthCheck 启动后台健康检查 goroutine。
	StartHealthCheck(interval time.Duration)
	// StopHealthCheck 停止后台健康检查。
	StopHealthCheck()
}

// healthState 是健康检查的共享状态。
type healthState struct {
	healthy atomic.Bool
	mu      sync.Mutex
	cancel  context.CancelFunc
	pingFn  func(context.Context) error
}

// newHealthState 创建健康状态（初始为 healthy）。
func newHealthState(pingFn func(context.Context) error) *healthState {
	hs := &healthState{pingFn: pingFn}
	hs.healthy.Store(true)
	return hs
}

// StartHealthCheck 启动后台健康检查。
func (hs *healthState) StartHealthCheck(interval time.Duration) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if hs.cancel != nil {
		return // 已启动
	}

	ctx, cancel := context.WithCancel(context.Background())
	hs.cancel = cancel

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := hs.pingFn(pingCtx)
				pingCancel()

				if err != nil {
					hs.healthy.Store(false)
				} else {
					hs.healthy.Store(true)
				}
			}
		}
	}()
}

// StopHealthCheck 停止后台健康检查。
func (hs *healthState) StopHealthCheck() {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if hs.cancel != nil {
		hs.cancel()
		hs.cancel = nil
	}
}

// IsHealthy 返回当前健康状态。
func (hs *healthState) IsHealthy() bool {
	return hs.healthy.Load()
}

// SetUnhealthy 手动标记为不健康（DB 操作失败时调用）。
func (hs *healthState) SetUnhealthy() {
	hs.healthy.Store(false)
}

// SetHealthy 手动标记为健康（重连成功时调用）。
func (hs *healthState) SetHealthy() {
	hs.healthy.Store(true)
}
