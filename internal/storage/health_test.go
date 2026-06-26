package storage

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestHealthState_InitialState 初始为健康。
func TestHealthState_InitialState(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error { return nil })
	if !hs.IsHealthy() {
		t.Fatal("initial state should be healthy")
	}
}

// TestHealthState_SetUnhealthy 手动标记不健康。
func TestHealthState_SetUnhealthy(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error { return nil })
	hs.SetUnhealthy()
	if hs.IsHealthy() {
		t.Fatal("should be unhealthy after SetUnhealthy")
	}
}

// TestHealthState_SetHealthy 手动恢复健康。
func TestHealthState_SetHealthy(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error { return nil })
	hs.SetUnhealthy()
	hs.SetHealthy()
	if !hs.IsHealthy() {
		t.Fatal("should be healthy after SetHealthy")
	}
}

// TestHealthState_PingFails 标记不健康。
func TestHealthState_PingFails(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error {
		return errFake // 模拟 DB 断连
	})
	hs.StartHealthCheck(50 * time.Millisecond)
	defer hs.StopHealthCheck()

	// 等待一次 ping。
	time.Sleep(150 * time.Millisecond)

	if hs.IsHealthy() {
		t.Fatal("should be unhealthy after ping fails")
	}
}

// TestHealthState_PingRecovers 恢复健康。
func TestHealthState_PingRecovers(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	hs := newHealthState(func(ctx context.Context) error {
		if failing.Load() {
			return errFake
		}
		return nil
	})
	hs.StartHealthCheck(50 * time.Millisecond)
	defer hs.StopHealthCheck()

	// 等待 ping 失败。
	time.Sleep(100 * time.Millisecond)
	if hs.IsHealthy() {
		t.Fatal("should be unhealthy initially")
	}

	// 恢复。
	failing.Store(false)
	time.Sleep(100 * time.Millisecond)
	if !hs.IsHealthy() {
		t.Fatal("should recover after ping succeeds")
	}
}

// TestHealthState_StopIdempotent 多次 Stop 不 panic。
func TestHealthState_StopIdempotent(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error { return nil })
	hs.StartHealthCheck(1 * time.Second)
	hs.StopHealthCheck()
	hs.StopHealthCheck() // 不应 panic
}

// TestHealthState_StartOnce 重复 Start 不创建多个 goroutine。
func TestHealthState_StartOnce(t *testing.T) {
	hs := newHealthState(func(ctx context.Context) error { return nil })
	hs.StartHealthCheck(1 * time.Second)
	hs.StartHealthCheck(1 * time.Second) // 应跳过
	hs.StopHealthCheck()
}

var errFake = errFakeType{}

type errFakeType struct{}

func (errFakeType) Error() string { return "fake DB error" }
