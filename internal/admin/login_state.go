// Package admin - 登录失败计数 + 锁定（v1.4.2）。
//
// 等保三级 b 项要求："应具有登录失败处理功能，应配置并启用结束会话、
// 限制非法登录次数和当登录连接超时自动退出等相关措施"。
//
// 策略：3 次失败 → 锁 30 分钟。
// 锁定粒度：按 (用户名 + IP) 二维 key，避免一个用户登录失败
//
//	把所有用户都锁了（共享 IP 的场景）。
package admin

import (
	"sync"
	"time"
)

const (
	loginMaxFailures   = 3
	loginLockoutWindow = 30 * time.Minute
)

// LoginState 单个 (user, ip) 的失败状态。
type LoginState struct {
	FailedCount int
	LockedUntil time.Time
	LastAttempt time.Time
}

// LoginStateStore 失败计数存储接口。
type LoginStateStore interface {
	Get(key string) (*LoginState, bool)
	IncFailed(key string) int
	ResetFailed(key string)
	IsLocked(key string) bool
}

// MemoryLoginStateStore in-memory 实现（dev 模式 + cluster 单实例）。
// 线程安全：sync.Mutex 保护。
type MemoryLoginStateStore struct {
	mu    sync.Mutex
	store map[string]*LoginState
}

// NewMemoryLoginStateStore 创建空的内存登录状态存储。
func NewMemoryLoginStateStore() *MemoryLoginStateStore {
	return &MemoryLoginStateStore{store: make(map[string]*LoginState)}
}

// Get 获取状态指针。注意：返回内部指针，调用方应只读。
// 线程安全：写入由 store mutex 保护；并发读取无锁（Go map 并发读安全）。
func (s *MemoryLoginStateStore) Get(key string) (*LoginState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.store[key]
	if !ok {
		return nil, false
	}
	return state, true
}

// IncFailed 累加失败次数。达到阈值时自动标记锁定。
// 返回新的失败计数。
func (s *MemoryLoginStateStore) IncFailed(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.store[key]
	if !ok {
		state = &LoginState{}
		s.store[key] = state
	}
	// 如果已经过了锁定窗口，重置计数
	if !state.LockedUntil.IsZero() && time.Now().After(state.LockedUntil) {
		state.FailedCount = 0
		state.LockedUntil = time.Time{}
	}
	state.FailedCount++
	state.LastAttempt = time.Now()
	if state.FailedCount >= loginMaxFailures {
		state.LockedUntil = time.Now().Add(loginLockoutWindow)
	}
	return state.FailedCount
}

// ResetFailed 重置失败计数 + 清除锁定。
func (s *MemoryLoginStateStore) ResetFailed(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.store[key]
	if !ok {
		return
	}
	state.FailedCount = 0
	state.LockedUntil = time.Time{}
}

// IsLocked 检查是否被锁定。过期锁定自动清除。
func (s *MemoryLoginStateStore) IsLocked(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.store[key]
	if !ok {
		return false
	}
	if state.LockedUntil.IsZero() {
		return false
	}
	if time.Now().After(state.LockedUntil) {
		// 过期自动清除
		state.FailedCount = 0
		state.LockedUntil = time.Time{}
		return false
	}
	return true
}
