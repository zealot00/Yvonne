// Package admin - 登录失败计数 + 锁定（v1.4.2）。
//
// 等保三级 b 项要求："应具有登录失败处理功能，应配置并启用结束会话、
// 限制非法登录次数和当登录连接超时自动退出等相关措施"。
//
// 策略：
//   - 客户端粒度（IP + UA/设备特征摘要）：单客户端连续 3 次失败 → 锁定该客户端 30 分钟，
//     避免同一 NAT 下其它正常客户端被连坐互锁（解决 NAT 互锁）。
//   - 账号全局粒度（跨 IP 聚合）：当失败来自 >= 3 个不同源 IP（换 IP 爆破）
//     或全局累计失败达 6 次时 → 锁定账号 30 分钟（解决换 IP 绕过）。
//   - 支持内存存储（MemoryLoginStateStore）与集群共享 KV 存储（KVLoginStateStore）。
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"yvonne/internal/storage"
)

const (
	loginMaxFailures        = 3
	loginAccountMaxFailures = 6
	loginLockoutWindow      = 30 * time.Minute
	clientTrackedMarker     = "__client_tracked__"
)

// LoginState 单个维度的失败状态。
type LoginState struct {
	FailedCount int             `json:"failed_count"`
	LockedUntil time.Time       `json:"locked_until"`
	LastAttempt time.Time       `json:"last_attempt"`
	DistinctIPs map[string]bool `json:"distinct_ips,omitempty"`
}

// LoginStateStore 失败计数存储接口。
type LoginStateStore interface {
	Get(key string) (*LoginState, bool)
	IncFailed(key string) int
	ResetFailed(key string)
	IsLocked(key string) bool
}

// AccountLockTracker 扩展接口：支持多维锁定（防 NAT 互锁 + 防换 IP 绕过）。
type AccountLockTracker interface {
	RecordFailure(accountKey, ipKey, clientKey, clientIP string)
	IsRequestLocked(accountKey, ipKey, clientKey string) bool
}

// loginClientKey 构造细粒度客户端锁定 key（IP + UA/设备指纹摘要）。
// 当 UA 与设备指纹均为空时退化为 ipKey。
func loginClientKey(clientIP, userAgent string, fp DeviceAttributes) string {
	ipKey := "admin-web@" + clientIP
	canonical, _ := fp.canonicalJSON()
	raw := userAgent + "|" + string(canonical)
	if userAgent == "" && fp == (DeviceAttributes{}) {
		return ipKey
	}
	sum := sha256.Sum256([]byte(raw))
	return ipKey + "#" + hex.EncodeToString(sum[:8])
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
		state.DistinctIPs = nil
		return false
	}
	return true
}

// RecordFailure 记录一次登录失败（同时更新客户端维度、IP 影子维度、账号全局维度）。
func (s *MemoryLoginStateStore) RecordFailure(accountKey, ipKey, clientKey, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	incState := func(key string, threshold int) *LoginState {
		st, ok := s.store[key]
		if !ok {
			st = &LoginState{}
			s.store[key] = st
		}
		if !st.LockedUntil.IsZero() && now.After(st.LockedUntil) {
			st.FailedCount = 0
			st.LockedUntil = time.Time{}
			st.DistinctIPs = nil
		}
		st.FailedCount++
		st.LastAttempt = now
		if st.FailedCount >= threshold {
			st.LockedUntil = now.Add(loginLockoutWindow)
		}
		return st
	}

	// 1. 客户端维度（IP + UA/设备特征）
	incState(clientKey, loginMaxFailures)

	// 2. IP 维度（标记来自细粒度客户端跟踪，避免误锁同 NAT 下其它客户端）
	if clientKey != ipKey {
		ipSt := incState(ipKey, loginMaxFailures)
		if ipSt.DistinctIPs == nil {
			ipSt.DistinctIPs = make(map[string]bool)
		}
		ipSt.DistinctIPs[clientTrackedMarker] = true
	}

	// 3. 账号全局维度（跨 IP 换 IP 爆破检测 + 全局阈值）
	accSt := incState(accountKey, loginAccountMaxFailures)
	if accSt.DistinctIPs == nil {
		accSt.DistinctIPs = make(map[string]bool)
	}
	if clientIP != "" {
		accSt.DistinctIPs[clientIP] = true
	}
	if len(accSt.DistinctIPs) >= loginMaxFailures {
		accSt.LockedUntil = now.Add(loginLockoutWindow)
	}
}

// IsRequestLocked 判断当前请求是否被锁（账号全局锁定 OR 当前客户端锁定 OR 显式 IP 锁定）。
func (s *MemoryLoginStateStore) IsRequestLocked(accountKey, ipKey, clientKey string) bool {
	if s.IsLocked(accountKey) {
		return true
	}
	if s.IsLocked(clientKey) {
		return true
	}
	if s.IsLocked(ipKey) {
		s.mu.Lock()
		st, ok := s.store[ipKey]
		trackedByClient := ok && st.DistinctIPs != nil && st.DistinctIPs[clientTrackedMarker]
		s.mu.Unlock()
		if !trackedByClient {
			return true
		}
	}
	return false
}

// =====================================================================
// KVLoginStateStore（集群模式，复用 storage.KVStore）
// =====================================================================

// KVLoginStateStore 基于共享 storage.KVStore 的登录状态存储。
type KVLoginStateStore struct {
	kv storage.KVStore
	ns string
	mu sync.Mutex
}

// NewKVLoginStateStore 创建基于共享 KVStore 的登录失败状态存储。
func NewKVLoginStateStore(kv storage.KVStore) *KVLoginStateStore {
	return &KVLoginStateStore{
		kv: kv,
		ns: "admin:login_state:",
	}
}

func (s *KVLoginStateStore) k(key string) string { return s.ns + key }

// Get 从 KV 读取登录状态。
func (s *KVLoginStateStore) Get(key string) (*LoginState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := s.kv.Get(ctx, s.k(key))
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var st LoginState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// IncFailed 原子累加失败计数。
func (s *KVLoginStateStore) IncFailed(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fullKey := s.k(key)
	now := time.Now()
	var count int

	_ = s.kv.WithTx(ctx, func(tx storage.KVStore) error {
		var st LoginState
		if raw, err := tx.Get(ctx, fullKey); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &st)
		}
		if !st.LockedUntil.IsZero() && now.After(st.LockedUntil) {
			st.FailedCount = 0
			st.LockedUntil = time.Time{}
			st.DistinctIPs = nil
		}
		st.FailedCount++
		st.LastAttempt = now
		if st.FailedCount >= loginMaxFailures {
			st.LockedUntil = now.Add(loginLockoutWindow)
		}
		count = st.FailedCount
		buf, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		return tx.Put(ctx, fullKey, buf)
	})
	return count
}

// ResetFailed 重置失败状态。
func (s *KVLoginStateStore) ResetFailed(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.kv.Delete(ctx, s.k(key))
}

// IsLocked 检查是否处于锁定窗口内。
func (s *KVLoginStateStore) IsLocked(key string) bool {
	st, ok := s.Get(key)
	if !ok || st.LockedUntil.IsZero() {
		return false
	}
	if time.Now().After(st.LockedUntil) {
		s.ResetFailed(key)
		return false
	}
	return true
}

// RecordFailure 集群模式多维失败记录。
func (s *KVLoginStateStore) RecordFailure(accountKey, ipKey, clientKey, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()

	_ = s.kv.WithTx(ctx, func(tx storage.KVStore) error {
		loadAndInc := func(key string, threshold int) (*LoginState, error) {
			var st LoginState
			if raw, err := tx.Get(ctx, s.k(key)); err == nil && len(raw) > 0 {
				_ = json.Unmarshal(raw, &st)
			}
			if !st.LockedUntil.IsZero() && now.After(st.LockedUntil) {
				st.FailedCount = 0
				st.LockedUntil = time.Time{}
				st.DistinctIPs = nil
			}
			st.FailedCount++
			st.LastAttempt = now
			if st.FailedCount >= threshold {
				st.LockedUntil = now.Add(loginLockoutWindow)
			}
			return &st, nil
		}

		clientSt, _ := loadAndInc(clientKey, loginMaxFailures)
		if buf, err := json.Marshal(clientSt); err == nil {
			_ = tx.Put(ctx, s.k(clientKey), buf)
		}

		if clientKey != ipKey {
			ipSt, _ := loadAndInc(ipKey, loginMaxFailures)
			if ipSt.DistinctIPs == nil {
				ipSt.DistinctIPs = make(map[string]bool)
			}
			ipSt.DistinctIPs[clientTrackedMarker] = true
			if buf, err := json.Marshal(ipSt); err == nil {
				_ = tx.Put(ctx, s.k(ipKey), buf)
			}
		}

		accSt, _ := loadAndInc(accountKey, loginAccountMaxFailures)
		if accSt.DistinctIPs == nil {
			accSt.DistinctIPs = make(map[string]bool)
		}
		if clientIP != "" {
			accSt.DistinctIPs[clientIP] = true
		}
		if len(accSt.DistinctIPs) >= loginMaxFailures {
			accSt.LockedUntil = now.Add(loginLockoutWindow)
		}
		if buf, err := json.Marshal(accSt); err == nil {
			_ = tx.Put(ctx, s.k(accountKey), buf)
		}
		return nil
	})
}

// IsRequestLocked 集群模式检查请求是否被锁。
func (s *KVLoginStateStore) IsRequestLocked(accountKey, ipKey, clientKey string) bool {
	if s.IsLocked(accountKey) {
		return true
	}
	if s.IsLocked(clientKey) {
		return true
	}
	if s.IsLocked(ipKey) {
		st, ok := s.Get(ipKey)
		trackedByClient := ok && st.DistinctIPs != nil && st.DistinctIPs[clientTrackedMarker]
		if !trackedByClient {
			return true
		}
	}
	return false
}
