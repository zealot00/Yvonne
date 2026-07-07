// Package admin - Session 生命周期（v1.4.2）。
//
// 等保三级 b 项要求："应能够对重要主体（管理员）进行唯一标识、
// 用户身份鉴别信息复杂度、登录失败处理、超时自动退出"。
//
// 设计要点：
//  1. SessionID：32 字节 crypto/rand → base64url（熵 ≥ 256 bit，不可预测）
//  2. idle timeout：30 min 无活动 → 失效（每次请求 Touch 刷新）
//  3. hard cap：创建后 8 h 强制失效（即使一直在用）
//  4. 两套存储：MemorySessionStore（dev 模式 / cluster 单实例）
//     KVSessionStore（cluster 多实例，命名空间 "admin:session:"）
//  5. Reaper：后台 goroutine 每 5 min 清理过期 session
//
// 安全：
//   - SessionID 写入 Set-Cookie 时 HttpOnly + Secure + SameSite=Strict
//   - Idle/hard-cap 检查在中间件执行，超时立即 401
//   - Touch 只更新 last_seen + expires_at，不影响 hard_cap
package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"
)

// Session 内存中的会话对象。
type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	CSRFToken  string    `json:"csrf_token"`
	CreatedAt  time.Time `json:"created_at"`
	HardCapAt  time.Time `json:"hard_cap_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Remember   bool      `json:"remember"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
}

// 默认 session 配置常量（供 server 初始化用）。
const (
	defaultSessionIdle    = 30 * time.Minute
	defaultSessionHardCap = 8 * time.Hour
	sessionIDEntropyBytes = 32 // 256 bit
)

// NewSession 创建新 session。
// idleTimeout：连续空闲时长上限（之后需重新登录）
// hardCapTimeout：自创建起的最长存活时间（即使活跃也强制下线）
// remember：勾选后允许 device token 跳过验证码 + TOTP
func NewSession(userID string, idleTimeout, hardCapTimeout time.Duration, remember bool, ip, ua string) (*Session, error) {
	id, err := randomID(sessionIDEntropyBytes)
	if err != nil {
		return nil, err
	}
	csrf, err := randomID(sessionIDEntropyBytes)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &Session{
		ID:         id,
		UserID:     userID,
		CSRFToken:  csrf,
		CreatedAt:  now,
		HardCapAt:  now.Add(hardCapTimeout),
		LastSeenAt: now,
		ExpiresAt:  now.Add(idleTimeout),
		Remember:   remember,
		IP:         ip,
		UserAgent:  ua,
	}, nil
}

// =====================================================================
// SessionStore 接口 + 内存实现
// =====================================================================

// SessionStore session 持久化抽象。
type SessionStore interface {
	Put(s *Session) error
	Get(id string) (*Session, bool)
	Touch(id string, lastSeenAt, expiresAt time.Time) error
	Delete(id string) error
	Reap(now time.Time) int
}

// MemorySessionStore 线程安全的内存 session 存储（dev / 单实例 cluster）。
type MemorySessionStore struct {
	mu    sync.RWMutex
	store map[string]*Session
}

// NewMemorySessionStore 创建一个空的内存 session 存储。
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{store: make(map[string]*Session)}
}

// Put 写入或覆盖。
func (s *MemorySessionStore) Put(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 防御性 copy，避免调用方后续 mutate 串扰
	cp := *session
	s.store[session.ID] = &cp
	return nil
}

// Get 按 ID 取。未找到或已过期（idle / hard-cap）→ 返回 false。
// 过期会 lazy cleanup。
func (s *MemorySessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.store[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(sess.HardCapAt) || now.After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.store, id)
		s.mu.Unlock()
		return nil, false
	}
	return sess, true
}

// Touch 刷新 last_seen 和 idle expires。HardCapAt 不变。
func (s *MemorySessionStore) Touch(id string, lastSeenAt, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.store[id]
	if !ok {
		return nil // 静默忽略：调用方后面 Get 会拿到 false
	}
	sess.LastSeenAt = lastSeenAt
	sess.ExpiresAt = expiresAt
	return nil
}

// Delete 显式删除。
func (s *MemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, id)
	return nil
}

// Reap 删除所有过期 session，返回清理数量。
func (s *MemorySessionStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.store {
		if now.After(sess.HardCapAt) || now.After(sess.ExpiresAt) {
			delete(s.store, id)
			n++
		}
	}
	return n
}

// =====================================================================
// KVSessionStore（cluster 模式，复用 storage.KVStore）
// =====================================================================
//
// 命名空间："admin:session:" + sessionID
// 值：JSON 编码的 Session
// 不依赖 TTL 列（yvonne_kv_str 表无 expires_at）→ 依赖 Reap 清理

// KVSessionStore 基于 storage.KVStore 的 session 存储。
type KVSessionStore struct {
	kv interface {
		Get(key string) ([]byte, bool, error)
		Put(key string, value []byte) error
		Delete(key string) error
	}
	ns    string // 命名空间前缀，默认 "admin:session:"
	mu    sync.Mutex
	cache map[string]*Session // 本地缓存避免每次 Get 反序列化
}

// NewKVSessionStore 创建基于 KV 的 session 存储。
// kv 必须是 cluster 模式注入的 storage.KVStore 实现。
func NewKVSessionStore(kv interface {
	Get(key string) ([]byte, bool, error)
	Put(key string, value []byte) error
	Delete(key string) error
}) *KVSessionStore {
	return &KVSessionStore{
		kv:    kv,
		ns:    "admin:session:",
		cache: make(map[string]*Session),
	}
}

func (s *KVSessionStore) k(key string) string { return s.ns + key }

// Put 写入 session（JSON）。
func (s *KVSessionStore) Put(session *Session) error {
	buf, err := json.Marshal(session)
	if err != nil {
		return err
	}
	if err := s.kv.Put(s.k(session.ID), buf); err != nil {
		return err
	}
	s.mu.Lock()
	cp := *session
	s.cache[session.ID] = &cp
	s.mu.Unlock()
	return nil
}

// Get 按 ID 取。未找到或已过期 → false。已过期 lazy delete。
func (s *KVSessionStore) Get(id string) (*Session, bool) {
	s.mu.Lock()
	if cached, ok := s.cache[id]; ok {
		s.mu.Unlock()
		now := time.Now()
		if now.After(cached.HardCapAt) || now.After(cached.ExpiresAt) {
			_ = s.kv.Delete(s.k(id))
			s.mu.Lock()
			delete(s.cache, id)
			s.mu.Unlock()
			return nil, false
		}
		return cached, true
	}
	s.mu.Unlock()

	buf, ok, err := s.kv.Get(s.k(id))
	if err != nil || !ok {
		return nil, false
	}
	var sess Session
	if err := json.Unmarshal(buf, &sess); err != nil {
		return nil, false
	}
	now := time.Now()
	if now.After(sess.HardCapAt) || now.After(sess.ExpiresAt) {
		_ = s.kv.Delete(s.k(id))
		return nil, false
	}
	s.mu.Lock()
	s.cache[id] = &sess
	s.mu.Unlock()
	return &sess, true
}

// Touch 写回更新后的 last_seen/expires_at。
func (s *KVSessionStore) Touch(id string, lastSeenAt, expiresAt time.Time) error {
	s.mu.Lock()
	cached, ok := s.cache[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	cached.LastSeenAt = lastSeenAt
	cached.ExpiresAt = expiresAt
	cp := *cached
	s.mu.Unlock()
	buf, err := json.Marshal(&cp)
	if err != nil {
		return err
	}
	return s.kv.Put(s.k(id), buf)
}

// Delete 显式删除。
func (s *KVSessionStore) Delete(id string) error {
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
	return s.kv.Delete(s.k(id))
}

// Reap 清理所有缓存中已过期的 session。
func (s *KVSessionStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.cache {
		if now.After(sess.HardCapAt) || now.After(sess.ExpiresAt) {
			delete(s.cache, id)
			_ = s.kv.Delete(s.k(id))
			n++
		}
	}
	return n
}

// =====================================================================
// SessionReaper 后台清理任务
// =====================================================================

// StartSessionReaper 启动后台 reaper goroutine，返回 stop 函数。
// 调用方在 bootstrap 时启动，在 server 关闭时调用 stop。
func StartSessionReaper(store SessionStore, interval time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case now := <-ticker.C:
				_ = store.Reap(now)
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(stop) }
}

// 防止 unused import 警告
var _ = rand.Reader
var _ = base64.RawURLEncoding
