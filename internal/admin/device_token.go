// Package admin - Device Token 与 TOTP 防重放存储（v1.4.2）。
//
// 设计：勾选"记住此设备 30 天"后，下一次登录验证设备指纹通过时仅跳过图形验证码（Captcha），
// 绝不跳过 adminToken 与 TOTP 二次认证，防止设备 cookie 泄露导致 30 天无 2FA 裸奔。
//
// 设备指纹：HMAC-SHA-256(sessionSecret, JSON(ua,lang,plat,screen,tz))
//   - 任意浏览器属性变化 → 指纹失效（接受为退化路径）
//   - salt (sessionSecret) 防伪造，服务端不暴露
//   - 校验时同时比对请求重算的指纹、User-Agent 与绑定 IP
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"yvonne/internal/auth"
	"yvonne/internal/storage"
)

// DeviceTTL 设备 token 默认有效期 30 天。
const DeviceTTL = 30 * 24 * time.Hour

// DeviceAttributes 浏览器/客户端可观测属性（前端收集）。
type DeviceAttributes struct {
	UA     string `json:"ua"`     // navigator.userAgent
	Lang   string `json:"lang"`   // navigator.language
	Plat   string `json:"plat"`   // navigator.platform
	Screen string `json:"screen"` // `${w}x${h}x${depth}`
	TZ     string `json:"tz"`     // Intl.DateTimeFormat().resolvedOptions().timeZone
}

// canonicalJSON 对属性做稳定 JSON 序列化（字段按字母序排序）。
// 必须确定性，否则同样输入算出不同指纹。
func (a DeviceAttributes) canonicalJSON() ([]byte, error) {
	// 用 map 强制排序（struct 字段顺序不可控）
	m := map[string]string{
		"ua":     a.UA,
		"lang":   a.Lang,
		"plat":   a.Plat,
		"screen": a.Screen,
		"tz":     a.TZ,
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 手写稳定序列化
	buf := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, _ := json.Marshal(k)
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, _ := json.Marshal(m[k])
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// DeviceFingerprint 计算设备指纹（64-char hex）。
// salt 来自 sessionSecret（>=32 字节），调用方负责保管。
func DeviceFingerprint(salt []byte, a DeviceAttributes) string {
	canonical, _ := a.canonicalJSON()
	mac := hmac.New(sha256.New, salt)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// DeviceToken 设备令牌。
type DeviceToken struct {
	Fingerprint string    `json:"fp"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	IP          string    `json:"ip"`
}

// IsExpired 判断是否已过期。
func (t *DeviceToken) IsExpired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}

// =====================================================================
// DeviceStore 接口 + 内存实现
// =====================================================================

// DeviceStore 设备 token 存储抽象。
type DeviceStore interface {
	Put(t *DeviceToken)
	Get(fp string) (*DeviceToken, bool)
	Exists(fp string) bool
	Delete(fp string)
	Reap(now time.Time) int
}

// MemoryDeviceStore 线程安全的内存设备 token 存储（dev / 单实例 cluster）。
type MemoryDeviceStore struct {
	mu    sync.RWMutex
	store map[string]*DeviceToken
}

// NewMemoryDeviceStore 创建一个空的内存设备 token 存储。
func NewMemoryDeviceStore() *MemoryDeviceStore {
	return &MemoryDeviceStore{store: make(map[string]*DeviceToken)}
}

// Put 写入。
func (s *MemoryDeviceStore) Put(t *DeviceToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.store[t.Fingerprint] = &cp
}

// Get 按指纹取。过期 → false（lazy cleanup）。
func (s *MemoryDeviceStore) Get(fp string) (*DeviceToken, bool) {
	s.mu.RLock()
	t, ok := s.store[fp]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if t.IsExpired(time.Now()) {
		s.mu.Lock()
		delete(s.store, fp)
		s.mu.Unlock()
		return nil, false
	}
	return t, true
}

// Exists 快速判断（含过期检查）。
func (s *MemoryDeviceStore) Exists(fp string) bool {
	_, ok := s.Get(fp)
	return ok
}

// Delete 显式删除。
func (s *MemoryDeviceStore) Delete(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, fp)
}

// Reap 清理过期 token。
func (s *MemoryDeviceStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for fp, t := range s.store {
		if t.IsExpired(now) {
			delete(s.store, fp)
			n++
		}
	}
	return n
}

// =====================================================================
// TOTPReplayStore 接口 + 内存/集群 KV 实现
// =====================================================================

// TOTPReplayStore TOTP 验证码防重放存储抽象。
// 在集群模式下应注入 KVTOTPReplayStore（共享 PostgreSQL 后端），
// 防止同一 TOTP 验证码在时间窗口内对不同副本各重放一次。
type TOTPReplayStore interface {
	MarkUsed(key string, now time.Time, ttl time.Duration) error
	Reap(now time.Time) int
}

// MemoryTOTPReplayStore 进程内内存 TOTP 防重放存储（dev / 单实例）。
type MemoryTOTPReplayStore struct {
	mu   sync.Mutex
	used map[string]time.Time // key -> expiresAt
}

// NewMemoryTOTPReplayStore 创建内存版 TOTP 防重放存储。
func NewMemoryTOTPReplayStore() *MemoryTOTPReplayStore {
	return &MemoryTOTPReplayStore{used: make(map[string]time.Time)}
}

// MarkUsed 原子检查并标记 key 已使用；若未过期则拒绝并返回 auth.ErrTOTPAlreadyUsed。
func (s *MemoryTOTPReplayStore) MarkUsed(key string, now time.Time, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.used {
		if !now.Before(exp) {
			delete(s.used, k)
		}
	}
	if exp, exists := s.used[key]; exists && now.Before(exp) {
		return auth.ErrTOTPAlreadyUsed
	}
	s.used[key] = now.Add(ttl)
	return nil
}

// Reap 清理过期记录。
func (s *MemoryTOTPReplayStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, exp := range s.used {
		if !now.Before(exp) {
			delete(s.used, k)
			n++
		}
	}
	return n
}

// KVTOTPReplayStore 基于共享 storage.KVStore 的集群级 TOTP 防重放存储。
// 利用 WithTx + RowLocker (SELECT FOR UPDATE) 保证跨副本原子防重放。
type KVTOTPReplayStore struct {
	kv storage.KVStore
	ns string
}

// NewKVTOTPReplayStore 创建基于共享 KVStore 的 TOTP 防重放存储。
func NewKVTOTPReplayStore(kv storage.KVStore) *KVTOTPReplayStore {
	return &KVTOTPReplayStore{
		kv: kv,
		ns: "admin:totp_used:",
	}
}

func (s *KVTOTPReplayStore) k(key string) string { return s.ns + key }

// MarkUsed 在共享 KV 事务内原子检查并写入已用 TOTP key。
func (s *KVTOTPReplayStore) MarkUsed(key string, now time.Time, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fullKey := s.k(key)

	return s.kv.WithTx(ctx, func(tx storage.KVStore) error {
		var raw []byte
		var err error
		if rl, ok := tx.(storage.RowLocker); ok {
			raw, err = rl.GetForUpdate(ctx, fullKey)
		} else {
			raw, err = tx.Get(ctx, fullKey)
		}
		if err == nil && len(raw) > 0 {
			var exp time.Time
			if jsonErr := json.Unmarshal(raw, &exp); jsonErr == nil && now.Before(exp) {
				return auth.ErrTOTPAlreadyUsed
			}
		}
		buf, mErr := json.Marshal(now.Add(ttl))
		if mErr != nil {
			return mErr
		}
		return tx.Put(ctx, fullKey, buf)
	})
}

// Reap 扫描并清理已过期的 TOTP 防重放记录。
func (s *KVTOTPReplayStore) Reap(now time.Time) int {
	ps, ok := s.kv.(storage.PrefixScanner)
	if !ok {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entries, err := ps.ScanPrefix(ctx, s.ns)
	if err != nil {
		return 0
	}
	n := 0
	for fullKey, raw := range entries {
		var exp time.Time
		if json.Unmarshal(raw, &exp) == nil && !now.Before(exp) {
			_ = s.kv.Delete(ctx, fullKey)
			n++
		}
	}
	return n
}
