// Package admin - Device Token（v1.4.2）。
//
// 设计：勾选"记住此设备 30 天"后，下一次登录用同样指纹自动跳过验证码 + TOTP。
// 仍需 adminToken 密码技术（不被完全绕过）。
//
// 设备指纹：HMAC-SHA-256(sessionSecret, JSON(ua,lang,plat,screen,tz))
//   - 任意浏览器属性变化 → 指纹失效（接受为退化路径）
//   - salt (sessionSecret) 防伪造，服务端不暴露
//
// 安全风险与缓解：
//   - 浏览器升级 / OS 升级 → UA 变化 → 失效（用户重新走完整登录）
//   - salt 泄露 → 历史设备 token 全可伪造（接受：salt 失守=会话体系崩）
//   - 用户无法主动撤销（v1.4.2 不在范围；v1.5.0 加 device 管理 UI）
package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
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
