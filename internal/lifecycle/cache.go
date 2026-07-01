// Package lifecycle - DEK 缓存层。
//
// 通过本地内存缓存 KeyMetadata，避免每次加解密都查 DB。
// 多节点一致性通过 Postgres LISTEN/NOTIFY 实现：
//   - Rotate/Shred 提交后 NOTIFY 通知所有节点。
//   - pg_listener 收到通知调 InvalidateCache。
//   - 断线重连后 ClearCache（防期间错失通知）。
//
// 安全：
//   - KeyMetadata 仅含密文，无明文。缓存淘汰直接 delete(map, key)。
//   - 缓存读写用 sync.RWMutex 保护。
//
// Bug-4 修复（空值缓存防穿透）:
//   - DB 返回 ErrNotFound 时缓存 nil 标记 + 短 TTL（默认 5s）。
//   - 防止攻击者用伪造的极大版本号砸穿缓存耗尽 DB 连接池。
package lifecycle

import (
	"sync"
	"time"
)

// dekCache 是 DEK 元数据的本地缓存。
type dekCache struct {
	mu   sync.RWMutex
	data map[string]*KeyMetadata // key: metadataKey(keyID, version)

	// Bug-4: 空值缓存（negative cache），防版本号穿透攻击。
	negative    map[string]time.Time // key → 过期时间
	negativeTTL time.Duration        // 空值缓存 TTL（默认 5s）
}

// newDekCache 创建空缓存。
func newDekCache() *dekCache {
	return &dekCache{
		data:        make(map[string]*KeyMetadata),
		negative:    make(map[string]time.Time),
		negativeTTL: 5 * time.Second, // Bug-4: 短 TTL，平衡穿透防护与新增密钥可见性
	}
}

// get 从缓存读取。
// 返回 (meta, true) 表示命中正缓存；返回 (nil, false) 表示未命中（需查 DB）。
// 注意：调用方需配合 isNegative 使用，区分"未命中"和"已知不存在"。
func (c *dekCache) get(key string) (*KeyMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	meta, ok := c.data[key]
	return meta, ok
}

// put 写入正缓存。
func (c *dekCache) put(key string, meta *KeyMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = meta
	// 写正缓存时清除该 key 的负缓存。
	delete(c.negative, key)
}

// putNegative 写入空值缓存（Bug-4 修复）。
// DB 返回 ErrNotFound 时调用，TTL 内相同 key 的请求直接返回"不存在"。
func (c *dekCache) putNegative(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.negative[key] = time.Now().Add(c.negativeTTL)
}

// isNegative 检查是否命中空值缓存（Bug-4 修复）。
// 返回 true 表示该 key 在 TTL 内被标记为"已知不存在"。
func (c *dekCache) isNegative(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	expiry, ok := c.negative[key]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		return false // 已过期
	}
	return true
}

// invalidate 删除指定 keyID 的所有版本缓存。
// KeyMetadata 仅含密文无明文，直接 delete 安全。
func (c *dekCache) invalidate(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// 遍历删除所有以 "key:<keyID>:v:" 为前缀的条目。
	prefix := "key:" + keyID + ":v:"
	for k := range c.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.data, k)
		}
	}
	// 同步清除负缓存（密钥可能刚被创建，旧负缓存过期）。
	for k := range c.negative {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.negative, k)
		}
	}
	// 清除 latest version 元数据的负缓存。
	delete(c.negative, latestVersionMetadataKey(keyID))
}

// clear 清空整个缓存池。
// 断线重连后调用，防止期间错失 NOTIFY 导致脏数据。
func (c *dekCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*KeyMetadata)
	c.negative = make(map[string]time.Time)
}

// size 返回缓存条目数（用于测试）。
func (c *dekCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}
