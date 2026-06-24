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
package lifecycle

import "sync"

// dekCache 是 DEK 元数据的本地缓存。
type dekCache struct {
	mu   sync.RWMutex
	data map[string]*KeyMetadata // key: metadataKey(keyID, version)
}

// newDekCache 创建空缓存。
func newDekCache() *dekCache {
	return &dekCache{data: make(map[string]*KeyMetadata)}
}

// get 从缓存读取。
func (c *dekCache) get(key string) (*KeyMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	meta, ok := c.data[key]
	return meta, ok
}

// put 写入缓存。
func (c *dekCache) put(key string, meta *KeyMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = meta
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
}

// clear 清空整个缓存池。
// 断线重连后调用，防止期间错失 NOTIFY 导致脏数据。
func (c *dekCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*KeyMetadata)
}

// size 返回缓存条目数（用于测试）。
func (c *dekCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}
