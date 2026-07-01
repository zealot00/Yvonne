// Package storage - MemoryStore：基于 map 的纯内存 KVStore 实现。
//
// 红线（Crypto-Shredding）：
//   - Delete 绝对不能仅调用 delete(m.data, key)。
//   - 必须先取出 value 切片，用 clear(value) 物理覆写底层数组为 0，
//     紧跟 runtime.KeepAlive(value) 防 DCE，再 delete(m.data, key)。
//
// 并发安全：
//   - 所有读写操作必须持读写锁。
//   - Delete 的 clear + delete 必须在同一个写锁临界区内。
//
// 事务支持：
//   - WithTx 用 mu.Lock 模拟事务隔离（整个 store 加锁）。
//   - 事务内的 memTx 实现 KVStore + RowLocker。
package storage

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
)

// sortStrings 排序字符串切片（内存存储分页扫描需要稳定顺序）。
func sortStrings(s []string) { sort.Strings(s) }

// MemoryStore 是基于 sync.RWMutex + map 的纯内存 KVStore 实现。
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryStore 创建空的 MemoryStore。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string][]byte),
	}
}

// Put 写入 key/value。
func (m *MemoryStore) Put(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return fmt.Errorf("storage: empty key")
	}
	if len(value) == 0 {
		return m.Delete(ctx, key)
	}

	cp := make([]byte, len(value))
	copy(cp, value)

	m.mu.Lock()
	defer m.mu.Unlock()

	if old, exists := m.data[key]; exists {
		clear(old)
		runtime.KeepAlive(old)
	}
	m.data[key] = cp
	return nil
}

// Get 返回 key 对应的值（副本）。
func (m *MemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, exists := m.data[key]
	if !exists {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// Delete 物理粉碎 key 对应的 value。
func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, exists := m.data[key]
	if !exists {
		return nil
	}
	clear(v)
	runtime.KeepAlive(v)
	delete(m.data, key)
	return nil
}

// --- KVStore.WithTx 实现 ---

// WithTx 在事务内执行 fn。
// MemoryStore 用 mu.Lock 模拟事务隔离。
// 注意：MemoryStore 不支持真正的事务回滚；fn 失败时已写入的数据不会自动撤销。
func (m *MemoryStore) WithTx(ctx context.Context, fn func(txStore KVStore) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := &memTx{store: m, ctx: ctx}
	return fn(tx)
}

// memTx 是 MemoryStore 的事务上下文，实现 KVStore + RowLocker。
type memTx struct {
	store *MemoryStore
	ctx   context.Context
}

func (t *memTx) Put(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return fmt.Errorf("storage: empty key")
	}
	if len(value) == 0 {
		return t.Delete(ctx, key)
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	if old, exists := t.store.data[key]; exists {
		clear(old)
		runtime.KeepAlive(old)
	}
	t.store.data[key] = cp
	return nil
}

func (t *memTx) Get(ctx context.Context, key string) ([]byte, error) {
	v, exists := t.store.data[key]
	if !exists {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (t *memTx) Delete(ctx context.Context, key string) error {
	v, exists := t.store.data[key]
	if !exists {
		return nil
	}
	clear(v)
	runtime.KeepAlive(v)
	delete(t.store.data, key)
	return nil
}

// WithTx 嵌套事务：直接在当前锁内执行（MemoryStore 已持锁）。
func (t *memTx) WithTx(ctx context.Context, fn func(txStore KVStore) error) error {
	return fn(t)
}

// GetForUpdate 实现 RowLocker（MemoryStore 已在事务期间持写锁）。
func (t *memTx) GetForUpdate(ctx context.Context, key string) ([]byte, error) {
	return t.Get(ctx, key)
}

// ScanPrefix 实现 PrefixScanner：返回所有以 prefix 开头的 key-value 对。
func (m *MemoryStore) ScanPrefix(ctx context.Context, prefix string) (map[string][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]byte)
	for k, v := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			cp := make([]byte, len(v))
			copy(cp, v)
			result[k] = cp
		}
	}
	return result, nil
}

// ScanPrefixPaged 实现 PagedPrefixScanner（Bug-5 修复）。
// 按 prefix 分页扫描，避免一次性加载百万级记录导致 OOM。
// offset: 跳过前 N 条；limit: 最多返回 N 条（<=0 默认 1000）。
// 返回 (items, total, error)，total 是匹配 prefix 的总条数。
func (m *MemoryStore) ScanPrefixPaged(ctx context.Context, prefix string, offset, limit int) ([]KVItem, int, error) {
	if limit <= 0 {
		limit = 1000
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 先收集所有匹配的 key（排序保证分页稳定性）。
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	// 排序（map 迭代顺序随机，分页需要稳定顺序）。
	sortStrings(keys)

	total := len(keys)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	items := make([]KVItem, 0, end-offset)
	for _, k := range keys[offset:end] {
		v := m.data[k]
		cp := make([]byte, len(v))
		copy(cp, v)
		items = append(items, KVItem{Key: []byte(k), Value: cp})
	}
	return items, total, nil
}
