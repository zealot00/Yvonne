// Package storage 定义 Yvonne KMS 的持久化抽象。
//
// 设计原则：
//   - Backend 接口极简，仅暴露 KV + 字段级覆写 + 事务能力。
//   - 所有密钥材料均以密文形式存储；明文绝不落盘。
//   - Delete 永远是物理删除（Crypto-Shredding），不做软删除。
//   - BoltDB / Postgres 两个实现均需满足 "字段级物理覆写" 语义。
package storage

import (
	"context"
	"errors"
)

// Backend 是 Yvonne 的统一持久化后端。
//
// 错误约定：
//   - ErrNotFound: 键不存在
//   - 其他错误: 由具体后端包装
type Backend interface {
	// Get 返回 keyName 对应的值。keyName 不存在时返回 ErrNotFound。
	Get(ctx context.Context, keyName []byte) ([]byte, error)

	// Put 写入 keyName/value。value 为空等价于删除。
	Put(ctx context.Context, keyName, value []byte) error

	// Delete 物理删除 keyName。Crypto-Shredding 由此触发；
	// 实现必须保证物理覆写，不可仅做逻辑标记。
	Delete(ctx context.Context, keyName []byte) error

	// ScanPrefix 按 prefix 顺序遍历所有键值对。
	// 用于密钥列表、版本枚举等只读场景。
	ScanPrefix(ctx context.Context, prefix []byte) (items []KVItem, err error)

	// Batch 在单事务内执行多个 Put/Delete，全部成功或全部回滚。
	Batch(ctx context.Context, ops []Op) error

	// Close 释放后端资源。
	Close() error
}

// KVItem 是 ScanPrefix 的单条结果。
type KVItem struct {
	Key   []byte
	Value []byte
}

// Op 是 Batch 的单条操作。
type Op struct {
	Kind  OpKind
	Key   []byte
	Value []byte // Delete 时忽略
}

type OpKind int

const (
	OpPut OpKind = iota
	OpDelete
)

// ErrNotFound 键不存在。
var ErrNotFound = errors.New("storage: key not found")

// TxNotifier 是事务内可执行的缓存失效通知接口（Bug-2 修复）。
//
// PostgresKVStore 的 pgTx 实现此接口，在 WithTx 闭包内调用
// NotifyInvalidationInTx，利用 PG NOTIFY 与事务同提交/回滚的原子性，
// 消除"事务提交成功但通知丢失"的窗口。
//
// 未实现此接口的 store（MemoryStore/BoltDB）在事务外回退到 NotifyInvalidation。
type TxNotifier interface {
	NotifyInvalidationInTx(ctx context.Context, keyID string) error
}

// PagedPrefixScanner 是支持分页前缀扫描的存储接口（Bug-5 修复）。
//
// ScanPrefix 一次性返回全部结果，在百万级历史版本场景下会引发 OOM。
// PagedPrefixScanner 提供 Limit/Offset 分页查询，保证常数级内存开销。
//
// MemoryStore 和 PostgresKVStore 均实现此接口。
type PagedPrefixScanner interface {
	// ScanPrefixPaged 按 prefix 分页扫描。
	// offset: 跳过前 N 条；limit: 最多返回 N 条（0 = 默认 1000）。
	// 返回 (items, total, error)，total 是匹配 prefix 的总条数（用于估算分页数）。
	ScanPrefixPaged(ctx context.Context, prefix string, offset, limit int) (items []KVItem, total int, err error)
}
