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
