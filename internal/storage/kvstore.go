// Package storage - KVStore：纯净的密钥-值存储抽象（终极蓝图对齐版）。
//
// 接口设计（对齐蓝图）：
//   - 所有方法首参为 ctx context.Context，支持超时与取消透传。
//   - WithTx 合并到 KVStore 接口，callback 接收 KVStore（事务版本）。
//   - RowLocker 是可选接口，提供 SELECT FOR UPDATE 行级锁能力。
//     lifecycle.Manager 在事务内 type-assert 此接口获取行级锁。
//
// 红线：
//   - Delete 必须实现物理级粉碎（Crypto-Shredding）。
//   - value 是密文（已被 Master Key 加密），但仍需物理粉碎。
package storage

import "context"

// KVStore 是面向业务层的密钥元数据存储抽象。
//
// 所有方法首参为 ctx，支持超时与取消。
// WithTx 提供事务闭包：fn 返回 nil 提交，返回 error 回滚。
// 事务内 fn 接收的 txStore 是 KVStore 类型，可能同时实现 RowLocker。
type KVStore interface {
	// Put 写入 key/value。value 为空等价于删除。
	Put(ctx context.Context, key string, value []byte) error

	// Get 返回 key 对应的值。key 不存在时返回 ErrNotFound。
	Get(ctx context.Context, key string) ([]byte, error)

	// Delete 物理粉碎 key 对应的 value（Crypto-Shredding）。
	Delete(ctx context.Context, key string) error

	// WithTx 在事务内执行 fn。fn 返回 nil 提交，返回 error 回滚。
	// 事务内的 txStore 是 KVStore 类型，可能同时实现 RowLocker。
	WithTx(ctx context.Context, fn func(txStore KVStore) error) error
}

// RowLocker 是可选接口，提供行级锁能力。
type RowLocker interface {
	GetForUpdate(ctx context.Context, key string) ([]byte, error)
}

// PrefixScanner 是可选接口，提供前缀扫描能力。
// 用于回收站 reaper 扫描所有 key: 前缀的元数据。
// MemoryStore 和 PostgresKVStore 都实现此接口。
type PrefixScanner interface {
	ScanPrefix(ctx context.Context, prefix string) (map[string][]byte, error)
}
