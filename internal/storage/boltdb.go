// Package storage - BoltDB 后端实现。
//
// BoltDB 是嵌入式 B+tree KV，单机部署默认选择。优势：
//   - 纯 Go，无外部依赖；ACID；单文件易备份。
//   - 写操作以页级覆写完成，Delete 会物理释放页（满足 Crypto-Shredding）。
//
// 注意：BoltDB 的 db.Update 会确保脏页落盘后再提交，可满足审计 fsync 要求。
package storage

import (
	"context"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// BoltBackend 基于 bbolt 的 Backend 实现。
type BoltBackend struct {
	db   *bolt.DB
	root []byte // 根 bucket 名
}

// NewBoltBackend 打开 / 创建指定路径的 BoltDB 文件。
// rootBucket 为顶层 bucket 名（如 "yvonne"）。
func NewBoltBackend(path, rootBucket string) (*BoltBackend, error) {
	if path == "" {
		return nil, errors.New("boltdb: path required")
	}
	if rootBucket == "" {
		return nil, errors.New("boltdb: root bucket required")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout:      0,
		NoGrowSync:   false,
		FreelistType: bolt.FreelistArrayType,
	})
	if err != nil {
		return nil, fmt.Errorf("boltdb: open %s: %w", path, err)
	}
	// 预创建根 bucket
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("boltdb: create root bucket: %w", err)
	}
	return &BoltBackend{db: db, root: []byte(rootBucket)}, nil
}

func (b *BoltBackend) Get(ctx context.Context, keyName []byte) ([]byte, error) {
	var out []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(b.root)
		if bk == nil {
			return ErrNotFound
		}
		v := bk.Get(keyName)
		if v == nil {
			return ErrNotFound
		}
		// bbolt 的 Get 返回的是 mmap 引用，事务结束即失效，必须拷贝。
		out = append(out, v...)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("boltdb: get: %w", err)
	}
	return out, nil
}

func (b *BoltBackend) Put(ctx context.Context, keyName, value []byte) error {
	if len(value) == 0 {
		return b.Delete(ctx, keyName)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists(b.root)
		if err != nil {
			return err
		}
		return bk.Put(keyName, value)
	})
}

func (b *BoltBackend) Delete(ctx context.Context, keyName []byte) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(b.root)
		if bk == nil {
			return nil // 没有根 bucket，视为已删除
		}
		// bbolt 的 Delete 会释放页到 freelist，后续写操作会物理覆写。
		return bk.Delete(keyName)
	})
}

func (b *BoltBackend) ScanPrefix(ctx context.Context, prefix []byte) ([]KVItem, error) {
	var out []KVItem
	err := b.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(b.root)
		if bk == nil {
			return nil
		}
		c := bk.Cursor()
		for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
			item := KVItem{
				Key:   append([]byte(nil), k...),
				Value: append([]byte(nil), v...),
			}
			out = append(out, item)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("boltdb: scan prefix: %w", err)
	}
	return out, nil
}

func (b *BoltBackend) Batch(ctx context.Context, ops []Op) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists(b.root)
		if err != nil {
			return err
		}
		for _, op := range ops {
			switch op.Kind {
			case OpPut:
				if len(op.Value) == 0 {
					if err := bk.Delete(op.Key); err != nil {
						return err
					}
					continue
				}
				if err := bk.Put(op.Key, op.Value); err != nil {
					return err
				}
			case OpDelete:
				if err := bk.Delete(op.Key); err != nil {
					return err
				}
			default:
				return fmt.Errorf("boltdb: unknown op kind %d", op.Kind)
			}
		}
		return nil
	})
}

func (b *BoltBackend) Close() error {
	if b.db != nil {
		return b.db.Close()
	}
	return nil
}

func hasPrefix(b, prefix []byte) bool {
	if len(prefix) > len(b) {
		return false
	}
	for i, p := range prefix {
		if b[i] != p {
			return false
		}
	}
	return true
}
