// Package lifecycle 管理 Yvonne 业务 DEK 的元数据与状态流转。
//
// 状态机：Active → Deactivated → Destroyed
//
// 并发控制：
//   - 所有 KVStore 实现都支持 WithTx。
//   - PostgresKVStore 事务内用 SELECT FOR UPDATE 行级锁。
//   - MemoryStore 事务内用 mu.Lock 模拟。
//   - Manager 级 mu 仅用于 findLatestVersion 等非事务路径的互斥。
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// KeyState 是 DEK 的生命周期状态。
type KeyState string

const (
	StateActive      KeyState = "Active"
	StateDeactivated KeyState = "Deactivated"
	StateSoftDeleted KeyState = "SoftDeleted" // 软删除：数据保留在回收站，可恢复
	StateDestroyed   KeyState = "Destroyed"   // 物理粉碎：不可逆
)

// DefaultSoftDeleteTTL 软删除默认存活时间（90 天后自动物理粉碎）。
const DefaultSoftDeleteTTL = 90 * 24 * time.Hour

// KeyMetadata 是密钥的元数据。仅含密文，无明文。
type KeyMetadata struct {
	KeyID              string    `json:"key_id"`
	Version            int       `json:"version"`
	State              KeyState  `json:"state"`
	KeyType            string    `json:"key_type"`
	EncryptedMaterial  []byte    `json:"encrypted_material"`
	KEKType            string    `json:"kek_type,omitempty"` // "software"|"hsm"，空值=software（旧数据兼容）
	PublicKey          []byte    `json:"public_key,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	DeletedAt          time.Time `json:"deleted_at,omitempty"`
	RotationPeriodDays int       `json:"rotation_period_days,omitempty"`
	NextRotationAt     time.Time `json:"next_rotation_at,omitempty"`
}

func metadataKey(keyID string, version int) string {
	return fmt.Sprintf("key:%s:v:%d", keyID, version)
}

// Manager 管理业务 DEK 的生命周期。
type Manager struct {
	store         storage.KVStore
	mu            sync.Mutex
	cache         *dekCache
	notifier      Notifier
	maxGlobalKeys int // 0=不限制
}

// ErrQuotaExceeded 全局密钥配额超限。
var ErrQuotaExceeded = errors.New("lifecycle: global key quota exceeded")

// Notifier 接口用于在 Rotate/Shred 后触发集群缓存失效通知。
// PostgresKVStore 实现此接口；MemoryStore 不实现（单机无需通知）。
type Notifier interface {
	NotifyInvalidation(keyID string) error
}

// NewManager 创建 lifecycle Manager。
func NewManager(store storage.KVStore) *Manager {
	return &Manager{
		store: store,
		cache: newDekCache(),
	}
}

// SetMaxGlobalKeys 设置全局密钥数量上限（0=不限制）。
// 超限时 CreateKey 返回 ErrQuotaExceeded。
func (m *Manager) SetMaxGlobalKeys(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxGlobalKeys = max
}

// SetNotifier 注入集群缓存失效通知器。
// 在 bootstrap 装配阶段调用（仅 PostgresKVStore 需注入）。
func (m *Manager) SetNotifier(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifier = n
}

// InvalidateCache 删除指定 keyID 的所有缓存版本。
// 由 pg_listener 在收到 NOTIFY 时调用。
func (m *Manager) InvalidateCache(keyID string) {
	m.cache.invalidate(keyID)
}

// ClearCache 清空整个缓存池。
// 由 pg_listener 在断线重连后调用。
func (m *Manager) ClearCache() {
	m.cache.clear()
}

// GenerateDataKey 生成临时 DEK 并用 Active 版本的密钥加密。
//
// 职责分离（关键）：
//   - 临时 DEK 不存入数据库，KMS 仅负责用现役密钥包装它。
//   - 返回明文 DEK（SecureBuffer，调用方负责 Wipe）+ 密文 DEK（版本化自路由格式）。
//   - 客户端用明文 DEK 本地加密数据，用完丢弃；密文 DEK 存储在业务侧。
//   - 解密时客户端将密文 DEK 发回 KMS Decrypt API，KMS 返回明文 DEK。
//
// 流程：
//  1. 获取 KeyID 的 Active 版本元数据
//  2. 用 MasterKey 解密存储的 DEK 密文 → 明文 DEK
//  3. 生成全新 32 字节随机临时 DEK
//  4. 用存储的 DEK 加密临时 DEK → 版本化密文
//  5. 返回临时 DEK（明文 SecureBuffer）+ 版本化密文
func (m *Manager) GenerateDataKey(ctx context.Context, keyID string, kek seal.KEK) (*memguard.SecureBuffer, []byte, error) {
	if keyID == "" {
		return nil, nil, errors.New("lifecycle: empty key id")
	}
	if kek == nil {
		return nil, nil, errors.New("lifecycle: kek is nil")
	}

	// 1. 获取 Active 版本（状态机强制：只有 Active 能用于加密）。
	meta, err := m.GetActiveKey(ctx, keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle: gdk get active key: %w", err)
	}

	// 2. 生成全新 32 字节随机临时 DEK。
	plainDEK, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle: gdk generate random DEK: %w", err)
	}

	// 3. 用 KEK 解密存储的 DEK，然后用存储的 DEK 加密临时 DEK。
	storedDEK, err := kek.UnwrapDEK(meta.EncryptedMaterial)
	if err != nil {
		plainDEK.Wipe()
		return nil, nil, fmt.Errorf("lifecycle: gdk unwrap stored DEK: %w", err)
	}
	defer storedDEK.Wipe()

	// 4. 用存储的 DEK 加密临时 DEK → 版本化密文（自路由格式）。
	var ciphertext []byte
	err = plainDEK.WithKey(func(dek []byte) error {
		var e error
		ciphertext, e = crypto.EncryptVersioned(storedDEK, uint32(meta.Version), dek)
		return e
	})
	if err != nil {
		plainDEK.Wipe()
		return nil, nil, fmt.Errorf("lifecycle: gdk encrypt temporary DEK: %w", err)
	}

	return plainDEK, ciphertext, nil
}

// CreateKey 生成新 DEK 并存储元数据。
// rotationPeriodDays=0 表示不自动轮转。
func (m *Manager) CreateKey(ctx context.Context, keyID string, kek seal.KEK, rotationPeriodDays int) (*KeyMetadata, *memguard.SecureBuffer, error) {
	if keyID == "" {
		return nil, nil, errors.New("lifecycle: empty key id")
	}
	if kek == nil {
		return nil, nil, errors.New("lifecycle: kek is nil")
	}

	// 全局密钥配额检查。
	if m.maxGlobalKeys > 0 {
		count, err := m.countKeys(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("lifecycle: quota check: %w", err)
		}
		if count >= m.maxGlobalKeys {
			return nil, nil, ErrQuotaExceeded
		}
	}

	// 生成 32 字节随机 DEK。
	plaintextDEK, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle: generate data key: %w", err)
	}

	// 用 KEK 加密 DEK。
	encryptedDEK, err := kek.WrapDEK(plaintextDEK)
	if err != nil {
		plaintextDEK.Wipe()
		return nil, nil, fmt.Errorf("lifecycle: wrap DEK: %w", err)
	}

	now := time.Now().UTC()
	meta := KeyMetadata{
		KeyID:              keyID,
		Version:            1,
		State:              StateActive,
		EncryptedMaterial:  encryptedDEK,
		KEKType:            string(kek.Type()),
		CreatedAt:          now,
		RotationPeriodDays: rotationPeriodDays,
	}
	if rotationPeriodDays > 0 {
		meta.NextRotationAt = now.Add(time.Duration(rotationPeriodDays) * 24 * time.Hour)
	}

	if err := m.saveMetadata(ctx, meta); err != nil {
		plaintextDEK.Wipe()
		return nil, nil, fmt.Errorf("lifecycle: save metadata: %w", err)
	}

	return &meta, plaintextDEK, nil
}

// CreateAsymmetricKey 生成非对称密钥对（RSA-4096 或 ECDSA P-256）。
//
// 安全流程（致命约束）：
//  1. 生成私钥 → 序列化为 PKCS#8 DER → 立即装入 SecureBuffer → clear(derBytes)
//  2. 用 MasterKey 信封加密 DER SecureBuffer → 得到密文
//  3. 公钥序列化为 PEM（明文存储，非敏感）
//  4. 存储 KeyMetadata（含 KeyType + 密文 + 公钥 PEM）
//
// 返回：
//   - meta: 密钥元数据（含公钥 PEM，不含私钥明文）
//   - 无明文私钥返回（私钥仅在 KMS 内部解密后用于签名，不暴露给调用方）
func (m *Manager) CreateAsymmetricKey(ctx context.Context, keyID, algoType string, kek seal.KEK) (*KeyMetadata, error) {
	if keyID == "" {
		return nil, errors.New("lifecycle: empty key id")
	}
	if kek == nil {
		return nil, errors.New("lifecycle: kek is nil")
	}
	if algoType != crypto.KeyTypeRSA && algoType != crypto.KeyTypeECDSA {
		return nil, fmt.Errorf("lifecycle: unsupported key type %q, want %q or %q", algoType, crypto.KeyTypeRSA, crypto.KeyTypeECDSA)
	}

	// 1. 生成非对称密钥对。
	rsaPriv, ecdsaPriv, err := crypto.GenerateAsymmetricKey(algoType)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: generate asymmetric key: %w", err)
	}

	// 2. 私钥序列化为 PKCS#8 DER → 立即装入 SecureBuffer → clear 明文 DER。
	var privKey interface{}
	if rsaPriv != nil {
		privKey = rsaPriv
	} else {
		privKey = ecdsaPriv
	}

	derSB, err := crypto.PrivateKeyToSecureDER(privKey)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: serialize private key to secure DER: %w", err)
	}
	defer derSB.Wipe()

	// 3. 用 KEK 信封加密私钥 DER。
	encryptedMaterial, err := kek.WrapDEK(derSB)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: encrypt private key: %w", err)
	}

	// 4. 公钥序列化为 PEM。
	var pubKey interface{}
	if rsaPriv != nil {
		pubKey = &rsaPriv.PublicKey
	} else {
		pubKey = &ecdsaPriv.PublicKey
	}
	pubPEM, err := crypto.PublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: serialize public key: %w", err)
	}

	// 5. 构造元数据。
	meta := KeyMetadata{
		KeyID:             keyID,
		Version:           1,
		State:             StateActive,
		KeyType:           algoType,
		EncryptedMaterial: encryptedMaterial,
		KEKType:           string(kek.Type()),
		PublicKey:         pubPEM,
		CreatedAt:         time.Now().UTC(),
	}

	if err := m.saveMetadata(ctx, meta); err != nil {
		return nil, fmt.Errorf("lifecycle: save metadata: %w", err)
	}

	return &meta, nil
}

func (m *Manager) saveMetadata(ctx context.Context, meta KeyMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("lifecycle: marshal metadata: %w", err)
	}
	key := metadataKey(meta.KeyID, meta.Version)
	if err := m.store.Put(ctx, key, data); err != nil {
		return fmt.Errorf("lifecycle: put metadata: %w", err)
	}
	return nil
}

func (m *Manager) loadMetadata(ctx context.Context, keyID string, version int) (*KeyMetadata, error) {
	key := metadataKey(keyID, version)

	// 先查缓存。
	if meta, ok := m.cache.get(key); ok {
		return meta, nil
	}

	// 缓存未命中，查 DB。
	data, err := m.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var meta KeyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("lifecycle: unmarshal metadata: %w", err)
	}

	// 写入缓存。
	m.cache.put(key, &meta)
	return &meta, nil
}

func (m *Manager) findLatestVersion(ctx context.Context, keyID string) (int, error) {
	for v := 1; ; v++ {
		key := metadataKey(keyID, v)
		_, err := m.store.Get(ctx, key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				if v == 1 {
					return 0, storage.ErrNotFound
				}
				return v - 1, nil
			}
			return 0, err
		}
	}
}

// findLatestVersionInTx 在事务内查找最新版本号，用 RowLocker 避免重入锁。
func (m *Manager) findLatestVersionInTx(ctx context.Context, txStore storage.KVStore, keyID string) (int, error) {
	rl, _ := txStore.(storage.RowLocker)
	for v := 1; ; v++ {
		key := metadataKey(keyID, v)
		var err error
		if rl != nil {
			_, err = rl.GetForUpdate(ctx, key)
		} else {
			_, err = txStore.Get(ctx, key)
		}
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				if v == 1 {
					return 0, storage.ErrNotFound
				}
				return v - 1, nil
			}
			return 0, err
		}
	}
}

// RotateKey 轮转密钥。
func (m *Manager) RotateKey(ctx context.Context, keyID string, kek seal.KEK) (*KeyMetadata, *memguard.SecureBuffer, error) {
	if keyID == "" {
		return nil, nil, errors.New("lifecycle: empty key id")
	}
	if kek == nil {
		return nil, nil, errors.New("lifecycle: kek is nil")
	}

	var newMeta *KeyMetadata
	var plaintextDEK *memguard.SecureBuffer

	err := m.store.WithTx(ctx, func(txStore storage.KVStore) error {
		latestV, err := m.findLatestVersionInTx(ctx, txStore, keyID)
		if err != nil {
			return err
		}

		oldKey := metadataKey(keyID, latestV)
		rl, _ := txStore.(storage.RowLocker)
		var oldData []byte
		if rl != nil {
			oldData, err = rl.GetForUpdate(ctx, oldKey)
		} else {
			oldData, err = txStore.Get(ctx, oldKey)
		}
		if err != nil {
			return fmt.Errorf("lifecycle: lock old version: %w", err)
		}

		var oldMeta KeyMetadata
		if err := json.Unmarshal(oldData, &oldMeta); err != nil {
			return fmt.Errorf("lifecycle: unmarshal old metadata: %w", err)
		}
		if oldMeta.State != StateActive {
			return fmt.Errorf("lifecycle: current version %d state is %s, not Active", latestV, oldMeta.State)
		}

		oldMeta.State = StateDeactivated
		updatedData, err := json.Marshal(oldMeta)
		if err != nil {
			return fmt.Errorf("lifecycle: marshal deactivated metadata: %w", err)
		}
		if err := txStore.Put(ctx, oldKey, updatedData); err != nil {
			return fmt.Errorf("lifecycle: update old version: %w", err)
		}

		plainDEK, err := memguard.NewSecureBufferFromRandom(32)
		if err != nil {
			return fmt.Errorf("lifecycle: generate new data key: %w", err)
		}
		encryptedDEK, err := kek.WrapDEK(plainDEK)
		if err != nil {
			plainDEK.Wipe()
			return fmt.Errorf("lifecycle: wrap new DEK: %w", err)
		}

		now := time.Now().UTC()
		newMeta = &KeyMetadata{
			KeyID:              keyID,
			Version:            latestV + 1,
			State:              StateActive,
			EncryptedMaterial:  encryptedDEK,
			KEKType:            string(kek.Type()),
			CreatedAt:          now,
			RotationPeriodDays: oldMeta.RotationPeriodDays,
		}
		if oldMeta.RotationPeriodDays > 0 {
			newMeta.NextRotationAt = now.Add(time.Duration(oldMeta.RotationPeriodDays) * 24 * time.Hour)
		}
		newData, err := json.Marshal(newMeta)
		if err != nil {
			plainDEK.Wipe()
			return fmt.Errorf("lifecycle: marshal new metadata: %w", err)
		}
		if err := txStore.Put(ctx, metadataKey(keyID, newMeta.Version), newData); err != nil {
			plainDEK.Wipe()
			return fmt.Errorf("lifecycle: put new version: %w", err)
		}

		plaintextDEK = plainDEK
		return nil
	})

	if err != nil {
		if plaintextDEK != nil {
			plaintextDEK.Wipe()
		}
		return nil, nil, err
	}

	// 事务提交成功后：失效本地缓存 + 通知集群其他节点。
	m.cache.invalidate(keyID)
	m.notifyCluster(keyID)

	return newMeta, plaintextDEK, nil
}

// ShredKey 物理粉碎指定版本的 DEK。
//
// 流程：
//  1. 读取元数据（事务内加行级锁）
//  2. clear(EncryptedMaterial) 物理覆写
//  3. Put(key, {State:Destroyed, EncryptedMaterial:nil}) — UPDATE NULL
//  4. Delete(key) — DELETE
//  5. 事务提交后失效本地缓存 + NOTIFY 集群
func (m *Manager) ShredKey(ctx context.Context, keyID string, version int) error {
	err := m.store.WithTx(ctx, func(txStore storage.KVStore) error {
		key := metadataKey(keyID, version)

		rl, _ := txStore.(storage.RowLocker)
		var data []byte
		var err error
		if rl != nil {
			data, err = rl.GetForUpdate(ctx, key)
		} else {
			data, err = txStore.Get(ctx, key)
		}
		if err != nil {
			return fmt.Errorf("lifecycle: lock for shred: %w", err)
		}

		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("lifecycle: unmarshal for shred: %w", err)
		}

		if meta.EncryptedMaterial != nil {
			clear(meta.EncryptedMaterial)
			runtime.KeepAlive(meta.EncryptedMaterial)
		}
		meta.EncryptedMaterial = nil
		meta.State = StateDestroyed

		updatedData, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("lifecycle: marshal destroyed metadata: %w", err)
		}
		if err := txStore.Put(ctx, key, updatedData); err != nil {
			return fmt.Errorf("lifecycle: put destroyed metadata: %w", err)
		}

		if err := txStore.Delete(ctx, key); err != nil {
			return fmt.Errorf("lifecycle: delete after shred: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	// 事务提交成功后：失效本地缓存 + 通知集群。
	m.cache.invalidate(keyID)
	m.notifyCluster(keyID)
	return nil
}

// notifyCluster 通知集群其他节点缓存失效。
// 若 notifier 为 nil（MemoryStore），跳过（单机无需通知）。
func (m *Manager) notifyCluster(keyID string) {
	if m.notifier != nil {
		if err := m.notifier.NotifyInvalidation(keyID); err != nil {
			// NOTIFY 失败不阻断操作（已提交到 DB），但记录告警。
			fmt.Printf("lifecycle: WARNING cluster notify failed for key %s: %v\n", keyID, err)
		}
	}
}

// GetKey 读取指定版本的元数据。
func (m *Manager) GetKey(ctx context.Context, keyID string, version int) (*KeyMetadata, error) {
	return m.loadMetadata(ctx, keyID, version)
}

// GetActiveKey 返回指定 KeyID 当前状态为 Active 的唯一版本。
// 用于 encrypt handler：加密操作必须且只能用 Active 版本。
//
// 若不存在 Active 版本，返回 error（拒绝加密）。
func (m *Manager) GetActiveKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	latestV, err := m.findLatestVersion(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: find active key: %w", err)
	}

	meta, err := m.loadMetadata(ctx, keyID, latestV)
	if err != nil {
		return nil, err
	}

	// 硬编码状态边界：只有 Active 才能用于加密。
	if meta.State != StateActive {
		return nil, fmt.Errorf("lifecycle: key %s v%d state is %s, not Active — encrypt refused", keyID, latestV, meta.State)
	}

	return meta, nil
}

// GetKeyForDecrypt 返回指定 KeyID + Version 的元数据，用于解密。
//
// 状态行为边界（硬编码）：
//   - Active：允许解密 ✓
//   - Deactivated：允许解密 ✓（历史版本向后兼容）
//   - Destroyed：拒绝解密 ✗（密文不可恢复）
//
// 若状态为 Destroyed，返回 ErrKeyDestroyed。
// SoftDeleted 也允许解密（回收站内的密钥仍需可解密历史密文）。
func (m *Manager) GetKeyForDecrypt(ctx context.Context, keyID string, version int) (*KeyMetadata, error) {
	meta, err := m.loadMetadata(ctx, keyID, version)
	if err != nil {
		return nil, err
	}

	switch meta.State {
	case StateActive, StateDeactivated, StateSoftDeleted:
		return meta, nil
	case StateDestroyed:
		return nil, ErrKeyDestroyed
	default:
		return nil, fmt.Errorf("lifecycle: key %s v%d has unknown state %s", keyID, version, meta.State)
	}
}

// ErrKeyDestroyed 表示密钥已被物理粉碎，拒绝一切操作。
var ErrKeyDestroyed = errors.New("lifecycle: key is destroyed, all operations refused")

// --- 软删除与回收站 ---

// SoftDeleteKey 将指定版本标记为软删除（回收站），数据保留可恢复。
//
// 行为：
//   - Active/Deactivated → SoftDeleted（标记 DeletedAt 时间戳）
//   - SoftDeleted → 幂等返回 nil
//   - Destroyed → 返回 ErrKeyDestroyed
//
// 软删除后：
//   - 仍可解密历史密文（GetKeyForDecrypt 允许）
//   - 不可加密（GetActiveKey 拒绝）
//   - TTL 过期后由后台 goroutine 自动 ShredKey（物理粉碎）
func (m *Manager) SoftDeleteKey(ctx context.Context, keyID string, version int) error {
	return m.store.WithTx(ctx, func(txStore storage.KVStore) error {
		key := metadataKey(keyID, version)

		rl, _ := txStore.(storage.RowLocker)
		var data []byte
		var err error
		if rl != nil {
			data, err = rl.GetForUpdate(ctx, key)
		} else {
			data, err = txStore.Get(ctx, key)
		}
		if err != nil {
			return fmt.Errorf("lifecycle: soft-delete: lock key: %w", err)
		}

		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("lifecycle: soft-delete: unmarshal: %w", err)
		}

		// 幂等：已软删除则直接返回。
		if meta.State == StateSoftDeleted {
			return nil
		}

		// 已物理粉碎的不可软删除。
		if meta.State == StateDestroyed {
			return ErrKeyDestroyed
		}

		// 标记软删除。
		meta.State = StateSoftDeleted
		meta.DeletedAt = time.Now().UTC()

		updatedData, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("lifecycle: soft-delete: marshal: %w", err)
		}
		if err := txStore.Put(ctx, key, updatedData); err != nil {
			return fmt.Errorf("lifecycle: soft-delete: put: %w", err)
		}

		return nil
	})
}

// RestoreKey 从回收站恢复指定版本（SoftDeleted → Deactivated）。
//
// 恢复后的状态为 Deactivated（非 Active），因为原 Active 版本可能已被新版本替代。
// 如需用于加密，应显式 RotateKey 生成新 Active 版本。
//
// 行为：
//   - SoftDeleted → Deactivated（清空 DeletedAt）
//   - Active/Deactivated → 幂等返回 nil
//   - Destroyed → 返回 ErrKeyDestroyed
func (m *Manager) RestoreKey(ctx context.Context, keyID string, version int) error {
	return m.store.WithTx(ctx, func(txStore storage.KVStore) error {
		key := metadataKey(keyID, version)

		rl, _ := txStore.(storage.RowLocker)
		var data []byte
		var err error
		if rl != nil {
			data, err = rl.GetForUpdate(ctx, key)
		} else {
			data, err = txStore.Get(ctx, key)
		}
		if err != nil {
			return fmt.Errorf("lifecycle: restore: lock key: %w", err)
		}

		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("lifecycle: restore: unmarshal: %w", err)
		}

		// 幂等：非 SoftDeleted 状态直接返回。
		if meta.State != StateSoftDeleted {
			if meta.State == StateDestroyed {
				return ErrKeyDestroyed
			}
			return nil
		}

		// 恢复为 Deactivated（不可直接恢复为 Active，防并发冲突）。
		meta.State = StateDeactivated
		meta.DeletedAt = time.Time{} // 清空 DeletedAt

		updatedData, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("lifecycle: restore: marshal: %w", err)
		}
		if err := txStore.Put(ctx, key, updatedData); err != nil {
			return fmt.Errorf("lifecycle: restore: put: %w", err)
		}

		// 失效缓存 + 通知集群。
		m.cache.invalidate(keyID)
		return nil
	})
}

// StartSoftDeleteReaper 启动后台 goroutine，定期扫描并物理粉碎超过 TTL 的软删除密钥。
//
// 每 24 小时扫描一次，将 DeletedAt 超过 ttl 的 SoftDeleted 密钥执行 ShredKey。
//
// onReaped 回调用于记录审计日志（如 AUDIT_KEY_REAPED）。
func (m *Manager) StartSoftDeleteReaper(ttl time.Duration, onReaped func(keyID string, version int)) {
	if ttl == 0 {
		ttl = DefaultSoftDeleteTTL
	}
	go m.reaperLoop(ttl, onReaped)
}

func (m *Manager) reaperLoop(ttl time.Duration, onReaped func(keyID string, version int)) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.reapExpiredSoftDeletes(ttl, onReaped)
	}
}

// reapExpiredSoftDeletes 扫描并物理粉碎过期的软删除密钥。
//
// 扫描所有 "key:" 前缀的元数据，找出 State=SoftDeleted 且 DeletedAt 超过 ttl 的，
// 逐个执行 ShredKey 物理粉碎。
func (m *Manager) reapExpiredSoftDeletes(ttl time.Duration, onReaped func(keyID string, version int)) {
	scanner, ok := m.store.(storage.PrefixScanner)
	if !ok {
		// 存储不支持前缀扫描（理论上不会发生，MemoryStore 和 PostgresKVStore 都实现了）。
		return
	}

	ctx := context.Background()
	items, err := scanner.ScanPrefix(ctx, "key:")
	if err != nil {
		return
	}

	cutoff := time.Now().UTC().Add(-ttl)

	for _, data := range items {
		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		if meta.State != StateSoftDeleted {
			continue
		}

		if meta.DeletedAt.IsZero() || meta.DeletedAt.After(cutoff) {
			continue
		}

		// 物理粉碎。
		if err := m.ShredKey(ctx, meta.KeyID, meta.Version); err != nil {
			continue
		}

		if onReaped != nil {
			onReaped(meta.KeyID, meta.Version)
		}
	}
}

// ReapNow 立即执行一次回收站清理（用于测试或手动触发）。
func (m *Manager) ReapNow(ttl time.Duration, onReaped func(keyID string, version int)) {
	m.reapExpiredSoftDeletes(ttl, onReaped)
}

// countKeys 统计当前全局唯一 KeyID 数量（用于配额检查）。
// 通过 ScanPrefix 扫描 "key:" 前缀，去重 KeyID。
func (m *Manager) countKeys(ctx context.Context) (int, error) {
	scanner, ok := m.store.(storage.PrefixScanner)
	if !ok {
		return 0, nil // 不支持扫描的 store 不限制
	}

	items, err := scanner.ScanPrefix(ctx, "key:")
	if err != nil {
		return 0, err
	}

	seen := make(map[string]bool)
	for _, data := range items {
		var meta KeyMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		seen[meta.KeyID] = true
	}
	return len(seen), nil
}

// ErrKeyNotActive 表示密钥非 Active 状态，拒绝加密操作。
var ErrKeyNotActive = errors.New("lifecycle: key is not active, encrypt refused")
