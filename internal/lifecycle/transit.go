// Package lifecycle - BYOK 传输密钥管理。
//
// 流程：
//  1. 客户端 GET /api/v1/keys/transit-pub → 获取临时 RSA-4096 公钥 PEM
//  2. 客户端离线用公钥加密外部 DEK → WrappedMaterial
//  3. 客户端 POST /api/v1/keys/import { KeyID, WrappedMaterial }
//  4. Yvonne 用临时私钥 RSA-OAEP 解密 → 明文 DEK
//  5. 立即用 CMK 信封加密 → Yvonne 标准密文
//  6. 存入 DB（V1 Active）
//  7. 阅后即焚：擦除临时私钥
//
// 安全：
//   - 临时私钥装入 SecureBuffer，存于内存 Map（TTL 10 分钟）
//   - TTL 过期或导入成功后彻底 Wipe
//   - 明文 DEK 用完立即 clear
package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// TransitKeyTTL 传输密钥存活时间（10 分钟）。
const TransitKeyTTL = 10 * time.Minute

// transitEntry 是内存中的传输密钥条目。
type transitEntry struct {
	privateKey *memguard.SecureBuffer // RSA 私钥 DER（PKCS#8）
	publicKey  []byte                 // 公钥 PEM（明文，非敏感）
	expiresAt  time.Time
}

// TransitKeyManager 管理临时传输密钥的生命周期。
type TransitKeyManager struct {
	mu   sync.RWMutex
	keys map[string]*transitEntry // keyID → entry
}

// NewTransitKeyManager 创建传输密钥管理器。
func NewTransitKeyManager() *TransitKeyManager {
	return &TransitKeyManager{
		keys: make(map[string]*transitEntry),
	}
}

// TransitPublicKey 是返回给客户端的公钥结构。
type TransitPublicKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"` // PEM 格式
	ExpiresAt time.Time `json:"expires_at"`
}

// GenerateTransitKey 生成临时 RSA-4096 传输密钥对。
//
// 返回公钥 PEM（给客户端）+ keyID（用于后续导入时查找私钥）。
// 私钥以 DER 格式装入 SecureBuffer，存于内存 Map。
func (t *TransitKeyManager) GenerateTransitKey() (*TransitPublicKey, error) {
	// 1. 生成 RSA-4096 密钥对。
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("transit: generate RSA-4096: %w", err)
	}

	// 2. 私钥序列化为 PKCS#8 DER → SecureBuffer。
	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("transit: marshal private key: %w", err)
	}
	privSB := memguard.NewSecureBuffer(derBytes)
	// 清零临时 DER（NewSecureBuffer 已拷贝）。
	for i := range derBytes {
		derBytes[i] = 0
	}

	// 3. 公钥序列化为 PEM。
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		privSB.Wipe()
		return nil, fmt.Errorf("transit: marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	// 4. 生成 keyID（用于关联公私钥）。
	keyID := fmt.Sprintf("transit-%d", time.Now().UnixNano())

	entry := &transitEntry{
		privateKey: privSB,
		publicKey:  pubPEM,
		expiresAt:  time.Now().UTC().Add(TransitKeyTTL),
	}

	t.mu.Lock()
	t.keys[keyID] = entry
	t.mu.Unlock()

	return &TransitPublicKey{
		KeyID:     keyID,
		PublicKey: string(pubPEM),
		ExpiresAt: entry.expiresAt,
	}, nil
}

// UnwrapWithTransitKey 用传输私钥解密 WrappedMaterial。
//
// 流程：
//  1. 查找 keyID 对应的私钥
//  2. RSA-OAEP SHA-256 解密
//  3. 返回明文（[]byte，调用方负责清理）
//  4. 阅后即焚：Wipe 私钥 + 从 Map 删除
//
// 如果 keyID 不存在或已过期，返回 error。
func (t *TransitKeyManager) UnwrapWithTransitKey(keyID string, wrappedMaterial []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.keys[keyID]
	if !ok {
		return nil, errors.New("transit: key not found (expired or already used)")
	}

	// 检查 TTL。
	if time.Now().UTC().After(entry.expiresAt) {
		entry.privateKey.Wipe()
		delete(t.keys, keyID)
		return nil, errors.New("transit: key expired")
	}

	// 用私钥 RSA-OAEP 解密。
	var plaintext []byte
	err := entry.privateKey.WithKey(func(der []byte) error {
		privKey, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return fmt.Errorf("transit: parse private key: %w", err)
		}
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("transit: not an RSA private key")
		}

		var e error
		plaintext, e = rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			rsaPriv,
			wrappedMaterial,
			nil, // label
		)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("transit: RSA decrypt: %w", err)
	}

	// 阅后即焚：擦除私钥 + 从 Map 删除。
	entry.privateKey.Wipe()
	delete(t.keys, keyID)

	return plaintext, nil
}

// CleanupExpired 清理所有过期的传输密钥。
// 应由后台定时调用。
func (t *TransitKeyManager) CleanupExpired() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	for keyID, entry := range t.keys {
		if now.After(entry.expiresAt) {
			entry.privateKey.Wipe()
			delete(t.keys, keyID)
		}
	}
}

// ImportKey 将外部 DEK 导入 Yvonne 纳管。
//
// 流程：
//  1. 用传输私钥解密 wrappedMaterial → 明文 DEK
//  2. 立即用 CMK 信封加密 → Yvonne 标准密文
//  3. 存入 DB（V1 Active）
//  4. 明文 DEK Wipe
//
// targetKeyID 是导入后的 Yvonne 密钥标识。
func (m *Manager) ImportKey(ctx context.Context, targetKeyID string, transitKeyID string, wrappedMaterial []byte, transitMgr *TransitKeyManager, kek seal.KEK) (*KeyMetadata, error) {
	if targetKeyID == "" {
		return nil, errors.New("lifecycle: empty target key id")
	}
	if kek == nil {
		return nil, errors.New("lifecycle: kek is nil")
	}

	// 1. 解密外部 DEK。
	plaintextDEK, err := transitMgr.UnwrapWithTransitKey(transitKeyID, wrappedMaterial)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: import unwrap: %w", err)
	}

	// 2. 装入 SecureBuffer + 立即清零明文 []byte。
	dekSB := memguard.NewSecureBuffer(plaintextDEK)
	for i := range plaintextDEK {
		plaintextDEK[i] = 0
	}
	defer dekSB.Wipe()

	// 3. 用 KEK 加密 DEK → Yvonne 标准密文。
	encryptedDEK, err := kek.WrapDEK(dekSB)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: import encrypt DEK: %w", err)
	}

	// 4. 存入 DB。
	meta := KeyMetadata{
		KeyID:             targetKeyID,
		Version:           1,
		State:             StateActive,
		KeyType:           crypto.KeyTypeAES,
		EncryptedMaterial: encryptedDEK,
		KEKType:           string(kek.Type()),
		CreatedAt:         time.Now().UTC(),
	}

	if err := m.saveMetadata(ctx, meta); err != nil {
		return nil, fmt.Errorf("lifecycle: import save metadata: %w", err)
	}

	return &meta, nil
}
