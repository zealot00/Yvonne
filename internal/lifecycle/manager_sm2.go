//go:build gmsm

// Package lifecycle - SM2 密钥创建（gmsm 构建标签）。
package lifecycle

import (
	"context"
	"fmt"
	"time"

	"yvonne/internal/crypto"
	"yvonne/internal/seal"
)

// createSM2Key 创建 SM2 非对称密钥（gmsm 构建专用）。
// SM2 私钥用 PEM 格式存储（tjfoc/gmsm 原生支持），KEK 加密 PEM bytes。
func (m *Manager) createSM2Key(ctx context.Context, keyID string, kek seal.KEK) (*KeyMetadata, error) {
	// 1. 生成 SM2 密钥对（私钥 PEM 装入 SecureBuffer + 公钥 PEM）。
	privPEMSB, pubPEM, err := crypto.GenerateSM2AsymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("lifecycle: generate SM2 key: %w", err)
	}
	defer privPEMSB.Wipe()

	// 2. KEK 加密私钥 PEM。
	encryptedMaterial, err := kek.WrapDEK(privPEMSB)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: encrypt SM2 private key: %w", err)
	}

	// 3. 构造元数据。
	meta := KeyMetadata{
		KeyID:             keyID,
		Version:           1,
		State:             StateActive,
		KeyType:           crypto.KeyTypeSM2,
		EncryptedMaterial: encryptedMaterial,
		KEKType:           string(kek.Type()),
		PublicKey:         pubPEM,
		CreatedAt:         time.Now().UTC(),
	}

	if err := m.saveMetadata(ctx, meta); err != nil {
		return nil, fmt.Errorf("lifecycle: save SM2 metadata: %w", err)
	}
	_ = m.setLatestVersion(ctx, keyID, 1)

	return &meta, nil
}
