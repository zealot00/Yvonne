// Package lifecycle - PKI 证书元数据管理（v1.4.x 新增）。
//
// CertManager 管理证书的全生命周期元数据（签发/查询/吊销/CRL），
// 复用现有 storage.KVStore，新增 cert: 前缀。
//
// 存储 key 约定：
//   - cert:{certID}         → CertMetadata JSON
//   - cert:crl:{caKeyID}    → CRL DER
//   - cert:by-ca:{caKeyID}:{serial} → certID 索引
//
// 安全：CertMetadata 仅含 PEM 证书（公开）+ 元数据，无私钥。
// CA 私钥由 lifecycle.Manager 管理（KEK 加密存储）。
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"yvonne/internal/storage"
)

// CertState 证书状态。
type CertState string

const (
	CertStateActive  CertState = "Active"
	CertStateRevoked CertState = "Revoked"
	CertStateExpired CertState = "Expired"
)

// CertMetadata 是证书的元数据（不含私钥）。
type CertMetadata struct {
	CertID        string    `json:"cert_id"`
	CAKeyID       string    `json:"ca_key_id"`
	SerialNumber  string    `json:"serial_number"` // 十进制字符串
	Subject       string    `json:"subject"`
	PEM           []byte    `json:"pem"`
	DER           []byte    `json:"der,omitempty"`
	State         CertState `json:"state"`
	CertType      string    `json:"cert_type"` // sign/encrypt/ca
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
}

// certKey 返回证书元数据的存储 key。
func certKey(certID string) string {
	return fmt.Sprintf("cert:%s", certID)
}

// certByCAKey 返回 CA → 证书索引的存储 key。
func certByCAKey(caKeyID, serial string) string {
	return fmt.Sprintf("cert:by-ca:%s:%s", caKeyID, serial)
}

// crlKey 返回 CRL 的存储 key。
func crlKey(caKeyID string) string {
	return fmt.Sprintf("cert:crl:%s", caKeyID)
}

// CertManager 管理证书元数据 CRUD。
type CertManager struct {
	store storage.KVStore
}

// NewCertManager 创建证书管理器。
func NewCertManager(store storage.KVStore) *CertManager {
	return &CertManager{store: store}
}

// SaveCert 存储证书元数据。
func (cm *CertManager) SaveCert(ctx context.Context, meta *CertMetadata) error {
	if meta == nil || meta.CertID == "" {
		return errors.New("lifecycle: cert metadata or cert_id is empty")
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("lifecycle: marshal cert metadata: %w", err)
	}
	if err := cm.store.Put(ctx, certKey(meta.CertID), data); err != nil {
		return fmt.Errorf("lifecycle: put cert metadata: %w", err)
	}
	// 写 CA 索引。
	if meta.CAKeyID != "" && meta.SerialNumber != "" {
		idxKey := certByCAKey(meta.CAKeyID, meta.SerialNumber)
		if err := cm.store.Put(ctx, idxKey, []byte(meta.CertID)); err != nil {
			return fmt.Errorf("lifecycle: put cert CA index: %w", err)
		}
	}
	return nil
}

// GetCert 查询证书元数据。
func (cm *CertManager) GetCert(ctx context.Context, certID string) (*CertMetadata, error) {
	if certID == "" {
		return nil, errors.New("lifecycle: cert_id is empty")
	}
	data, err := cm.store.Get(ctx, certKey(certID))
	if err != nil {
		return nil, err
	}
	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("lifecycle: unmarshal cert metadata: %w", err)
	}
	return &meta, nil
}

// ListByCA 列出指定 CA 签发的所有证书。
// 使用 PrefixScanner 扫描 cert:by-ca:{caKeyID}: 前缀。
func (cm *CertManager) ListByCA(ctx context.Context, caKeyID string) ([]*CertMetadata, error) {
	if caKeyID == "" {
		return nil, errors.New("lifecycle: ca_key_id is empty")
	}
	scanner, ok := cm.store.(storage.PrefixScanner)
	if !ok {
		// 回退到分页扫描。
		return cm.listByCAPaged(ctx, caKeyID)
	}

	prefix := fmt.Sprintf("cert:by-ca:%s:", caKeyID)
	items, err := scanner.ScanPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: scan certs by CA: %w", err)
	}

	var result []*CertMetadata
	for certIDBytes := range items {
		certID := string(items[certIDBytes])
		// 用 certID 查完整元数据（避免索引只存 certID）。
		meta, err := cm.GetCert(ctx, certID)
		if err != nil {
			continue // 跳过损坏的索引
		}
		result = append(result, meta)
	}
	return result, nil
}

// listByCAPaged 用 PagedPrefixScanner 分页扫描（回退路径）。
func (cm *CertManager) listByCAPaged(ctx context.Context, caKeyID string) ([]*CertMetadata, error) {
	pagedScanner, ok := cm.store.(storage.PagedPrefixScanner)
	if !ok {
		return nil, nil // 不支持扫描的 store 返回空
	}

	prefix := fmt.Sprintf("cert:by-ca:%s:", caKeyID)
	var result []*CertMetadata
	const pageSize = 1000
	offset := 0
	for {
		items, _, err := pagedScanner.ScanPrefixPaged(ctx, prefix, offset, pageSize)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			certID := string(item.Value)
			meta, err := cm.GetCert(ctx, certID)
			if err != nil {
				continue
			}
			result = append(result, meta)
		}
		offset += len(items)
		if len(items) < pageSize {
			break
		}
	}
	return result, nil
}

// RevokeCert 标记证书为已吊销。
func (cm *CertManager) RevokeCert(ctx context.Context, certID, reason string) error {
	meta, err := cm.GetCert(ctx, certID)
	if err != nil {
		return fmt.Errorf("lifecycle: get cert for revoke: %w", err)
	}
	if meta.State == CertStateRevoked {
		return nil // 幂等
	}
	meta.State = CertStateRevoked
	meta.RevokedAt = time.Now().UTC()
	meta.RevokedReason = reason
	return cm.SaveCert(ctx, meta)
}

// FindBySerial 按序列号查询证书（通过 CA 索引）。
func (cm *CertManager) FindBySerial(ctx context.Context, caKeyID string, serial *big.Int) (*CertMetadata, error) {
	if caKeyID == "" || serial == nil {
		return nil, errors.New("lifecycle: ca_key_id and serial are required")
	}
	idxKey := certByCAKey(caKeyID, serial.String())
	certIDBytes, err := cm.store.Get(ctx, idxKey)
	if err != nil {
		return nil, err
	}
	return cm.GetCert(ctx, string(certIDBytes))
}

// SaveCRL 存储 CRL DER（覆盖旧 CRL）。
func (cm *CertManager) SaveCRL(ctx context.Context, caKeyID string, crlDER []byte) error {
	if caKeyID == "" {
		return errors.New("lifecycle: ca_key_id is empty for CRL")
	}
	return cm.store.Put(ctx, crlKey(caKeyID), crlDER)
}

// GetCRL 查询 CRL DER。
func (cm *CertManager) GetCRL(ctx context.Context, caKeyID string) ([]byte, error) {
	if caKeyID == "" {
		return nil, errors.New("lifecycle: ca_key_id is empty for CRL")
	}
	return cm.store.Get(ctx, crlKey(caKeyID))
}
