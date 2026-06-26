// Package service — transport-agnostic 核心业务层。
//
// HTTP/gRPC/MCP 三个前端共享 Core 的业务逻辑、授权检查、审计记录。
// Core 方法接收 *auth.Policy（由各前端的认证中间件注入）做资源级授权。
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// Core 是 KMS 核心业务层，transport-agnostic。
//
// 所有方法接收 *auth.Policy 做资源级授权（nil Policy = Dev 模式放行）。
// 所有方法内置：Sealed 拦截 → 授权校验 → 业务调用 → 审计记录。
type Core struct {
	manager  *lifecycle.Manager
	seal     seal.Unsealer
	auditLog audit.Auditor
}

// NewCore 创建 Core 实例。
func NewManager(mgr *lifecycle.Manager, s seal.Unsealer, log audit.Auditor) *Core {
	return &Core{manager: mgr, seal: s, auditLog: log}
}

// === 系统管理 ===

// Health 返回 vault 状态。
func (c *Core) Health(ctx context.Context) (state string, emergencySealed bool, err error) {
	if c.seal.IsEmergencySealed() {
		return "emergency_sealed", true, nil
	}
	if c.seal.IsSealed() {
		return "sealed", false, nil
	}
	return "unsealed", false, nil
}

// EmergencySeal 紧急封印。
func (c *Core) EmergencySeal(ctx context.Context, adminToken string) error {
	c.seal.EmergencySeal(ctx)
	if c.manager != nil {
		c.manager.ClearCache()
	}
	c.recordAudit(ctx, "EmergencySeal", "", 0, "success", "")
	return nil
}

// === 密钥生命周期 ===

// CreateKeyResult 是 CreateKey 的返回。
type CreateKeyResult struct {
	KeyID        string
	Version      int
	PlaintextDEK *memguard.SecureBuffer // 调用方负责 Wipe；returnDEK=false 时为 nil
}

// CreateKey 创建新业务密钥。
func (c *Core) CreateKey(ctx context.Context, keyID string, rotationPeriodDays int, returnDEK bool, policy *auth.Policy) (*CreateKeyResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "CreateKey", keyID); err != nil {
		return nil, err
	}

	var result *CreateKeyResult
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		meta, plainDEK, e := c.manager.CreateKey(ctx, keyID, kek, rotationPeriodDays)
		if e != nil {
			return e
		}
		result = &CreateKeyResult{
			KeyID:        meta.KeyID,
			Version:      meta.Version,
			PlaintextDEK: plainDEK,
		}
		if !returnDEK {
			plainDEK.Wipe()
			result.PlaintextDEK = nil
		}
		return nil
	})
	if err != nil {
		c.recordAudit(ctx, "CreateKey", keyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "CreateKey", keyID, result.Version, "success", "")
	return result, nil
}

// RotateKeyResult 是 RotateKey 的返回。
type RotateKeyResult struct {
	KeyID        string
	NewVersion   int
	PlaintextDEK *memguard.SecureBuffer
}

// RotateKey 轮转密钥。
func (c *Core) RotateKey(ctx context.Context, keyID string, policy *auth.Policy) (*RotateKeyResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return nil, err
	}

	var result *RotateKeyResult
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		meta, plainDEK, e := c.manager.RotateKey(ctx, keyID, kek)
		if e != nil {
			return e
		}
		result = &RotateKeyResult{
			KeyID:        meta.KeyID,
			NewVersion:   meta.Version,
			PlaintextDEK: plainDEK,
		}
		return nil
	})
	if err != nil {
		c.recordAudit(ctx, "RotateKey", keyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "RotateKey", keyID, result.NewVersion, "success", "")
	return result, nil
}

// ShredKey 物理粉碎密钥版本。
func (c *Core) ShredKey(ctx context.Context, keyID string, version int, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return err
	}
	if err := c.manager.ShredKey(ctx, keyID, version); err != nil {
		c.recordAudit(ctx, "ShredKey", keyID, version, "error", err.Error())
		return err
	}
	c.recordAudit(ctx, "ShredKey", keyID, version, "success", "")
	return nil
}

// SoftDeleteKey 软删除密钥版本。
func (c *Core) SoftDeleteKey(ctx context.Context, keyID string, version int, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return err
	}
	if err := c.manager.SoftDeleteKey(ctx, keyID, version); err != nil {
		c.recordAudit(ctx, "SoftDeleteKey", keyID, version, "error", err.Error())
		return err
	}
	c.recordAudit(ctx, "SoftDeleteKey", keyID, version, "success", "")
	return nil
}

// RestoreKey 恢复软删除的密钥版本。
func (c *Core) RestoreKey(ctx context.Context, keyID string, version int, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return err
	}
	if err := c.manager.RestoreKey(ctx, keyID, version); err != nil {
		c.recordAudit(ctx, "RestoreKey", keyID, version, "error", err.Error())
		return err
	}
	c.recordAudit(ctx, "RestoreKey", keyID, version, "success", "")
	return nil
}

// === 数据密钥 ===

// GenerateDataKeyResult 是 GenerateDataKey 的返回。
type GenerateDataKeyResult struct {
	PlaintextDEK *memguard.SecureBuffer
	Ciphertext   []byte
}

// GenerateDataKey 生成数据密钥。
func (c *Core) GenerateDataKey(ctx context.Context, keyID string, policy *auth.Policy) (*GenerateDataKeyResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return nil, err
	}

	var result *GenerateDataKeyResult
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		plainDEK, ciphertext, e := c.manager.GenerateDataKey(ctx, keyID, kek)
		if e != nil {
			return e
		}
		result = &GenerateDataKeyResult{
			PlaintextDEK: plainDEK,
			Ciphertext:   ciphertext,
		}
		return nil
	})
	if err != nil {
		c.recordAudit(ctx, "GenerateDataKey", keyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "GenerateDataKey", keyID, 0, "success", "")
	return result, nil
}

// === 加解密 ===

// EncryptResult 是 Encrypt 的返回。
type EncryptResult struct {
	Ciphertext []byte
	Version    int
}

// Encrypt 加密业务明文。
func (c *Core) Encrypt(ctx context.Context, keyID string, plaintext []byte, policy *auth.Policy) (*EncryptResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "Encrypt", keyID); err != nil {
		return nil, err
	}

	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "Encrypt", keyID, 0, "error", err.Error())
		return nil, err
	}

	var ciphertext []byte
	err = c.seal.KEKRef(func(kek seal.KEK) error {
		plaintextDEK, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer plaintextDEK.Wipe()
		ciphertext, e = crypto.EncryptVersioned(plaintextDEK, uint32(meta.Version), plaintext)
		return e
	})
	if err != nil {
		c.recordAudit(ctx, "Encrypt", keyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "Encrypt", keyID, meta.Version, "success", "")
	return &EncryptResult{Ciphertext: ciphertext, Version: meta.Version}, nil
}

// DecryptResult 是 Decrypt 的返回。
type DecryptResult struct {
	Plaintext *memguard.SecureBuffer // 调用方负责 Wipe
	Version   int
}

// Decrypt 解密业务密文。
func (c *Core) Decrypt(ctx context.Context, keyID string, ciphertext []byte, policy *auth.Policy) (*DecryptResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "Decrypt", keyID); err != nil {
		return nil, err
	}
	if len(ciphertext) < crypto.MinCiphertextSize {
		return nil, errors.New("service: ciphertext too short")
	}

	version, _, _, err := crypto.DecodeVersionedCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}

	meta, err := c.manager.GetKeyForDecrypt(ctx, keyID, int(version))
	if err != nil {
		c.recordAudit(ctx, "Decrypt", keyID, int(version), "error", err.Error())
		return nil, err
	}

	var plaintext *memguard.SecureBuffer
	var decVersion uint32
	err = c.seal.KEKRef(func(kek seal.KEK) error {
		plaintextDEK, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer plaintextDEK.Wipe()
		plaintext, decVersion, e = crypto.DecryptVersioned(plaintextDEK, ciphertext)
		return e
	})
	if err != nil {
		c.recordAudit(ctx, "Decrypt", keyID, int(version), "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "Decrypt", keyID, int(decVersion), "success", "")
	return &DecryptResult{Plaintext: plaintext, Version: int(decVersion)}, nil
}

// === 内部辅助 ===

// requireUnsealed 检查 vault 是否已解封。
func (c *Core) requireUnsealed() error {
	if c.seal.IsEmergencySealed() {
		return errors.New("service: vault is emergency sealed")
	}
	if c.seal.IsSealed() {
		return errors.New("service: vault is sealed")
	}
	return nil
}

// authorize 检查 Policy 是否允许指定 action + keyID。
// nil Policy = Dev 模式放行。
func (c *Core) authorize(policy *auth.Policy, action, keyID string) error {
	if policy == nil {
		return nil // Dev 模式
	}
	if !policy.IsActionAllowed(action) {
		return fmt.Errorf("service: action %q not allowed for role %q", action, policy.RoleID)
	}
	if !policy.IsKeyAllowed(keyID) {
		return fmt.Errorf("service: key %q not allowed for role %q", keyID, policy.RoleID)
	}
	return nil
}

// recordAudit 记录审计日志。
func (c *Core) recordAudit(ctx context.Context, action, keyID string, version int, status, errMsg string) {
	if c.auditLog == nil {
		return
	}
	actor := "system"
	if policy := auth.PolicyFromContext(ctx); policy != nil {
		actor = policy.RoleID
	}
	entry := audit.LogEntry{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Actor:     actor,
		Resource:  keyID,
		Result:    status,
	}
	_ = c.auditLog.Record(entry)
}

// ClearCache 代理 manager.ClearCache（供 EmergencySeal 回调）。
func (c *Core) ClearCache() {
	if c.manager != nil {
		c.manager.ClearCache()
	}
}
