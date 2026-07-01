// Package service — transport-agnostic 核心业务层。
//
// HTTP/gRPC/MCP 三个前端共享 Core 的业务逻辑、授权检查、审计记录。
// Core 方法接收 *auth.Policy（由各前端的认证中间件注入）做资源级授权。
package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
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
// PG 断连时进入 degraded 模式：写操作拒绝，读操作用缓存。
//
// Bug-6 修复: KEK 解密失败（HSM 离线/MasterKey 损坏）触发 CRITICAL 告警。
type Core struct {
	manager    *lifecycle.Manager
	seal       seal.Unsealer
	auditLog   audit.Auditor
	adminToken string  // EmergencySeal 校验用
	alerter    Alerter // Bug-6: KEK 解密失败告警（nil = NoopAlerter）
}

// Alerter 是 service 层的告警接口（避免直接 import observability 包循环依赖）。
// Bug-6 修复: KEK 解密失败等系统级危机触发告警。
type Alerter interface {
	Alert(ctx context.Context, operation, resource, description string) error
}

// noopAlerter 默认无操作告警器。
type noopAlerter struct{}

func (noopAlerter) Alert(ctx context.Context, operation, resource, description string) error {
	return nil
}

// NewCore 创建 Core 实例（PD-9: 重命名为 NewCore，旧名保持兼容）。
func NewCore(mgr *lifecycle.Manager, s seal.Unsealer, log audit.Auditor) *Core {
	return &Core{manager: mgr, seal: s, auditLog: log, alerter: noopAlerter{}}
}

// NewManager 别名（向后兼容，PD-9 建议用 NewCore）。
func NewManager(mgr *lifecycle.Manager, s seal.Unsealer, log audit.Auditor) *Core {
	return NewCore(mgr, s, log)
}

// SetAdminToken 设置 EmergencySeal 用的 admin token（BUG-8 修复）。
func (c *Core) SetAdminToken(token string) {
	c.adminToken = token
}

// SetAlerter 注入告警器（Bug-6 修复）。
// KEK 解密失败等系统级危机触发告警。
// 不调用时默认 NoopAlerter（向后兼容）。
func (c *Core) SetAlerter(a Alerter) {
	if a == nil {
		c.alerter = noopAlerter{}
		return
	}
	c.alerter = a
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

// EmergencySeal 紧急封印。校验 adminToken 后触发。
func (c *Core) EmergencySeal(ctx context.Context, adminToken string) error {
	if c.adminToken == "" {
		return errors.New("service: emergency seal not configured (no admin token)")
	}
	if subtle.ConstantTimeCompare([]byte(adminToken), []byte(c.adminToken)) != 1 {
		c.recordAudit(ctx, "EmergencySeal", "", 0, "denied", "invalid admin token")
		return errors.New("service: invalid admin token")
	}
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
	if err := c.requireWritable(); err != nil {
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
	if err := c.requireWritable(); err != nil {
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
	if err := c.requireWritable(); err != nil {
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
	if err := c.requireWritable(); err != nil {
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
	if err := c.requireWritable(); err != nil {
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
//
// Bug-7 修复: 明文 DEK 不再以 *memguard.SecureBuffer 直接暴露给调用方。
// 调用方必须通过 WriteBase64To 方法写入响应，由 Core 内部控制 Wipe 时机，
// 从接口设计上消除"Handler 遗漏 defer Wipe"的风险。
type GenerateDataKeyResult struct {
	plaintextDEK *memguard.SecureBuffer // 私有，调用方无法直接访问
	Ciphertext   []byte
}

// WriteBase64To 将明文 DEK 以 Base64 编码写入 w，写入完成后立即 Wipe 内部 SecureBuffer。
//
// Bug-7 修复: 受控暴露接口 — 调用方无法获取 SecureBuffer 引用，
// Core 内部保证写入后立即擦除，从设计上消除内存逃逸风险。
//
// 注意: 此方法只能调用一次（Wipe 后 SecureBuffer 已清空）。
// 重复调用返回 error（不 panic，便于调用方优雅处理）。
func (r *GenerateDataKeyResult) WriteBase64To(w io.Writer) error {
	if r == nil || r.plaintextDEK == nil {
		return errors.New("service: plaintext DEK already wiped or nil")
	}
	if r.plaintextDEK.IsDestroyed() {
		return errors.New("service: plaintext DEK already wiped")
	}
	defer r.plaintextDEK.Wipe()

	return r.plaintextDEK.WithKey(func(dek []byte) error {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(dek)))
		base64.StdEncoding.Encode(encoded, dek)
		_, err := w.Write(encoded)
		// 擦除编码缓冲。
		for i := range encoded {
			encoded[i] = 0
		}
		runtime.KeepAlive(encoded)
		return err
	})
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
		// Bug-7 修复: plaintextDEK 作为私有字段存储，调用方通过 WriteBase64To 受控访问。
		result = &GenerateDataKeyResult{
			plaintextDEK: plainDEK,
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
			// Bug-6 修复: KEK 解密失败属于系统级危机，触发 CRITICAL 告警。
			c.alerter.Alert(ctx, "KEKUnwrapFailure", keyID,
				fmt.Sprintf("encrypt: KEK failed to unwrap DEK: %v", e))
			return e
		}
		defer plaintextDEK.Wipe()
		ciphertext, e = crypto.EncryptVersioned(plaintextDEK, crypto.SafeUint32(meta.Version), plaintext)
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
			// Bug-6 修复: KEK 解密失败属于系统级危机，触发 CRITICAL 告警。
			c.alerter.Alert(ctx, "KEKUnwrapFailure", keyID,
				fmt.Sprintf("decrypt: KEK failed to unwrap DEK: %v", e))
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
		return errors.New("vault is emergency sealed: all operations refused until process restart + Shamir unseal")
	}
	if c.seal.IsSealed() {
		return errors.New("vault is sealed: run unseal ceremony to resume operations")
	}
	return nil
}

// requireWritable 检查 DB 是否可用（写操作前调用）。
// degraded 模式下拒绝写操作，返回 503 等价错误。
func (c *Core) requireWritable() error {
	if c.manager == nil {
		return nil
	}
	store := c.manager.Store()
	if store == nil {
		return nil
	}
	hc, ok := store.(storageHealthChecker)
	if !ok {
		return nil // 非健康检查 store（MemoryStore/BoltDB）不限制
	}
	if !hc.IsHealthy() {
		return errors.New("database unavailable (degraded mode): write operations refused, cached DEKs still available for decrypt")
	}
	return nil
}

// storageHealthChecker 是 service 层需要的最小健康检查接口。
// 避免直接 import storage 包（循环依赖）。
type storageHealthChecker interface {
	IsHealthy() bool
}

// authorize 检查 Policy 是否允许指定 action + keyID。
// nil Policy = Dev 模式放行。
// 错误消息包含 role/key/allowed 详情，便于运维诊断。
func (c *Core) authorize(policy *auth.Policy, action, keyID string) error {
	if policy == nil {
		return nil // Dev 模式
	}
	if !policy.IsActionAllowed(action) {
		return fmt.Errorf("access denied: role %q does not have action %q on key %q (allowed actions: %v)",
			policy.RoleID, action, keyID, policy.AllowedActions)
	}
	if !policy.IsKeyAllowed(keyID) {
		return fmt.Errorf("access denied: role %q cannot access key %q (allowed keys: %v)",
			policy.RoleID, keyID, policy.AllowedKeys)
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
