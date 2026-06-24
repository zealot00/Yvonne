// Package audit - 哈希链防篡改引擎。
//
// 哈希链算法：
//
//	CurrentSignature = HMAC-SHA256(AuditKey, lastSignature + CurrentLogPayload)
//
// 初始 lastSignature = SHA256(AuditKey)（链头锚定）。
//
// 每条日志记录后更新 lastSignature，形成不可篡改的链条。
// 任何中间日志被篡改或删除，后续所有签名验证都会失败。
//
// 并发安全：哈希链计算加写锁，严格串行。
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// hashChain 维护审计日志的哈希链条。
type hashChain struct {
	mu            sync.Mutex
	lastSignature []byte
}

// newHashChain 创建哈希链，初始签名为 SHA256(chainKey)。
// chainKey 是从 AuditKey 提取的 []byte（通过 WithKey 闭包），非直接密钥参数。
func newHashChain(chainKey []byte) *hashChain {
	h := sha256.Sum256(chainKey)
	return &hashChain{
		lastSignature: h[:],
	}
}

// computeAndAdvance 计算当前日志的签名并推进链条。
//
// 算法：sig = HMAC-SHA256(chainKey, lastSig + payload)
// 计算后 lastSignature = sig。
//
// 返回 (currentSig, prevSig)，prevSig 是计算前的 lastSignature。
// prevSig 用于写入 envelope，使每条日志可独立验证（无需按序重放）。
//
// 必须持锁调用（保证链条顺序）。
func (c *hashChain) computeAndAdvance(chainKey, payload []byte) (currentSig, prevSig string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prevSig = hex.EncodeToString(c.lastSignature)

	mac := hmac.New(sha256.New, chainKey)
	mac.Write(c.lastSignature)
	mac.Write(payload)
	sig := mac.Sum(nil)

	c.lastSignature = sig
	return hex.EncodeToString(sig), prevSig
}

// LastSignatureHex 返回当前链条末端的签名（hex 编码）。
// 用于测试与外部验证。
func (c *hashChain) LastSignatureHex() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return hex.EncodeToString(c.lastSignature)
}

// SetLastSignature 设置链条末端签名（从持久化文件恢复时用）。
func (c *hashChain) SetLastSignature(sig []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSignature = sig
}

// Reset 重置哈希链（用于测试）。
func (c *hashChain) Reset(chainKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := sha256.Sum256(chainKey)
	c.lastSignature = h[:]
}
