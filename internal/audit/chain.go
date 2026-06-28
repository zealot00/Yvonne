// Package audit - 哈希链防篡改引擎。
//
// 哈希链算法：
//
//	CurrentSignature = HMAC(AuditKey, lastSignature + CurrentLogPayload)
//
// HMAC 算法可插拔：
//   - 标准模式：HMAC-SHA256
//   - 国密模式：HMAC-SM3（需 -tags gmsm）
//
// 初始 lastSignature = Hash(chainKey)（链头锚定）。
// 每条日志记录后更新 lastSignature，形成不可篡改的链条。
// 任何中间日志被篡改或删除，后续所有签名验证都会失败。
//
// 并发安全：哈希链计算加写锁，严格串行。
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"
)

// hashChain 维护审计日志的哈希链条。
type hashChain struct {
	mu            sync.Mutex
	lastSignature []byte
	newHash       func() hash.Hash    // HMAC 内层 hash 函数（SHA-256 或 SM3）
	anchorHash    func([]byte) []byte // 链头锚定 hash（SHA-256 或 SM3）
}

// newHashChain 创建哈希链（标准模式，HMAC-SHA256）。
// chainKey 是从 AuditKey 提取的 []byte。
func newHashChain(chainKey []byte) *hashChain {
	return &hashChain{
		lastSignature: sha256Sum(chainKey),
		newHash:       sha256.New,
		anchorHash:    sha256Sum,
	}
}

// newHashChainWithHash 创建哈希链（自定义 hash 函数，用于国密 HMAC-SM3）。
func newHashChainWithHash(chainKey []byte, newHash func() hash.Hash, anchorHash func([]byte) []byte) *hashChain {
	return &hashChain{
		lastSignature: anchorHash(chainKey),
		newHash:       newHash,
		anchorHash:    anchorHash,
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

	mac := hmac.New(c.newHash, chainKey)
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

// sha256Sum 计算 SHA-256 摘要。
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Reset 重置哈希链（用于测试）。
func (c *hashChain) Reset(chainKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSignature = c.anchorHash(chainKey)
}
