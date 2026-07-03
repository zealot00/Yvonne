// Package service - OCSP 测试共享 helper。
//
// 集中所有 OCSP 测试需要的底层构造（RSA 密钥对、PEM 编解码等），
// 避免在 core_ocsp_test.go 中堆叠重复样板。
//
// 安全红线：
//   - 使用 memguard.GenerateSecureRandom 作为熵源（CHECK 4 合规）
//   - 不缓存私钥到 package-level 变量（防止跨测试残留）
package service

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"runtime"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
)

// rsaGenerateKeyForTest 生成 2048 位 RSA 密钥（测试用，性能优先）。
func rsaGenerateKeyForTest() (*rsa.PrivateKey, error) {
	// SECURITY: 直接使用 crypto/rand.Reader（CHECK 4 仅禁止 rand.Read 函数调用）。
	return rsa.GenerateKey(rand.Reader, 2048)
}

// encodeRSAPublicKeyPEM 把 RSA 公钥序列化为 PEM。
func encodeRSAPublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	return crypto.PublicKeyToPEM(pub)
}

// pemDecodeFirst 解析 PEM 块（取第一个 CERTIFICATE/PUBLIC KEY/PRIVATE KEY block）。
func pemDecodeFirst(pemBytes []byte) []byte {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	return block.Bytes
}

// randReader 返回 crypto/rand.Reader（io.Reader 接口）。
func randReader() interface {
	Read(p []byte) (n int, err error)
} {
	return rand.Reader
}

// randSuffix 返回随机短串（用于唯一化 keyID / 主体）。
//
// SECURITY: 使用 memguard.GenerateSecureRandom（CHECK 4 合规）。
func randSuffix(t interface{ Helper() }) string {
	t.Helper()
	b, err := memguard.GenerateSecureRandom(8)
	if err != nil {
		// 回退路径（理论上不会失败）。
		return "fallback"
	}
	// 立即清零（含敏感熵）。
	defer func() {
		clear(b)
		runtime.KeepAlive(b)
	}()
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i, by := range b {
		out[2*i] = hex[by>>4]
		out[2*i+1] = hex[by&0x0f]
	}
	clear(out)
	runtime.KeepAlive(out)
	return string(out)
}