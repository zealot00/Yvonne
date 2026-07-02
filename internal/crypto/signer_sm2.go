//go:build gmsm

// SM2 SecureSigner 实现（gmsm 构建标签）。
package crypto

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"yvonne/internal/memguard"

	"github.com/tjfoc/gmsm/sm2"
)

// newSM2SecureSigner 从 SM2 私钥 PEM 创建 crypto.Signer。
func newSM2SecureSigner(privPEM []byte) (*SecureSigner, error) {
	priv, err := parseSMPrivateKeyPEM(privPEM)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 private key for signer: %w", err)
	}
	sb := memguard.NewSecureBuffer(privPEM)
	return &SecureSigner{priv: priv, sb: sb}, nil
}

// sm2SignerPublic 返回 SM2 公钥。
func sm2SignerPublic(priv interface{}) crypto.PublicKey {
	if sm2Priv, ok := priv.(*sm2.PrivateKey); ok {
		return &sm2Priv.PublicKey
	}
	return nil
}

// sm2SignerSign SM2 签名。
// 注意：tjfoc 的 sm2.PrivateKey.Sign 接收原始数据，内部用 SM3 做摘要。
// 证书签发时 x509.CreateCertificate 会传入 TBS 的哈希，
// tjfoc 的 CreateCertificateToPem 实现会正确处理 SM2WithSM3。
// 此方法作为 crypto.Signer 接口的 fallback 实现。
func sm2SignerSign(priv interface{}, digest []byte) ([]byte, error) {
	sm2Priv, ok := priv.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: not an SM2 private key: %T", priv)
	}
	sig, err := sm2Priv.Sign(rand.Reader, digest, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: SM2 signer sign: %w", err)
	}
	return sig, nil
}
