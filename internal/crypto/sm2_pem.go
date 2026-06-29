//go:build gmsm

// SM2 PEM 编解码辅助（用 tjfoc/gmsm 内置方法）。
package crypto

import (
	"encoding/pem"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// marshalSMPublicKeyPEM 将 SM2 公钥编码为 PEM。
func marshalSMPublicKeyPEM(pub *sm2.PublicKey) ([]byte, error) {
	der, err := x509.MarshalSm2PublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal SM2 public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// marshalSMPrivateKeyPEM 将 SM2 私钥编码为 PEM（PKCS8）。
func marshalSMPrivateKeyPEM(priv *sm2.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalSm2UnecryptedPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal SM2 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// parseSMPublicKeyPEM 从 PEM 解码 SM2 公钥。
//
// 安全检查：
//   - 校验 PEM block.Type 为 "PUBLIC KEY"
//   - 校验解析后的密钥类型为 *sm2.PublicKey（防算法混淆攻击）
//   - 拒绝含附加数据的 PEM（rest 非空）
func parseSMPublicKeyPEM(pemData []byte) (*sm2.PublicKey, error) {
	if len(pemData) == 0 {
		return nil, fmt.Errorf("parse SM2 public key: empty PEM data")
	}
	block, rest := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("parse SM2 public key: no PEM block found")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parse SM2 public key: trailing data after PEM block (%d bytes)", len(rest))
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("parse SM2 public key: unexpected PEM type %q, want %q", block.Type, "PUBLIC KEY")
	}

	pub, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 public key DER: %w", err)
	}

	// 曲线校验：确认密钥使用 SM2P256V1 曲线（防算法混淆攻击）。
	if pub.Curve != sm2.P256Sm2() {
		return nil, fmt.Errorf("parse SM2 public key: unexpected curve %T (possible algorithm confusion attack)", pub.Curve)
	}
	return pub, nil
}

// parseSMPrivateKeyPEM 从 PEM 解码 SM2 私钥（PKCS8 格式）。
//
// 安全检查：
//   - 校验 PEM block.Type 为 "PRIVATE KEY"
//   - 校验解析后的密钥类型为 *sm2.PrivateKey（防算法混淆攻击）
//   - 拒绝含附加数据的 PEM（rest 非空）
func parseSMPrivateKeyPEM(pemData []byte) (*sm2.PrivateKey, error) {
	if len(pemData) == 0 {
		return nil, fmt.Errorf("parse SM2 private key: empty PEM data")
	}
	block, rest := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("parse SM2 private key: no PEM block found")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parse SM2 private key: trailing data after PEM block (%d bytes)", len(rest))
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("parse SM2 private key: unexpected PEM type %q, want %q", block.Type, "PRIVATE KEY")
	}

	// MarshalSm2UnecryptedPrivateKey 输出 PKCS8 格式，需用 ParsePKCS8UnecryptedPrivateKey。
	priv, err := x509.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 private key (PKCS8): %w", err)
	}

	// 曲线校验：确认密钥使用 SM2P256V1 曲线（防算法混淆攻击）。
	if priv.Curve != sm2.P256Sm2() {
		return nil, fmt.Errorf("parse SM2 private key: unexpected curve %T (possible algorithm confusion attack)", priv.Curve)
	}
	return priv, nil
}
