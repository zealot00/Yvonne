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
func parseSMPublicKeyPEM(pemData []byte) (*sm2.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("parse SM2 public key: no PEM block")
	}
	pub, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 public key: %w", err)
	}
	return pub, nil
}

// parseSMPrivateKeyPEM 从 PEM 解码 SM2 私钥（PKCS8 格式）。
func parseSMPrivateKeyPEM(pemData []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("parse SM2 private key: no PEM block")
	}
	// MarshalSm2UnecryptedPrivateKey 输出 PKCS8 格式，需用 ParsePKCS8UnecryptedPrivateKey。
	priv, err := x509.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 private key (PKCS8): %w", err)
	}
	return priv, nil
}
