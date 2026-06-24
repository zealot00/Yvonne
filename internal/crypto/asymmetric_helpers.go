// Package crypto - 非对称密码学辅助函数。
//
// 将 crypto.SHA256 与 x509.MarshalPKCS8PrivateKey 等封装为内部类型/函数，
// 避免与包名 crypto 冲突。
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// cryptoHash 是 crypto.Hash 的别名，用于避免直接 import crypto 包名冲突。
type cryptoHash = crypto.Hash

// cryptoSHA256Value 是 crypto.SHA256 常量。
const cryptoSHA256Value = crypto.SHA256

// pkcs8Marshal 将私钥序列化为 PKCS#8 DER。
func pkcs8Marshal(privateKey interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// publicKeyToPEMImpl 将公钥序列化为 PEM 格式。
func publicKeyToPEMImpl(publicKey interface{}) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// ParsePrivateKeyFromDER 从 PKCS#8 DER 反序列化私钥。
func ParsePrivateKeyFromDER(der []byte) (interface{}, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse PKCS#8 private key: %w", err)
	}
	// 校验类型。
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported private key type %T", key)
	}
}

// ParsePublicKeyFromPEM 从 PEM 反序列化公钥。
func ParsePublicKeyFromPEM(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("crypto: failed to decode public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse PKIX public key: %w", err)
	}
	return key, nil
}
