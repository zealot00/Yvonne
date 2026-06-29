//go:build gmsm

// Package crypto - SM2 公钥密码实现（GB/T 32918）。
//
// SM2 是基于椭圆曲线的公钥密码算法，支持：
//   - 密钥对生成（256 位曲线 SM2P256V1）
//   - 公钥加密 / 私钥解密（GB/T 32918.4）
//   - 数字签名 / 验签（GB/T 32918.2，使用 SM3 作为摘要）
//
// 依赖：github.com/tjfoc/gmsm/sm2
// 编译：go build -tags gmsm
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
)

// SM2PublicKey 是 SM2 公钥（PEM 编码）。
type SM2PublicKey struct {
	Key *sm2.PublicKey
	PEM []byte // PEM 编码的公钥（用于存储/传输）
}

// SM2PrivateKey 是 SM2 私钥（不应直接存储，需 KEK 加密）。
type SM2PrivateKey struct {
	Key *sm2.PrivateKey
}

// GenerateSM2KeyPair 生成 SM2 密钥对。
func GenerateSM2KeyPair() (*SM2PublicKey, *SM2PrivateKey, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: sm2 generate key: %w", err)
	}

	// 导出公钥 PEM。
	pubPEM, err := sm2PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: sm2 public key to PEM: %w", err)
	}

	return &SM2PublicKey{Key: &priv.PublicKey, PEM: pubPEM}, &SM2PrivateKey{Key: priv}, nil
}

// SM2Encrypt 用 SM2 公钥加密数据。
// 返回 ASN.1 编码的密文（GB/T 32918.4）。
func SM2Encrypt(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil || pub.Key == nil {
		return nil, errors.New("crypto: sm2 encrypt: nil public key")
	}
	ciphertext, err := sm2.EncryptAsn1(pub.Key, plaintext, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: sm2 encrypt: %w", err)
	}
	return ciphertext, nil
}

// SM2Decrypt 用 SM2 私钥解密数据。
func SM2Decrypt(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	if priv == nil || priv.Key == nil {
		return nil, errors.New("crypto: sm2 decrypt: nil private key")
	}
	plaintext, err := sm2.DecryptAsn1(priv.Key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: sm2 decrypt: %w", err)
	}
	return plaintext, nil
}

// sm2UID 是 SM2 签名/验签的用户 ID（GB/T 32918.2 默认值）。
// 可通过 SetSM2UID 在启动时覆盖（与第三方系统互操作）。
var sm2UID = []byte("1234567812345678")

// SetSM2UID 设置全局 SM2 UID（用于与第三方系统互操作）。
// 必须在首次 SM2 签名/验签前调用。
func SetSM2UID(uid []byte) {
	if len(uid) > 0 {
		sm2UID = uid
	}
}

// SM2Sign 用 SM2 私钥签名（使用 SM3 摘要，uid 可通过 SetSM2UID 配置）。
func SM2Sign(priv *SM2PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil || priv.Key == nil {
		return nil, errors.New("crypto: sm2 sign: nil private key")
	}
	uid := sm2UID
	r, s, err := sm2.Sm2Sign(priv.Key, msg, uid, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: sm2 sign: %w", err)
	}
	// 将 r,s 编码为 ASN.1 签名值。
	sig, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		return nil, fmt.Errorf("crypto: sm2 sign encode: %w", err)
	}
	return sig, nil
}

// SM2Verify 用 SM2 公钥验证签名。
func SM2Verify(pub *SM2PublicKey, msg, sig []byte) (bool, error) {
	if pub == nil || pub.Key == nil {
		return false, errors.New("crypto: sm2 verify: nil public key")
	}
	uid := sm2UID
	r, s, err := sm2.SignDataToSignDigit(sig)
	if err != nil {
		return false, fmt.Errorf("crypto: sm2 verify decode: %w", err)
	}
	return sm2.Sm2Verify(pub.Key, msg, uid, r, s), nil
}

// SM2PrivateKeyToPEM 将 SM2 私钥序列化为 PEM（用于 KEK 加密存储）。
func SM2PrivateKeyToPEM(priv *SM2PrivateKey) ([]byte, error) {
	if priv == nil || priv.Key == nil {
		return nil, errors.New("crypto: sm2 private key to PEM: nil key")
	}
	return sm2PrivateKeyToPEM(priv.Key)
}

// SM2PrivateKeyFromPEM 从 PEM 反序列化 SM2 私钥。
func SM2PrivateKeyFromPEM(pemData []byte) (*SM2PrivateKey, error) {
	priv, err := sm2PrivateKeyFromPEM(pemData)
	if err != nil {
		return nil, err
	}
	return &SM2PrivateKey{Key: priv}, nil
}

// SM2PublicKeyFromPEM 从 PEM 反序列化 SM2 公钥。
func SM2PublicKeyFromPEM(pemData []byte) (*SM2PublicKey, error) {
	pub, err := sm2PublicKeyFromPEM(pemData)
	if err != nil {
		return nil, err
	}
	return &SM2PublicKey{Key: pub, PEM: pemData}, nil
}

// --- 内部 PEM 辅助 ---

// sm2PublicKeyToPEM 将 SM2 公钥编码为 PEM。
func sm2PublicKeyToPEM(pub *sm2.PublicKey) ([]byte, error) {
	// tjfoc/gmsm 的 sm2.PublicKey 内嵌 ecdsa.PublicKey
	// 用标准库 x509 MarshalPKIXPublicKey + PEM 编码
	return marshalSMPublicKeyPEM(pub)
}

// sm2PrivateKeyToPEM 将 SM2 私钥编码为 PEM。
func sm2PrivateKeyToPEM(priv *sm2.PrivateKey) ([]byte, error) {
	return marshalSMPrivateKeyPEM(priv)
}

// sm2PublicKeyFromPEM 从 PEM 解码 SM2 公钥。
func sm2PublicKeyFromPEM(pemData []byte) (*sm2.PublicKey, error) {
	return parseSMPublicKeyPEM(pemData)
}

// sm2PrivateKeyFromPEM 从 PEM 解码 SM2 私钥。
func sm2PrivateKeyFromPEM(pemData []byte) (*sm2.PrivateKey, error) {
	return parseSMPrivateKeyPEM(pemData)
}
