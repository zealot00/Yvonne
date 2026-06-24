// Package crypto - 非对称密码学引擎（RSA-4096 PSS + ECDSA P-256）。
//
// 算法约束（红线）：
//   - RSA 仅支持 4096 位，强制 PSS 填充（不用 PKCS#1 v1.5）。
//   - ECDSA 仅支持 P-256 曲线。
//   - 签名/验签的输入是 digest（如 SHA-256 哈希），非原始明文。
//   - 熵源强制 crypto/rand.Reader。
//
// 安全红线：
//   - 私钥序列化为 PKCS#8 DER 后必须立即被 SecureBuffer 接管。
//   - 明文 DER []byte 用完立即 clear + KeepAlive。
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"runtime"

	"yvonne/internal/memguard"
)

// 支持的密钥类型。
const (
	KeyTypeAES   = "aes"
	KeyTypeRSA   = "rsa"
	KeyTypeECDSA = "ecdsa"
)

// rsaKeyBits 强制 RSA-4096。
const rsaKeyBits = 4096

// errUnsupportedKeyType 表示不支持的密钥类型。
var errUnsupportedKeyType = errors.New("crypto: unsupported key type, must be 'rsa' or 'ecdsa'")

// GenerateAsymmetricKey 生成非对称密钥对。
//
// keyType: "rsa" 或 "ecdsa"。
// 返回值：rsa 私钥或 ecdsa 私钥（另一个为 nil）。
//
// 安全：用 crypto/rand.Reader 作为绝对熵源。
func GenerateAsymmetricKey(keyType string) (*rsa.PrivateKey, *ecdsa.PrivateKey, error) {
	switch keyType {
	case KeyTypeRSA:
		priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("crypto: generate RSA-4096 key: %w", err)
		}
		return priv, nil, nil
	case KeyTypeECDSA:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("crypto: generate ECDSA P-256 key: %w", err)
		}
		return nil, priv, nil
	default:
		return nil, nil, errUnsupportedKeyType
	}
}

// Sign 用私钥对 digest 签名。
//
// privateKey: *rsa.PrivateKey 或 *ecdsa.PrivateKey。
// digest: 已计算好的哈希值（如 SHA-256 输出 32 字节）。
//
// RSA 用 PSS 填充（sha256 hash + rand.Reader 随机化）。
// ECDSA 用标准 ECDSA 签名（rand.Reader）。
func Sign(privateKey interface{}, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("crypto: empty digest")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("crypto: RSA key too short (%d bits), need at least 2048", key.N.BitLen())
		}
		// PSS 填充签名。
		sig, err := rsa.SignPSS(rand.Reader, key, cryptoSHA256(), digest, nil)
		if err != nil {
			return nil, fmt.Errorf("crypto: RSA-PSS sign: %w", err)
		}
		return sig, nil

	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("crypto: ECDSA curve must be P-256")
		}
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			return nil, fmt.Errorf("crypto: ECDSA sign: %w", err)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("crypto: unsupported private key type %T", privateKey)
	}
}

// Verify 用公钥验签。
//
// publicKey: *rsa.PublicKey 或 *ecdsa.PublicKey。
// digest: 原始哈希值。
// signature: Sign 返回的签名。
//
// 验签失败返回 error（不返回 bool，遵循 Go 惯例）。
func Verify(publicKey interface{}, digest, signature []byte) error {
	if len(digest) == 0 || len(signature) == 0 {
		return errors.New("crypto: empty digest or signature")
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("crypto: RSA public key too short (%d bits)", key.N.BitLen())
		}
		if err := rsa.VerifyPSS(key, cryptoSHA256(), digest, signature, nil); err != nil {
			return fmt.Errorf("crypto: RSA-PSS verify: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return errors.New("crypto: ECDSA public key curve must be P-256")
		}
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return errors.New("crypto: ECDSA verify failed")
		}
		return nil

	default:
		return fmt.Errorf("crypto: unsupported public key type %T", publicKey)
	}
}

// PrivateKeyToDER 将私钥序列化为 PKCS#8 DER 格式。
//
// 返回的 []byte 是明文私钥，调用方必须立即装入 SecureBuffer 并 clear 原 []byte。
func PrivateKeyToDER(privateKey interface{}) ([]byte, error) {
	der, err := pkcs8Marshal(privateKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal private key to PKCS#8 DER: %w", err)
	}
	return der, nil
}

// PrivateKeyToSecureDER 将私钥序列化为 PKCS#8 DER 并立即装入 SecureBuffer。
// 明文 DER []byte 在装入后被 clear + KeepAlive 擦除。
//
// 这是非对称私钥进入 lifecycle 的推荐入口。
func PrivateKeyToSecureDER(privateKey interface{}) (*memguard.SecureBuffer, error) {
	der, err := PrivateKeyToDER(privateKey)
	if err != nil {
		return nil, err
	}
	// 立即装入 SecureBuffer（NewSecureBuffer 会拷贝并清零入参）。
	sb := memguard.NewSecureBuffer(der)
	// 防御性二次 clear。
	clear(der)
	runtime.KeepAlive(der)
	return sb, nil
}

// PublicKeyToPEM 将公钥序列化为 PEM 格式（明文存储，非敏感）。
func PublicKeyToPEM(publicKey interface{}) ([]byte, error) {
	return publicKeyToPEMImpl(publicKey)
}

// cryptoSHA256 返回 crypto.SHA256 常量，避免直接 import crypto 包名冲突。
func cryptoSHA256() cryptoHash {
	return cryptoSHA256Value
}
