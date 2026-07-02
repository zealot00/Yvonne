// Package crypto - crypto.Signer 适配器（PKI 证书签发用）。
//
// 证书签发需要 crypto.Signer 接口（x509.CreateCertificate 内部调用）。
// 本文件把 KEK 解密后的私钥包装为 crypto.Signer，
// 签名完成后立即 Wipe 底层 SecureBuffer。
//
// 安全红线：
//   - Sign 方法内部不做哈希（x509.CreateCertificate 传入已哈希的 digest）
//   - SecureBuffer 在适配器 Dispose 时 Wipe
//   - 适配器不长期持有明文密钥
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"yvonne/internal/memguard"
)

// SecureSigner 把 KEK 解密后的私钥包装为 crypto.Signer。
//
// 用法：
//
//	signer, err := NewSecureSigner(privKeyBytes, keyType)
//	defer signer.Dispose()
//	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signer)
//
// Dispose 后 Signer 不可再用。
type SecureSigner struct {
	priv    interface{} // *rsa.PrivateKey / *ecdsa.PrivateKey / SM2 私钥（gmsm 标签下）
	sb      *memguard.SecureBuffer
	wiped   bool
}

// NewSecureSigner 从私钥字节（DER 或 PEM，取决于 keyType）创建 crypto.Signer。
//
// keyType: "rsa" / "ecdsa" / "sm2"
// privBytes: PKCS#8 DER（rsa/ecdsa）或 PEM（sm2，tjfoc 格式）
func NewSecureSigner(privBytes []byte, keyType string) (*SecureSigner, error) {
	switch keyType {
	case KeyTypeRSA, KeyTypeECDSA:
		// PKCS#8 DER 路径。
		priv, err := ParsePrivateKeyFromDER(privBytes)
		if err != nil {
			return nil, fmt.Errorf("crypto: parse private key for signer: %w", err)
		}
		// 装入 SecureBuffer（持有 DER 副本，Dispose 时 Wipe）。
		sb := memguard.NewSecureBuffer(privBytes)
		return &SecureSigner{priv: priv, sb: sb}, nil

	case KeyTypeSM2:
		// SM2 走 gmsm 路径（signer_sm2.go / signer_sm2_stub.go）。
		return newSM2SecureSigner(privBytes)

	default:
		return nil, fmt.Errorf("crypto: unsupported key type for signer: %q", keyType)
	}
}

// Public 实现 crypto.Signer 接口。
func (s *SecureSigner) Public() crypto.PublicKey {
	if s.wiped {
		return nil
	}
	switch k := s.priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		// SM2 路径在 signer_sm2.go 中覆盖。
		return sm2SignerPublic(s.priv)
	}
}

// Sign 实现 crypto.Signer 接口。
//
// randReader 是随机数源；digest 是已计算好的哈希值；opts 指定签名算法。
// RSA 强制 PSS；ECDSA 用标准 ECDSA；SM2 用 SM2WithSM3。
func (s *SecureSigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.wiped {
		return nil, errors.New("crypto: signer already disposed")
	}
	if len(digest) == 0 {
		return nil, errors.New("crypto: empty digest for signer")
	}

	switch k := s.priv.(type) {
	case *rsa.PrivateKey:
		// 证书签名用 PSS（与现有 Sign 一致）。
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest, nil)
		if err != nil {
			return nil, fmt.Errorf("crypto: signer RSA-PSS sign: %w", err)
		}
		return sig, nil

	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("crypto: signer ECDSA sign: %w", err)
		}
		return sig, nil

	default:
		// SM2 路径。
		return sm2SignerSign(s.priv, digest)
	}
}

// Dispose 立即 Wipe 底层 SecureBuffer。调用后 Signer 不可再用。
func (s *SecureSigner) Dispose() {
	if s.sb != nil {
		s.sb.Wipe()
	}
	s.wiped = true
}
