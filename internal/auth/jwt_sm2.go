//go:build gmsm

// Package auth - JWT SM2 签名方法支持（国密模式）。
//
// 在 -tags gmsm 编译时，JWT 支持 signing_method: "SM2"。
// SM2 签名使用 SM3 作为摘要算法（GB/T 32918.2）。
package auth

import (
	"crypto"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tjfoc/gmsm/sm2"
	gmsmx509 "github.com/tjfoc/gmsm/x509"
)

// SigningMethodSM2 是 JWT SM2 签名方法。
// 实现 jwt.SigningMethod 接口。
type SigningMethodSM2 struct{}

// Alg 返回算法名称。
func (m *SigningMethodSM2) Alg() string { return "SM2" }

// Verify 验证 SM2 签名的 JWT。
func (m *SigningMethodSM2) Verify(signingString string, signature []byte, key any) error {
	pub, ok := key.(*sm2.PublicKey)
	if !ok {
		return fmt.Errorf("auth: SM2 verify: invalid key type %T", key)
	}

	uid := []byte("1234567812345678")
	r, s, err := sm2.SignDataToSignDigit(signature)
	if err != nil {
		return fmt.Errorf("auth: SM2 verify: decode signature: %w", err)
	}

	if !sm2.Sm2Verify(pub, []byte(signingString), uid, r, s) {
		return jwt.ErrSignatureInvalid
	}
	return nil
}

// Sign 用 SM2 私钥签名 JWT。
func (m *SigningMethodSM2) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("auth: SM2 sign: invalid key type %T", key)
	}

	uid := []byte("1234567812345678")
	r, s, err := sm2.Sm2Sign(priv, []byte(signingString), uid, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: SM2 sign: %w", err)
	}

	sig, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		return nil, fmt.Errorf("auth: SM2 sign: encode: %w", err)
	}
	return sig, nil
}

// init 注册 SM2 签名方法。
func init() {
	jwt.RegisterSigningMethod("SM2", func() jwt.SigningMethod {
		return &SigningMethodSM2{}
	})
}

// loadSM2PublicKey 从 PEM 文件加载 SM2 公钥。
func loadSM2PublicKey(path string) (*sm2.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("auth: no PEM block found")
	}
	pub, err := gmsmx509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse SM2 public key: %w", err)
	}
	return pub, nil
}

// ensure crypto import is used (for jwt.SigningMethod interface compliance).
var _ crypto.SignerOpts = crypto.SHA256
var _ = sha256.New
