//go:build gmsm

// Package crypto - 国密套件（SM4-GCM + SM3 + SM2）。
//
// 符合标准：
//   - SM4: GB/T 32907（分组密码算法）
//   - SM3: GB/T 32905（密码杂凑算法）
//   - SM2: GB/T 32918（椭圆曲线公钥密码算法）
//   - HMAC-SM3: GM/T 0054（密码应用消息认证码）
//
// 依赖：github.com/tjfoc/gmsm
// 编译：go build -tags gmsm
package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"io"

	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"

	"yvonne/internal/memguard"
)

// GMSMCipher 是 SM4-GCM 对称加密实现。
// SM4 密钥长度 16 字节（128 位），GCM nonce 12 字节。
// 密文格式：[12B Nonce][Ciphertext+AuthTag]，与 AES-GCM 结构一致。
type GMSMCipher struct{}

// NewGMSMCipher 创建国密 Cipher。
func NewGMSMCipher() Cipher { return GMSMCipher{} }

func (GMSMCipher) Encrypt(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error) {
	var ct []byte
	err := key.WithKey(func(k []byte) error {
		if len(k) < 16 {
			return errors.New("crypto: SM4 key must be 16 bytes")
		}
		block, e := sm4.NewCipher(k[:16])
		if e != nil {
			return e
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return e
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
			return e
		}
		ct = gcm.Seal(nonce, nonce, plaintext, nil)
		return nil
	})
	return ct, err
}

func (GMSMCipher) Decrypt(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error) {
	var pt []byte
	err := key.WithKey(func(k []byte) error {
		if len(k) < 16 {
			return errors.New("crypto: SM4 key must be 16 bytes")
		}
		block, e := sm4.NewCipher(k[:16])
		if e != nil {
			return e
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return e
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) <= nonceSize {
			return errors.New("crypto: SM4 ciphertext too short")
		}
		nonce := ciphertext[:nonceSize]
		ct := ciphertext[nonceSize:]
		pt, e = gcm.Open(nil, nonce, ct, nil)
		return e
	})
	if err != nil {
		return nil, err
	}
	sb := memguard.NewSecureBuffer(pt)
	for i := range pt {
		pt[i] = 0
	}
	return sb, nil
}

func (GMSMCipher) KeySize() int { return 16 }
func (GMSMCipher) Name() string { return "sm4-gcm" }

// GMSMHash 是 SM3 哈希实现。
type GMSMHash struct{}

// NewGMSMHash 创建国密 Hash。
func NewGMSMHash() Hash { return GMSMHash{} }

func (GMSMHash) Sum(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

func (GMSMHash) Size() int    { return 32 }
func (GMSMHash) Name() string { return "sm3" }

func (GMSMHash) HMAC(key, data []byte) []byte {
	mac := hmac.New(sm3.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// GMSMSuite 是国密密码套件（SM4-GCM + SM3）。
type GMSMSuite struct{}

// NewGMSMSuite 创建国密套件。
func NewGMSMSuite() (CryptoSuite, error) { return GMSMSuite{}, nil }

func (GMSMSuite) Cipher() Cipher { return GMSMCipher{} }
func (GMSMSuite) Hash() Hash     { return GMSMHash{} }
func (GMSMSuite) Name() string   { return string(SuiteGMSM) }
