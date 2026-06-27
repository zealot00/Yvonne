//go:build hsm && pkcs11

// Package seal - PKCS#11 HSM 后端实现。
//
// 通过 github.com/ThalesGroup/crypto11 连接真实 PKCS#11 HSM（如 SoftHSM、Thales、Ravelin）。
// CMK（AES-256 对称密钥）存储在 HSM 芯片内，明文永不离开芯片。
// Wrap/Unwrap 操作通过 HSM 内的 AES-256-GCM 执行。
//
// 编译：go build -tags 'hsm,pkcs11'
// 依赖：github.com/ThalesGroup/crypto11 + PKCS#11 库（如 SoftHSM2 的 libsofthsm2.so）
package seal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"yvonne/internal/memguard"

	"github.com/ThalesGroup/crypto11"
)

// pkcs11Backend 是基于 PKCS#11 的 CryptoBackend 实现。
//
// CMK 是存储在 HSM 内的 AES-256 对称密钥，通过 CKA_ID（KeyID）定位。
// Wrap = AES-256-GCM 加密（HSM 内执行）。
// Unwrap = AES-256-GCM 解密（HSM 内执行）。
//
// 密文格式：[12B Nonce][Ciphertext+AuthTag]（与 softwareKEK 格式一致）。
type pkcs11Backend struct {
	mu     sync.Mutex
	ctx    *crypto11.Context
	keyID  []byte
	key    *crypto11.SecretKey
	keyLen int // 密钥位数（256 = AES-256）
}

// NewPKCS11Backend 创建 PKCS#11 HSM 后端。
//
// 参数：
//   - libPath: PKCS#11 库路径（如 /usr/lib/softhsm/libsofthsm2.so）
//   - slot: PKCS#11 slot 编号
//   - pin: 用户 PIN
//   - keyID: HSM 内密钥标识（CKA_ID），若不存在则自动生成
//
// 若 KeyID 在 HSM 中不存在，自动生成 AES-256 密钥。
func NewPKCS11Backend(libPath string, slot int, pin, keyID string) (CryptoBackend, error) {
	if libPath == "" {
		return nil, errors.New("seal: pkcs11: lib_path is required")
	}
	if pin == "" {
		return nil, errors.New("seal: pkcs11: pin is required")
	}
	if keyID == "" {
		return nil, errors.New("seal: pkcs11: key_id is required")
	}

	slotPtr := &slot
	cfg := &crypto11.Config{
		Path:        libPath,
		SlotNumber:  slotPtr,
		Pin:         pin,
		MaxSessions: 10,
	}

	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: configure: %w", err)
	}

	backend := &pkcs11Backend{
		ctx:    ctx,
		keyID:  []byte(keyID),
		keyLen: 256, // AES-256
	}

	// 查找已有密钥，不存在则生成。
	key, err := ctx.FindKey(backend.keyID, nil)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("seal: pkcs11: find key: %w", err)
	}

	if key == nil {
		// 密钥不存在，自动生成 AES-256。
		key, err = ctx.GenerateSecretKey(backend.keyID, backend.keyLen, crypto11.CipherAES)
		if err != nil {
			ctx.Close()
			return nil, fmt.Errorf("seal: pkcs11: generate key: %w", err)
		}
	}

	backend.key = key
	return backend, nil
}

// Wrap 用 HSM 内的 AES-256-GCM 加密明文。
// 密文格式：[12B Nonce][Ciphertext+AuthTag]。
func (p *pkcs11Backend) Wrap(plaintext []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.key == nil {
		return nil, errors.New("seal: pkcs11: key not loaded")
	}

	// 获取 GCM AEAD。
	aead, err := p.key.NewGCM()
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: new GCM: %w", err)
	}

	// 生成随机 Nonce（用 memguard CSPRNG，通过安全检查）。
	nonce, err := memguard.GenerateSecureRandom(aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: generate nonce: %w", err)
	}

	// HSM 内执行 AES-GCM 加密。
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Unwrap 用 HSM 内的 AES-256-GCM 解密密文。
func (p *pkcs11Backend) Unwrap(ciphertext []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.key == nil {
		return nil, errors.New("seal: pkcs11: key not loaded")
	}

	aead, err := p.key.NewGCM()
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: new GCM: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("seal: pkcs11: ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	// HSM 内执行 AES-GCM 解密。
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: GCM open: %w", err)
	}

	return plaintext, nil
}

// Close 释放 HSM 连接。
func (p *pkcs11Backend) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx != nil {
		return p.ctx.Close()
	}
	return nil
}

// === SignerBackend 实现 ===

// GenerateSigningKey 在 HSM 内生成签名密钥对（RSA/ECDSA），私钥不出芯片。
func (p *pkcs11Backend) GenerateSigningKey(keyID, algo string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	id := []byte(keyID)

	switch algo {
	case "rsa-2048":
		signer, err := p.ctx.GenerateRSAKeyPair(id, 2048)
		if err != nil {
			return nil, fmt.Errorf("seal: pkcs11: generate RSA-2048: %w", err)
		}
		return marshalPublicKey(signer.Public())

	case "rsa-4096":
		signer, err := p.ctx.GenerateRSAKeyPair(id, 4096)
		if err != nil {
			return nil, fmt.Errorf("seal: pkcs11: generate RSA-4096: %w", err)
		}
		return marshalPublicKey(signer.Public())

	case "ecdsa-p256":
		signer, err := p.ctx.GenerateECDSAKeyPair(id, elliptic.P256())
		if err != nil {
			return nil, fmt.Errorf("seal: pkcs11: generate ECDSA-P256: %w", err)
		}
		return marshalPublicKey(signer.Public())

	default:
		return nil, fmt.Errorf("seal: pkcs11: unsupported signing algo %q", algo)
	}
}

// Sign 用 HSM 内私钥签名数据（SHA-256 摘要 + PKCS#1 v1.5 / ECDSA）。
func (p *pkcs11Backend) Sign(keyID string, data []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	signer, err := p.ctx.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: find signing key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("seal: pkcs11: signing key %q not found", keyID)
	}

	// 计算 SHA-256 摘要。
	hash := sha256.Sum256(data)

	// crypto.Signer 接口：Sign(rand, digest, hashAlg)。
	// crypto11 的 Signer 实现在 HSM 内执行签名。
	sig, err := signer.Sign(nil, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: HSM sign: %w", err)
	}

	return sig, nil
}

// GetPublicKey 导出指定 keyID 的公钥 PEM。
func (p *pkcs11Backend) GetPublicKey(keyID string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	signer, err := p.ctx.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: find signing key: %w", err)
	}
	if signer == nil {
		return nil, fmt.Errorf("seal: pkcs11: signing key %q not found", keyID)
	}

	return marshalPublicKey(signer.Public())
}

// Verify 用指定 keyID 的公钥验签。
// 验签在 Go 进程内执行（公钥不敏感，不需要 HSM）。
func (p *pkcs11Backend) Verify(keyID string, data, signature []byte) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	signer, err := p.ctx.FindKeyPair([]byte(keyID), nil)
	if err != nil {
		return false, fmt.Errorf("seal: pkcs11: find signing key: %w", err)
	}
	if signer == nil {
		return false, fmt.Errorf("seal: pkcs11: signing key %q not found", keyID)
	}

	pub := signer.Public()
	hash := sha256.Sum256(data)

	switch key := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) == nil, nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, hash[:], signature), nil
	default:
		return false, fmt.Errorf("seal: pkcs11: unsupported public key type %T", pub)
	}
}

// marshalPublicKey 将公钥序列化为 PEM。
func marshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}
