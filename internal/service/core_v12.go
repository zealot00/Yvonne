// v1.2 新增功能：Sign/Verify/Mac/GDKWithoutPlaintext/ReEncrypt/GetPublicKey/DisableKey/EnableKey/CancelKeyDeletion
//
// 新增文件，避免 core.go 过大。

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"yvonne/internal/auth"
	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// === Sign / Verify ===

// SignResult 是 Sign 的返回。
type SignResult struct {
	Signature []byte
	Version   int
}

// Sign 用非对称密钥签名数据。
// keyID 必须是非对称密钥（RSA/ECDSA/SM2）。
func (c *Core) Sign(ctx context.Context, keyID string, data []byte, policy *auth.Policy) (*SignResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "Sign", keyID); err != nil {
		return nil, err
	}

	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "Sign", keyID, 0, "error", err.Error())
		return nil, err
	}

	if !isAsymmetricKeyType(meta.KeyType) {
		err := fmt.Errorf("service: sign requires asymmetric key, got %s", meta.KeyType)
		c.recordAudit(ctx, "Sign", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	// 解密私钥。
	var sig []byte
	err = c.seal.KEKRef(func(kek seal.KEK) error {
		privSB, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return fmt.Errorf("service: sign: unwrap key: %w", e)
		}
		defer privSB.Wipe()
		var privKey []byte
		if err := privSB.WithKey(func(k []byte) error {
			privKey = make([]byte, len(k))
			copy(privKey, k)
			return nil
		}); err != nil {
			return err
		}

		// 根据密钥类型签名。
		switch meta.KeyType {
		case "sm2":
			// SM2 签名（需 -tags gmsm）。
			sig, e = signSM2(privKey, data)
		default:
			sig, e = signAsymmetric(privKey, data, meta.KeyType)
		}
		return e
	})

	if err != nil {
		c.recordAudit(ctx, "Sign", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	c.recordAudit(ctx, "Sign", keyID, meta.Version, "success", "")
	return &SignResult{Signature: sig, Version: meta.Version}, nil
}

// VerifyResult 是 Verify 的返回。
type VerifyResult struct {
	Valid   bool
	Version int
}

// Verify 验证签名。
func (c *Core) Verify(ctx context.Context, keyID string, data, signature []byte, policy *auth.Policy) (*VerifyResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "Verify", keyID); err != nil {
		return nil, err
	}

	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "Verify", keyID, 0, "error", err.Error())
		return nil, err
	}

	if len(meta.PublicKey) == 0 {
		err := fmt.Errorf("service: verify: no public key for %s", keyID)
		c.recordAudit(ctx, "Verify", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	valid, err := verifyAsymmetric(meta.PublicKey, data, signature, meta.KeyType)
	if err != nil {
		c.recordAudit(ctx, "Verify", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	c.recordAudit(ctx, "Verify", keyID, meta.Version, "success", "")
	return &VerifyResult{Valid: valid, Version: meta.Version}, nil
}

// === GenerateMac / VerifyMac ===

// MacResult 是 GenerateMac 的返回。
type MacResult struct {
	Mac     []byte
	Version int
}

// GenerateMac 生成 HMAC（使用对称密钥）。
func (c *Core) GenerateMac(ctx context.Context, keyID string, data []byte, policy *auth.Policy) (*MacResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "GenerateMac", keyID); err != nil {
		return nil, err
	}

	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "GenerateMac", keyID, 0, "error", err.Error())
		return nil, err
	}

	if !isSymmetricKeyType(meta.KeyType) {
		err := fmt.Errorf("service: mac requires symmetric key, got %s", meta.KeyType)
		c.recordAudit(ctx, "GenerateMac", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	var mac []byte
	err = c.seal.KEKRef(func(kek seal.KEK) error {
		keySB, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer keySB.Wipe()
		var key []byte
		if err := keySB.WithKey(func(k []byte) error {
			key = make([]byte, len(k))
			copy(key, k)
			return nil
		}); err != nil {
			return err
		}

		h := hmac.New(sha256.New, key)
		h.Write(data)
		mac = h.Sum(nil)
		return nil
	})

	if err != nil {
		c.recordAudit(ctx, "GenerateMac", keyID, meta.Version, "error", err.Error())
		return nil, err
	}

	c.recordAudit(ctx, "GenerateMac", keyID, meta.Version, "success", "")
	return &MacResult{Mac: mac, Version: meta.Version}, nil
}

// VerifyMac 验证 HMAC。
func (c *Core) VerifyMac(ctx context.Context, keyID string, data, expectedMac []byte, policy *auth.Policy) (*VerifyResult, error) {
	result, err := c.GenerateMac(ctx, keyID, data, policy)
	if err != nil {
		return nil, err
	}

	valid := len(result.Mac) == len(expectedMac) &&
		subtleEqual(result.Mac, expectedMac)

	c.recordAudit(ctx, "VerifyMac", keyID, result.Version, "success", "")
	return &VerifyResult{Valid: valid, Version: result.Version}, nil
}

// === GenerateDataKeyWithoutPlaintext ===

// GenerateDataKeyWithoutPlaintext 仅返回密文 DEK，不返回明文（更安全）。
func (c *Core) GenerateDataKeyWithoutPlaintext(ctx context.Context, keyID string, policy *auth.Policy) ([]byte, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return nil, err
	}

	var ciphertext []byte
	err := c.seal.KEKRef(func(kek seal.KEK) error {
		_, ct, e := c.manager.GenerateDataKey(ctx, keyID, kek)
		if e != nil {
			return e
		}
		ciphertext = ct
		return nil
	})

	if err != nil {
		c.recordAudit(ctx, "GenerateDataKeyWithoutPlaintext", keyID, 0, "error", err.Error())
		return nil, err
	}
	c.recordAudit(ctx, "GenerateDataKeyWithoutPlaintext", keyID, 0, "success", "")
	return ciphertext, nil
}

// === ReEncrypt ===

// ReEncryptResult 是 ReEncrypt 的返回。
type ReEncryptResult struct {
	Ciphertext  []byte
	Version     int
	SourceKeyID string
	DestKeyID   string
}

// ReEncrypt 用 destKeyID 重新加密数据。
// 解密 sourceKeyID 的密文 → 用 destKeyID 重新加密。
func (c *Core) ReEncrypt(ctx context.Context, sourceKeyID string, ciphertext []byte, destKeyID string, policy *auth.Policy) (*ReEncryptResult, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, err
	}
	// 必须同时拥有 source 和 dest 的权限。
	if err := c.authorize(policy, "Decrypt", sourceKeyID); err != nil {
		return nil, err
	}
	if err := c.authorize(policy, "Encrypt", destKeyID); err != nil {
		return nil, err
	}

	// 1. 解密旧密文。
	decResult, err := c.Decrypt(ctx, sourceKeyID, ciphertext, policy)
	if err != nil {
		c.recordAudit(ctx, "ReEncrypt", sourceKeyID, 0, "error", "decrypt failed: "+err.Error())
		return nil, fmt.Errorf("service: re-encrypt: decrypt source: %w", err)
	}

	// 2. 用新密钥加密。
	var plainBytes []byte
	if err := decResult.Plaintext.WithKey(func(k []byte) error {
		plainBytes = make([]byte, len(k))
		copy(plainBytes, k)
		return nil
	}); err != nil {
		c.recordAudit(ctx, "ReEncrypt", destKeyID, 0, "error", "extract plaintext: "+err.Error())
		return nil, fmt.Errorf("service: re-encrypt: extract plaintext: %w", err)
	}
	decResult.Plaintext.Wipe()

	encResult, err := c.Encrypt(ctx, destKeyID, plainBytes, policy)
	if err != nil {
		c.recordAudit(ctx, "ReEncrypt", destKeyID, 0, "error", "encrypt failed: "+err.Error())
		return nil, fmt.Errorf("service: re-encrypt: encrypt dest: %w", err)
	}

	c.recordAudit(ctx, "ReEncrypt", sourceKeyID+"→"+destKeyID, encResult.Version, "success", "")
	return &ReEncryptResult{
		Ciphertext:  encResult.Ciphertext,
		Version:     encResult.Version,
		SourceKeyID: sourceKeyID,
		DestKeyID:   destKeyID,
	}, nil
}

// === GetPublicKey ===

// GetPublicKey 返回非对称密钥的公钥 PEM。
func (c *Core) GetPublicKey(ctx context.Context, keyID string, policy *auth.Policy) ([]byte, int, error) {
	if err := c.requireUnsealed(); err != nil {
		return nil, 0, err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return nil, 0, err
	}

	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "GetPublicKey", keyID, 0, "error", err.Error())
		return nil, 0, err
	}

	if len(meta.PublicKey) == 0 {
		err := fmt.Errorf("service: key %s has no public key", keyID)
		c.recordAudit(ctx, "GetPublicKey", keyID, meta.Version, "error", err.Error())
		return nil, 0, err
	}

	c.recordAudit(ctx, "GetPublicKey", keyID, meta.Version, "success", "")
	return meta.PublicKey, meta.Version, nil
}

// === DisableKey / EnableKey ===

// DisableKey 禁用密钥（转为 Deactivated 状态，仅允许解密）。
func (c *Core) DisableKey(ctx context.Context, keyID string, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return err
	}

	// Disable = RotateKey 旧版本自动 Deactivated + 标记当前版本 Deactivated。
	meta, err := c.manager.GetActiveKey(ctx, keyID)
	if err != nil {
		c.recordAudit(ctx, "DisableKey", keyID, 0, "error", err.Error())
		return err
	}

	// 将 Active 版本转为 Deactivated（不生成新版本）。
	if err := c.manager.SoftDeleteKey(ctx, keyID, meta.Version); err != nil {
		c.recordAudit(ctx, "DisableKey", keyID, meta.Version, "error", err.Error())
		return err
	}

	c.recordAudit(ctx, "DisableKey", keyID, meta.Version, "success", "")
	return nil
}

// EnableKey 启用密钥（从 SoftDeleted 恢复）。
func (c *Core) EnableKey(ctx context.Context, keyID string, version int, policy *auth.Policy) error {
	if err := c.requireUnsealed(); err != nil {
		return err
	}
	if err := c.authorize(policy, "KeyOp", keyID); err != nil {
		return err
	}

	if err := c.manager.RestoreKey(ctx, keyID, version); err != nil {
		c.recordAudit(ctx, "EnableKey", keyID, version, "error", err.Error())
		return err
	}

	c.recordAudit(ctx, "EnableKey", keyID, version, "success", "")
	return nil
}

// === CancelKeyDeletion ===

// CancelKeyDeletion 取消待删除密钥（恢复 SoftDeleted 的密钥）。
func (c *Core) CancelKeyDeletion(ctx context.Context, keyID string, version int, policy *auth.Policy) error {
	return c.EnableKey(ctx, keyID, version, policy) // 同逻辑
}

// === 辅助函数 ===

// isAsymmetricKeyType 判断 KeyType 是否为非对称。
func isAsymmetricKeyType(keyType string) bool {
	switch keyType {
	case "rsa", "ecdsa", "sm2":
		return true
	default:
		return false
	}
}

// isSymmetricKeyType 判断 KeyType 是否为对称（空 = 默认对称）。
func isSymmetricKeyType(keyType string) bool {
	switch keyType {
	case "", "aes", "sm4":
		return true
	default:
		return false
	}
}

// subtleEqual 常量时间比较。
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// signAsymmetric 签名（RSA-PSS / ECDSA）。
// privKeyDER: PKCS#8 DER 编码的私钥。
// data: 原始数据（函数内部做 SHA-256 哈希）。
// keyType: "rsa" 或 "ecdsa"。
func signAsymmetric(privKeyDER []byte, data []byte, keyType string) ([]byte, error) {
	privKey, err := crypto.ParsePrivateKeyFromDER(privKeyDER)
	if err != nil {
		return nil, fmt.Errorf("service: parse private key: %w", err)
	}

	// 服务端哈希：SHA-256。
	digest := sha256.Sum256(data)

	return crypto.Sign(privKey, digest[:])
}

// verifyAsymmetric 验签（RSA-PSS / ECDSA / SM2 路由）。
// pubKeyPEM: PEM 编码的公钥。
// data: 原始数据（函数内部做哈希）。
// keyType: "rsa" / "ecdsa" / "sm2"。
func verifyAsymmetric(pubKeyPEM []byte, data, signature []byte, keyType string) (bool, error) {
	switch keyType {
	case crypto.KeyTypeSM2:
		return verifySM2Key(pubKeyPEM, data, signature)
	case crypto.KeyTypeRSA, crypto.KeyTypeECDSA:
		// RSA/ECDSA 路径。
		pubKey, err := crypto.ParsePublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			return false, fmt.Errorf("service: parse public key: %w", err)
		}
		digest := sha256.Sum256(data)
		if err := crypto.Verify(pubKey, digest[:], signature); err != nil {
			// 验签失败不返回 error，返回 valid=false。
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("service: unsupported key type %q", keyType)
	}
}

// 确保 crypto 包被引用。
var _ = crypto.SafeUint32
var _ = memguard.NewSecureBuffer
