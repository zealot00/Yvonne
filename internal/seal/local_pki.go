// Package seal - Local PKI 自动解封。
//
// 流程：
//  1. 读取本地 PEM 文件（RSA-4096 私钥）
//  2. 从 KVStore 读取 Wrapped Master Key（key: "master-key-wrapped"）
//  3. RSA-OAEP 解密
//  4. 封装为 SecureBuffer，DirectUnseal 到 VaultState
//  5. 阅后即焚：清零 PEM 内容内存 + os.Remove(pemPath)
//
// 安全：
//   - PEM 文件读取后立刻清零内存 + 物理删除文件
//   - RSA 私钥用完即清零
//   - 解密出的 Master Key 直接进 SecureBuffer
package seal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"

	"yvonne/internal/memguard"
	"yvonne/internal/storage"
)

// WrappedMasterKeyKey 是存储中 Wrapped Master Key 的键名。
const WrappedMasterKeyKey = "master-key-wrapped"

// LocalPKIUnsealer 用本地 PKI 私钥自动解封。
type LocalPKIUnsealer struct {
	pemPath    string
	vaultState *VaultState
	store      storage.KVStore
}

// NewLocalPKIUnsealer 创建 LocalPKIUnsealer。
func NewLocalPKIUnsealer(pemPath string, vault *VaultState, store storage.KVStore) *LocalPKIUnsealer {
	return &LocalPKIUnsealer{
		pemPath:    pemPath,
		vaultState: vault,
		store:      store,
	}
}

// AutoUnseal 执行自动解封流程。
//
// 步骤：
//  1. 读取 PEM 文件 → RSA 私钥
//  2. 从 store 读取 Wrapped Master Key
//  3. RSA-OAEP SHA-256 解密
//  4. SecureBuffer 封装 + DirectUnseal
//  5. 阅后即焚：清零 PEM 内存 + os.Remove(pemPath)
func (u *LocalPKIUnsealer) AutoUnseal(ctx context.Context) (err error) {
	// 1. 读取 PEM 文件。
	pemBytes, readErr := os.ReadFile(u.pemPath)
	if readErr != nil {
		return fmt.Errorf("local_pki: read pem file: %w", readErr)
	}
	// 保证 pemBytes 在所有路径下被清理 + 文件被删除。
	unsealDone := false
	defer func() {
		// 阅后即焚：清零 PEM 内容内存。
		if pemBytes != nil {
			clear(pemBytes)
			runtime.KeepAlive(pemBytes)
		}
		// 阅后即焚：物理删除 PEM 文件（仅解封成功后删除）。
		// 安全红线：删除失败 = 明文 RSA 私钥滞留磁盘，必须 abort unseal。
		if unsealDone {
			if rmErr := os.Remove(u.pemPath); rmErr != nil && !os.IsNotExist(rmErr) {
				// 删除失败是致命安全风险：覆盖返回值，让上层知道 unseal 不完整。
				// 即使 vault 已解封，仍返回 error 让 bootstrap 拒绝继续启动。
				err = fmt.Errorf("local_pki: CRITICAL failed to delete PEM file %s after unseal: %w (private key may persist on disk)", u.pemPath, rmErr)
			}
		}
	}()

	// 2. 解析 PEM 块。
	if len(pemBytes) == 0 {
		return errors.New("local_pki: empty PEM data")
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("local_pki: no PEM block found in private key data")
	}
	if len(rest) > 0 {
		return fmt.Errorf("local_pki: trailing data after private key PEM block (%d bytes)", len(rest))
	}

	// 3. 解析 RSA 私钥（支持 PKCS#1 和 PKCS#8）。
	var rsaKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var key interface{}
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			rsaKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("local_pki: not an RSA private key")
			}
		}
	default:
		return fmt.Errorf("local_pki: unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return fmt.Errorf("local_pki: parse private key: %w", err)
	}

	// 校验密钥长度。
	if rsaKey.N.BitLen() < 2048 {
		return fmt.Errorf("local_pki: RSA key too short (%d bits), need at least 2048", rsaKey.N.BitLen())
	}

	// 4. 从 store 读取 Wrapped Master Key。
	wrappedKey, err := u.store.Get(ctx, WrappedMasterKeyKey)
	if err != nil {
		return fmt.Errorf("local_pki: read wrapped master key: %w", err)
	}
	if len(wrappedKey) == 0 {
		return errors.New("local_pki: wrapped master key is empty")
	}

	// 5. RSA-OAEP SHA-256 解密。
	decrypted, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaKey,
		wrappedKey,
		[]byte("yvonne-master-key"),
	)
	// 立刻清理 wrappedKey（密文，但仍应清理）。
	clear(wrappedKey)
	runtime.KeepAlive(wrappedKey)
	if err != nil {
		return fmt.Errorf("local_pki: RSA decrypt failed: %w", err)
	}

	// 6. 封装为 SecureBuffer 并 DirectUnseal。
	masterKey := memguard.NewSecureBuffer(decrypted)
	// NewSecureBuffer 已清零 decrypted，但防御性再 clear。
	clear(decrypted)
	runtime.KeepAlive(decrypted)

	if err := u.vaultState.DirectUnseal(masterKey); err != nil {
		masterKey.Wipe()
		return fmt.Errorf("local_pki: direct unseal failed: %w", err)
	}

	unsealDone = true
	return nil
}

// GenerateUnsealKeyPair 生成 RSA-4096 密钥对，用于 yvonne unseal-keygen CLI。
//
// 返回：
//   - privateKeyPEM: PKCS#1 PEM 编码的私钥（写入 --out 文件）
//   - publicKeyPEM: PKCS#1 PEM 编码的公钥（打印到 stdout，供初始化加密 Master Key 用）
func GenerateUnsealKeyPair() (privateKeyPEM, publicKeyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA-4096 key pair: %w", err)
	}

	// 编码私钥为 PKCS#1 PEM。
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码公钥为 PKCS#1 PEM。
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	return privateKeyPEM, publicKeyPEM, nil
}

// EncryptMasterKeyWithPublicKey 用公钥加密 Master Key，生成 Wrapped Master Key。
// 用于初始化阶段：生成 Master Key → 用公钥加密 → 存入 DB。
func EncryptMasterKeyWithPublicKey(publicKeyPEM []byte, masterKey *memguard.SecureBuffer) ([]byte, error) {
	if len(publicKeyPEM) == 0 {
		return nil, errors.New("local_pki: empty public key PEM data")
	}
	block, rest := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("local_pki: no PEM block found in public key data")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("local_pki: trailing data after public key PEM block (%d bytes)", len(rest))
	}

	var pub *rsa.PublicKey
	var err error
	switch block.Type {
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("local_pki: parse PKCS1 public key: %w", err)
		}
	case "PUBLIC KEY":
		var key interface{}
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("local_pki: parse PKIX public key: %w", err)
		}
		var ok bool
		pub, ok = key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("local_pki: not an RSA public key")
		}
	default:
		return nil, fmt.Errorf("local_pki: unsupported public key PEM type %q", block.Type)
	}

	// 通过 SecureBuffer 闭包获取明文 masterKey 用于 RSA-OAEP 加密。
	var wrapped []byte
	encErr := masterKey.WithKey(func(mk []byte) error {
		var e error
		wrapped, e = rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			pub,
			mk,
			[]byte("yvonne-master-key"),
		)
		return e
	})
	if encErr != nil {
		return nil, fmt.Errorf("local_pki: RSA encrypt master key: %w", encErr)
	}
	return wrapped, nil
}
