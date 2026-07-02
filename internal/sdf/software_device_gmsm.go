//go:build gmsm

// SDF 软件密码机实现（gmsm 构建标签）。
//
// 用 tjfoc/gmsm 实现 GM/T 0018-2023 SDF 接口。
// 所有密码运算在内存中完成，密钥用 SecureBuffer 保护。
package sdf

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"yvonne/internal/memguard"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// softwareDevice 是纯软件 SDF 设备实现。
type softwareDevice struct {
	mu       sync.Mutex
	closed   bool
	signKeys map[int][]byte // 内置签名密钥对（index → SM2 私钥 PEM）
	encKeys  map[int][]byte // 内置加密密钥对（index → SM2 私钥 PEM）
}

// newSoftwareDevice 创建软件 SDF 设备。
func newSoftwareDevice() (Device, error) {
	dev := &softwareDevice{
		signKeys: make(map[int][]byte),
		encKeys:  make(map[int][]byte),
	}
	// 预生成 2 个内置密钥对（index 1=sign, 2=encrypt）。
	for i := 1; i <= 2; i++ {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("sdf: generate built-in key %d: %w", i, err)
		}
		// 序列化为 PEM（hex 编码存储）。
		privPEM, err := gmx509.WritePrivateKeyToPem(priv, nil)
		if err != nil {
			return nil, fmt.Errorf("sdf: marshal key %d: %w", i, err)
		}
		if i == 1 {
			dev.signKeys[i] = privPEM
		} else {
			dev.encKeys[i] = privPEM
		}
	}
	return dev, nil
}

// DeviceInfo 返回设备信息。
func (d *softwareDevice) DeviceInfo() (*DeviceInfo, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	return &DeviceInfo{
		Name:        "Yvonne Software SDF Device",
		Version:     "GM/T 0018-2023",
		Serial:      "YVONNE-SW-0001",
		MaxSessions: 1024,
	}, nil
}

// GenerateRandom 生成随机数。
func (d *softwareDevice) GenerateRandom(length int) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	if length <= 0 || length > 65536 {
		return nil, fmt.Errorf("sdf: invalid random length %d (1-65536)", length)
	}
	buf, err := memguard.GenerateSecureRandom(length)
	if err != nil {
		return nil, fmt.Errorf("sdf: generate random: %w", err)
	}
	return buf, nil
}

// GenerateSM2KeyPair 生成 SM2 密钥对。
// 返回 hex 编码的公钥（04||x||y）和私钥（PEM）。
func (d *softwareDevice) GenerateSM2KeyPair() (pubKey, privKey []byte, err error) {
	if d.closed {
		return nil, nil, errors.New("sdf: device is closed")
	}
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sdf: generate SM2 key: %w", err)
	}
	// 公钥：04||x(32)||y(32) → hex。
	pub := sm2.Compress(&priv.PublicKey)
	// 用未压缩格式（04||x||y）。
	pubBytes := append([]byte{0x04}, append(priv.PublicKey.X.Bytes(), priv.PublicKey.Y.Bytes()...)...)
	_ = pub // 避免 unused
	pubHex := make([]byte, hex.EncodedLen(len(pubBytes)))
	hex.Encode(pubHex, pubBytes)

	// 私钥 PEM。
	privPEM, err := gmx509.WritePrivateKeyToPem(priv, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("sdf: marshal SM2 private key: %w", err)
	}
	return pubHex, privPEM, nil
}

// ExportSignPublicKey 导出内置签名公钥。
func (d *softwareDevice) ExportSignPublicKey(index int) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	privPEM, ok := d.signKeys[index]
	if !ok {
		return nil, fmt.Errorf("sdf: sign key index %d not found", index)
	}
	return exportSMPublicKeyHex(privPEM)
}

// ExportEncPublicKey 导出内置加密公钥。
func (d *softwareDevice) ExportEncPublicKey(index int) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	privPEM, ok := d.encKeys[index]
	if !ok {
		return nil, fmt.Errorf("sdf: enc key index %d not found", index)
	}
	return exportSMPublicKeyHex(privPEM)
}

// SM2Sign 用 SM2 私钥签名（SM2WithSM3）。
func (d *softwareDevice) SM2Sign(privKey, data []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	if len(privKey) == 0 || len(data) == 0 {
		return nil, errors.New("sdf: empty private key or data")
	}
	priv, err := gmx509.ReadPrivateKeyFromPem(privKey, nil)
	if err != nil {
		return nil, fmt.Errorf("sdf: parse SM2 private key: %w", err)
	}
	sig, err := priv.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, fmt.Errorf("sdf: SM2 sign: %w", err)
	}
	return sig, nil
}

// SM2Verify 验证 SM2 签名。
func (d *softwareDevice) SM2Verify(pubKey, data, sig []byte) (bool, error) {
	if d.closed {
		return false, errors.New("sdf: device is closed")
	}
	if len(pubKey) == 0 || len(data) == 0 || len(sig) == 0 {
		return false, errors.New("sdf: empty public key, data, or signature")
	}
	// pubKey 是 hex 编码的 04||x||y。
	pubBytes, err := hex.DecodeString(string(pubKey))
	if err != nil {
		return false, fmt.Errorf("sdf: decode public key hex: %w", err)
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(pubBytes[1:33])
	pub.Y = new(big.Int).SetBytes(pubBytes[33:65])
	if !pub.Verify(data, sig) {
		return false, nil
	}
	return true, nil
}

// SM2Encrypt 用 SM2 公钥加密。
func (d *softwareDevice) SM2Encrypt(pubKey, data []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	pubBytes, err := hex.DecodeString(string(pubKey))
	if err != nil {
		return nil, fmt.Errorf("sdf: decode public key hex: %w", err)
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(pubBytes[1:33])
	pub.Y = new(big.Int).SetBytes(pubBytes[33:65])
	ciphertext, err := sm2.Encrypt(pub, data, rand.Reader, sm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("sdf: SM2 encrypt: %w", err)
	}
	return ciphertext, nil
}

// SM2Decrypt 用 SM2 私钥解密。
func (d *softwareDevice) SM2Decrypt(privKey, ciphertext []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	priv, err := gmx509.ReadPrivateKeyFromPem(privKey, nil)
	if err != nil {
		return nil, fmt.Errorf("sdf: parse SM2 private key: %w", err)
	}
	plaintext, err := sm2.Decrypt(priv, ciphertext, sm2.C1C3C2)
	if err != nil {
		return nil, fmt.Errorf("sdf: SM2 decrypt: %w", err)
	}
	return plaintext, nil
}

// SM3Hash 计算 SM3 哈希。
func (d *softwareDevice) SM3Hash(data []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// SM4Encrypt 用 SM4 ECB 模式加密（GM/T 0018 默认 ECB）。
func (d *softwareDevice) SM4Encrypt(key, data []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("sdf: SM4 key must be 16 bytes, got %d", len(key))
	}
	cipher, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sdf: SM4 new cipher: %w", err)
	}
	// PKCS#7 填充到 16 字节块。
	padded := pkcs7Pad(data, 16)
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		cipher.Encrypt(encrypted[i:i+16], padded[i:i+16])
	}
	return encrypted, nil
}

// SM4Decrypt 用 SM4 ECB 模式解密。
func (d *softwareDevice) SM4Decrypt(key, data []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	if len(key) != 16 {
		return nil, fmt.Errorf("sdf: SM4 key must be 16 bytes, got %d", len(key))
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("sdf: SM4 ciphertext must be multiple of 16, got %d", len(data))
	}
	cipher, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sdf: SM4 new cipher: %w", err)
	}
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		cipher.Decrypt(decrypted[i:i+16], data[i:i+16])
	}
	return pkcs7Unpad(decrypted, 16)
}

// WrapKey 用 KEK 包装目标密钥（SM4 ECB 加密）。
func (d *softwareDevice) WrapKey(kekKey, targetKey []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	return d.SM4Encrypt(kekKey, targetKey)
}

// UnwrapKey 用 KEK 解包密钥（SM4 ECB 解密）。
func (d *softwareDevice) UnwrapKey(kekKey, wrappedKey []byte) ([]byte, error) {
	if d.closed {
		return nil, errors.New("sdf: device is closed")
	}
	return d.SM4Decrypt(kekKey, wrappedKey)
}

// Close 关闭设备。
func (d *softwareDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	// 清除内置密钥。
	for k := range d.signKeys {
		d.signKeys[k] = nil
	}
	for k := range d.encKeys {
		d.encKeys[k] = nil
	}
	return nil
}

// exportSMPublicKeyHex 从私钥 PEM 导出公钥 hex（04||x||y）。
func exportSMPublicKeyHex(privPEM []byte) ([]byte, error) {
	priv, err := gmx509.ReadPrivateKeyFromPem(privPEM, nil)
	if err != nil {
		return nil, fmt.Errorf("sdf: parse SM2 private key: %w", err)
	}
	pubBytes := append([]byte{0x04}, append(priv.PublicKey.X.Bytes(), priv.PublicKey.Y.Bytes()...)...)
	pubHex := make([]byte, hex.EncodedLen(len(pubBytes)))
	hex.Encode(pubHex, pubBytes)
	return pubHex, nil
}

// pkcs7Pad PKCS#7 填充。
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpad PKCS#7 去填充。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("sdf: invalid padding data length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errors.New("sdf: invalid PKCS#7 padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, errors.New("sdf: invalid PKCS#7 padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}
