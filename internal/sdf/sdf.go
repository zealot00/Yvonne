// Package sdf — GM/T 0018-2023 密码设备应用接口规范（Go 风格接口）。
//
// 本包定义 SDF（Secure Data Format / 密码设备应用接口）的 Go 接口，
// 并提供纯软件实现（用 tjfoc/gmsm）。
//
// SDF 是中国密码行业的 HSM 标准接口，定义了密码设备的应用层 API。
// 集成 SDF 后，Yvonne 可作为"软件国密密码机"对外提供 SDF 服务。
//
// 安全红线：
//   - 软件实现无硬件隔离，仅适用于密评二级以下场景
//   - 密钥操作在内存中完成，用 memguard.SecureBuffer 保护
//   - 无商密产品认证，生产环境需与密评机构确认
package sdf

import "errors"

// Device 是 SDF 密码设备接口（GM/T 0018-2023）。
//
// 接口设计为 Go 风格（非 C FFI），便于 HTTP/gRPC 暴露。
// 二进制数据（密钥/密文/签名）在 HTTP 层用 hex 编码传输。
type Device interface {
	// 设备管理
	DeviceInfo() (*DeviceInfo, error)
	GenerateRandom(length int) ([]byte, error)

	// SM2 密钥管理
	GenerateSM2KeyPair() (pubKey, privKey []byte, err error)
	ExportSignPublicKey(index int) ([]byte, error)
	ExportEncPublicKey(index int) ([]byte, error)

	// SM2 签名/验签
	SM2Sign(privKey, data []byte) ([]byte, error)
	SM2Verify(pubKey, data, sig []byte) (bool, error)

	// SM2 加密/解密
	SM2Encrypt(pubKey, data []byte) ([]byte, error)
	SM2Decrypt(privKey, ciphertext []byte) ([]byte, error)

	// SM3 哈希
	SM3Hash(data []byte) ([]byte, error)

	// SM4 对称加密
	SM4Encrypt(key, data []byte) ([]byte, error)
	SM4Decrypt(key, data []byte) ([]byte, error)

	// 密钥包装
	WrapKey(kekKey, targetKey []byte) ([]byte, error)
	UnwrapKey(kekKey, wrappedKey []byte) ([]byte, error)

	// 关闭设备
	Close() error
}

// DeviceInfo 是设备信息。
type DeviceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Serial      string `json:"serial"`
	MaxSessions int    `json:"max_sessions"`
}

// ErrSDFNotAvailable 表示 SDF 设备不可用（无 gmsm 构建标签）。
var ErrSDFNotAvailable = errors.New("sdf: software device requires -tags gmsm")

// NewSoftwareDevice 创建软件 SDF 设备。
// 无 gmsm 构建标签时返回 ErrSDFNotAvailable。
func NewSoftwareDevice() (Device, error) {
	return newSoftwareDevice()
}
