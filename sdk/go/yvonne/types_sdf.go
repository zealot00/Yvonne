// Package yvonne - SDF 请求/响应类型（v1.4.0，GM/T 0018-2023）。
//
// 与 internal/sdf/server.go 的 JSON 字段严格一致。
// 二进制数据（密钥/密文/签名/哈希）用 hex 字符串编码。
package yvonne

// === SDF 响应类型 ===

// SDFDeviceInfoResponse SDF 设备信息响应。
type SDFDeviceInfoResponse struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Serial      string `json:"serial,omitempty"`
	MaxSessions int    `json:"max_sessions,omitempty"`
}

// SDFRandomResponse 随机数响应（hex）。
type SDFRandomResponse struct {
	Random string `json:"random"`
}

// SDFSM2KeyPairResponse SM2 密钥对响应。
// 公私钥为 PEM 编码字符串（tjfoc 格式）。
type SDFSM2KeyPairResponse struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// SDFSM2SignResponse SM2 签名响应（hex）。
type SDFSM2SignResponse struct {
	Signature string `json:"signature"`
}

// SDFSM2VerifyResponse SM2 验签响应。
type SDFSM2VerifyResponse struct {
	Valid bool `json:"valid"`
}

// SDFSM2EncryptResponse SM2 加密响应（hex）。
type SDFSM2EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

// SDFSM2DecryptResponse SM2 解密响应（hex）。
type SDFSM2DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

// SDFSM3HashResponse SM3 哈希响应（hex）。
type SDFSM3HashResponse struct {
	Hash string `json:"hash"`
}

// SDFSM4EncryptResponse SM4 加密响应（hex）。
type SDFSM4EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

// SDFSM4DecryptResponse SM4 解密响应（hex）。
type SDFSM4DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}
