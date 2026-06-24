// Package crypto - 版本化密文格式（Self-Routing Ciphertext）。
//
// 密文二进制格式（严格定义）：
//
//	[Version (uint32, 4 bytes, BigEndian)] [Nonce (12 bytes)] [Ciphertext + AuthTag (变长)]
//
// 解密时先切片读取前 4 字节解析 KeyVersion，再按版本路由到对应 DEK。
//
// 安全红线：
//   - 版本号必须用 encoding/binary.BigEndian 解析，防范不同架构 CPU 字节序错乱。
//   - 明文 DEK 装入 SecureBuffer 后用完必须 clear + KeepAlive。
package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// VersionPrefixSize 是密文前版本号的字节长度（uint32 = 4 字节）。
const VersionPrefixSize = 4

// NonceSize 是 GCM Nonce 长度（12 字节）。
const NonceSize = 12

// MinCiphertextSize 是合法密文的最小长度。
// Version(4) + Nonce(12) + GCM AuthTag(16) = 32 字节。
// 少于此长度必然是截断或篡改的密文，直接拒绝解析以防 index out of range。
const MinCiphertextSize = VersionPrefixSize + NonceSize + 16

// ErrCiphertextTooShort 密文过短。
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// EncodeVersionedCiphertext 将版本号、Nonce、密文体拼接为自路由密文格式。
//
// 格式：[Version uint32 BE][Nonce][Ciphertext+AuthTag]
func EncodeVersionedCiphertext(version uint32, nonce, ciphertext []byte) []byte {
	out := make([]byte, VersionPrefixSize+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(out[:VersionPrefixSize], version)
	copy(out[VersionPrefixSize:VersionPrefixSize+len(nonce)], nonce)
	copy(out[VersionPrefixSize+len(nonce):], ciphertext)
	return out
}

// DecodeVersionedCiphertext 从自路由密文中解析版本号与剩余密文体。
//
// 返回：
//   - version: 密钥版本号
//   - nonce: GCM Nonce（12 字节）
//   - ciphertext: 密文 + AuthTag
//   - error: 密文过短或格式错误
func DecodeVersionedCiphertext(raw []byte) (version uint32, nonce, ciphertext []byte, err error) {
	if len(raw) < MinCiphertextSize {
		return 0, nil, nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrCiphertextTooShort, len(raw), MinCiphertextSize)
	}

	version = binary.BigEndian.Uint32(raw[:VersionPrefixSize])
	nonce = raw[VersionPrefixSize : VersionPrefixSize+NonceSize]
	ciphertext = raw[VersionPrefixSize+NonceSize:]
	return version, nonce, ciphertext, nil
}

// ExtractVersion 仅解析密文头部的版本号（不解密）。
// 用于 decrypt handler 路由到对应版本的 DEK。
func ExtractVersion(raw []byte) (uint32, error) {
	if len(raw) < VersionPrefixSize {
		return 0, fmt.Errorf("%w: cannot extract version from %d bytes", ErrCiphertextTooShort, len(raw))
	}
	return binary.BigEndian.Uint32(raw[:VersionPrefixSize]), nil
}
