// Package crypto - 公钥解析统一入口（支持 RSA/ECDSA/SM2）。
package crypto

import (
	"fmt"
)

// ParsePublicKey 从 PEM 解析公钥，按 keyType 分发到标准库或 gmsm 路径。
//
// keyType: "rsa" / "ecdsa" / "sm2"
// pemBytes: 公钥 PEM
func ParsePublicKey(pemBytes []byte, keyType string) (interface{}, error) {
	switch keyType {
	case KeyTypeRSA, KeyTypeECDSA:
		return ParsePublicKeyFromPEM(pemBytes)
	case KeyTypeSM2:
		return ParseSM2PublicKey(pemBytes)
	default:
		return nil, fmt.Errorf("crypto: unsupported key type for public key parse: %q", keyType)
	}
}
