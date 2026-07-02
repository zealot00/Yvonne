//go:build gmsm

package crypto

import (
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
)

// ParseSM2PublicKey 从 PEM 解析 SM2 公钥。
func ParseSM2PublicKey(pemBytes []byte) (interface{}, error) {
	pub, err := parseSMPublicKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ParseSM2CACertPEM 解析 SM2 CA 证书 PEM（返回标准库兼容格式，失败时返回 error）。
func ParseSM2CACertPEM(pemBytes []byte) (interface{}, error) {
	_ = sm2.PublicKey{} // 确保 import
	return parseSM2CertPEM(pemBytes)
}

// parseSM2CACert 内部：解析 SM2 证书 PEM 返回 gmx509.Certificate。
func parseSM2CACert(pemBytes []byte) (interface{}, error) {
	cert, err := parseSM2CertPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 CA cert: %w", err)
	}
	return cert, nil
}
