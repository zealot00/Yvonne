//go:build !gmsm

// SM2 OCSP 桩实现（无 gmsm 标签时的占位）。
package crypto

import (
	"errors"
	"time"
)

// CreateSM2OCSPResponse 在非 gmsm 构建下不可用。
//
// 编译时使用 -tags gmsm 启用 SM2 OCSP 支持。
func CreateSM2OCSPResponse(reqDER, sm2CertDER []byte, sm2Signer *SecureSigner, status int, revokedAt time.Time, reason int, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	return nil, errors.New("crypto: SM2 OCSP requires -tags gmsm build flag")
}
