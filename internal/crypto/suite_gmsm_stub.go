//go:build !gmsm

// Package crypto - 国密套件 stub（默认编译时不可用）。
//
// 启用国密：go build -tags gmsm
// 依赖：github.com/tjfoc/gmsm 或 github.com/emmansun/gmsm
package crypto

import "errors"

// NewGMSMSuite 在默认编译时返回 error（国密依赖可插拔）。
func NewGMSMSuite() (CryptoSuite, error) {
	return nil, errors.New("crypto: GM (SM2/SM3/SM4) support not compiled in (rebuild with -tags gmsm)")
}
