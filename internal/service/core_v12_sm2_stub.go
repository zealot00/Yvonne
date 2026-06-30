//go:build !gmsm

// Package service - SM2 签名/验签 stub（非 gmsm 构建）。
//
// 非 gmsm 构建下 SM2 不可用，返回明确错误。
package service

import "errors"

// errSM2RequiresGmsmBuild 表示 SM2 需要 gmsm 构建标签。
var errSM2RequiresGmsmBuild = errors.New("service: sm2 requires -tags gmsm")

// signSM2 非 gmsm 构建返回错误。
func signSM2(privKeyPEM []byte, data []byte) ([]byte, error) {
	return nil, errSM2RequiresGmsmBuild
}

// verifySM2Key 非 gmsm 构建返回错误。
func verifySM2Key(pubKeyPEM []byte, data, signature []byte) (bool, error) {
	return false, errSM2RequiresGmsmBuild
}
