//go:build !gmsm

// Package config - 国密 TLS stub（非 gmsm 构建）。
//
// 非 gmsm 构建下国密 TLS 不可用，返回明确错误。
package config

import (
	"errors"
)

// ErrGMTLSRequiresGmsm 表示国密 TLS 需要 gmsm 构建标签。
var ErrGMTLSRequiresGmsm = errors.New("config: gm_tls requires -tags gmsm")

// GMTLSConfig 是国密 TLS 配置的封装（非 gmsm 构建 stub）。
type GMTLSConfig struct{}

// BuildGMTLSConfig 非 gmsm 构建返回错误。
func BuildGMTLSConfig(cfg TLSConfig) (*GMTLSConfig, error) {
	return nil, ErrGMTLSRequiresGmsm
}
