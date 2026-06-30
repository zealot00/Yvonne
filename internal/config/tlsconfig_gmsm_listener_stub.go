//go:build !gmsm

// Package config - 国密 TLS listener stub（非 gmsm 构建）。
package config

import (
	"errors"
	"net"
)

// NewGMTLSListener 非 gmsm 构建返回错误。
func NewGMTLSListener(gmCfg *GMTLSConfig, addr string) (net.Listener, error) {
	return nil, errors.New("config: gm_tls listener requires -tags gmsm")
}
