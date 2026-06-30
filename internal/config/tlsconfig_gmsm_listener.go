//go:build gmsm

// Package config - 国密 TLS listener 辅助（gmsm 构建标签）。
//
// 提供国密 TLS 的 net.Listener 创建函数，
// 供 main.go 在 gmsm 构建模式下启动国密 HTTPS 服务。
package config

import (
	"fmt"
	"net"

	"github.com/tjfoc/gmsm/gmtls"
)

// NewGMTLSListener 创建国密 TLS net.Listener。
// gmCfg: BuildGMTLSConfig 返回的配置。
// addr: 监听地址（如 "127.0.0.1:8200"）。
func NewGMTLSListener(gmCfg *GMTLSConfig, addr string) (net.Listener, error) {
	ln, err := gmtls.Listen("tcp", addr, gmCfg.Config)
	if err != nil {
		return nil, fmt.Errorf("config: gmtls listen on %s: %w", addr, err)
	}
	return ln, nil
}
