// Package bootstrap - 补充覆盖测试（Close）。
package bootstrap

import (
	"testing"

	"yvonne/internal/config"
)

// TestServer_Close_Nil Close nil 安全。
func TestServer_Close_Nil(t *testing.T) {
	srv := &Server{}
	srv.Close()
	t.Log("✅ Close nil safe")
}

// TestServer_Close_WithResources Close 带资源。
func TestServer_Close_WithResources(t *testing.T) {
	cfg := buildDevTestConfig()
	srv, err := BuildYvonne(cfg)
	if err != nil {
		t.Fatalf("BuildYvonne: %v", err)
	}
	srv.Close()
	t.Log("✅ Close with resources")
}

// buildDevTestConfig 构建 Dev 模式测试配置。
func buildDevTestConfig() *config.YvonneConfig {
	return &config.YvonneConfig{
		Mode: "dev",
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 0,
			TLS:      config.TLSConfig{Enabled: false},
		},
	}
}
