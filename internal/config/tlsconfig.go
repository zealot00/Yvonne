// Package config - TLS 配置构造。
//
// 从 TLSConfig 构造 *tls.Config，支持 mTLS 客户端证书认证。
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// BuildTLSConfig 从 TLSConfig 构造 *tls.Config。
//
// 支持 mTLS：
//   - client_auth: "require"  → RequireAndVerifyClientCert（强制客户端证书）
//   - client_auth: "optional" → VerifyClientCertIfGiven（可选客户端证书）
//   - client_auth: "none"     → NoClientCert（不校验，默认）
//
// 服务端证书通过 cert_file/key_file 加载（由 http.Server.ListenAndServeTLS 使用）。
// ClientCA 通过 client_ca_file 加载为证书池。
func BuildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{}

	// MinVersion。
	switch cfg.MinVersion {
	case "TLS1.3":
		tlsCfg.MinVersion = tls.VersionTLS13
	case "TLS1.2", "":
		tlsCfg.MinVersion = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("config: unsupported tls.min_version %q", cfg.MinVersion)
	}

	// ClientAuth + ClientCA。
	switch cfg.ClientAuth {
	case "require":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "optional":
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	case "", "none":
		tlsCfg.ClientAuth = tls.NoClientCert
	default:
		return nil, fmt.Errorf("config: unsupported tls.client_auth %q", cfg.ClientAuth)
	}

	// 加载 ClientCA（require/optional 时必填）。
	if tlsCfg.ClientAuth != tls.NoClientCert {
		if cfg.ClientCAFile == "" {
			return nil, errors.New("config: tls.client_auth require/optional needs client_ca_file")
		}
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("config: read client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("config: failed to parse client_ca_file (invalid PEM)")
		}
		tlsCfg.ClientCAs = pool
	}

	return tlsCfg, nil
}
