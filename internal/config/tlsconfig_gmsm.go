//go:build gmsm

// Package config - RFC 8998 国密 TLS 配置（gmsm 构建标签）。
//
// 使用 tjfoc/gmsm/gmtls 实现 TLS 1.3 + SM2/SM3/SM4。
// 国密 TLS 需要双证书（签名 + 加密），与标准 TLS 的单证书不同。
//
// 编译：go build -tags gmsm
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/tjfoc/gmsm/gmtls"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// GMTLSConfig 是国密 TLS 配置的封装。
type GMTLSConfig struct {
	Config *gmtls.Config
}

// BuildGMTLSConfig 从 TLSConfig 构造国密 TLS 配置。
//
// 要求 cfg.GMEnabled=true 且提供 SM2 签名 + 加密双证书。
func BuildGMTLSConfig(cfg TLSConfig) (*GMTLSConfig, error) {
	if !cfg.GMEnabled {
		return nil, errors.New("config: gm_tls not enabled")
	}

	// 校验双证书文件路径。
	if cfg.GMSignCertFile == "" || cfg.GMSignKeyFile == "" {
		return nil, errors.New("config: gm_sign_cert_file and gm_sign_key_file are required for gm_tls")
	}
	if cfg.GMEncCertFile == "" || cfg.GMEncKeyFile == "" {
		return nil, errors.New("config: gm_enc_cert_file and gm_enc_key_file are required for gm_tls")
	}

	// 加载 SM2 签名证书 + 私钥。
	signCert, err := gmtls.LoadX509KeyPair(cfg.GMSignCertFile, cfg.GMSignKeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: load SM2 sign cert: %w", err)
	}

	// 加载 SM2 加密证书 + 私钥。
	encCert, err := gmtls.LoadX509KeyPair(cfg.GMEncCertFile, cfg.GMEncKeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: load SM2 enc cert: %w", err)
	}

	// 构造 gmtls.Config。
	// tjfoc/gmsm 的 gmtls 基于 GMSSL（GB/T 38636），非 RFC 8998 的 TLS 1.3。
	// 最高支持 TLS 1.2 + GMSSL 国密套件。
	gmCfg := &gmtls.Config{
		GMSupport:    gmtls.NewGMSupport(),
		Certificates: []gmtls.Certificate{signCert, encCert},
		MinVersion:   gmtls.VersionTLS12,
		MaxVersion:   gmtls.VersionTLS12,
	}

	// mTLS 客户端证书校验（可选）。
	switch cfg.ClientAuth {
	case "require":
		gmCfg.ClientAuth = gmtls.RequireAndVerifyClientCert
	case "optional":
		gmCfg.ClientAuth = gmtls.VerifyClientCertIfGiven
	case "", "none":
		gmCfg.ClientAuth = gmtls.NoClientCert
	default:
		return nil, fmt.Errorf("config: unsupported tls.client_auth %q", cfg.ClientAuth)
	}

	// 加载 ClientCA（require/optional 时必填）。
	if gmCfg.ClientAuth != gmtls.NoClientCert {
		if cfg.ClientCAFile == "" {
			return nil, errors.New("config: tls.client_auth require/optional needs client_ca_file")
		}
		caPEM, err := os.ReadFile(cfg.ClientCAFile) // #nosec G304 -- path 由管理员配置
		if err != nil {
			return nil, fmt.Errorf("config: read client_ca_file: %w", err)
		}
		pool := gmx509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("config: failed to parse client_ca_file (invalid PEM)")
		}
		gmCfg.ClientCAs = pool
	}

	return &GMTLSConfig{Config: gmCfg}, nil
}
