// Package config - Validator：强制安全校验，未通过则进程拒绝启动。
package config

import (
	"fmt"
	"strings"
)

// Validate 强制校验配置；任一红线被触碰即返回错误，进程拒绝启动。
func Validate(cfg *Config) error {
	var errs []string

	// --- Server ---
	if cfg.Server.BindPort <= 0 || cfg.Server.BindPort > 65535 {
		errs = append(errs, "server.bind_port must be in 1..65535")
	}
	if cfg.Server.BindAddr == "0.0.0.0" || cfg.Server.BindAddr == "::" {
		// 允许显式声明，但要求同时开启 TLS
		if !cfg.Server.TLS.Enabled {
			errs = append(errs, "server.bind_addr=0.0.0.0 requires server.tls.enabled=true")
		}
	}
	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.MinVersion != "TLS1.2" && cfg.Server.TLS.MinVersion != "TLS1.3" {
			errs = append(errs, "server.tls.min_version must be TLS1.2 or TLS1.3")
		}
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			errs = append(errs, "server.tls.enabled=true requires cert_file and key_file")
		}
		// mTLS 校验
		switch cfg.Server.TLS.ClientAuth {
		case "require":
			if cfg.Server.TLS.ClientCAFile == "" {
				errs = append(errs, "server.tls.client_auth=require requires client_ca_file")
			}
		case "optional":
			if cfg.Server.TLS.ClientCAFile == "" {
				errs = append(errs, "server.tls.client_auth=optional requires client_ca_file")
			}
		case "", "none":
			// 默认 none，无需 ClientCA
		default:
			errs = append(errs, "server.tls.client_auth must be require, optional, or none")
		}
	}

	// --- Admin ---
	if cfg.Server.Admin.Enabled {
		if cfg.Server.Admin.BindAddr != "127.0.0.1" && cfg.Server.Admin.BindAddr != "localhost" {
			errs = append(errs, "admin.bind_addr must be 127.0.0.1 (loopback only); expose via reverse proxy + mTLS in prod")
		}
		if cfg.Server.Admin.BindPort <= 0 || cfg.Server.Admin.BindPort > 65535 {
			errs = append(errs, "admin.bind_port must be in 1..65535")
		}
	}

	// --- Storage ---
	switch cfg.Storage.Backend {
	case "boltdb":
		if cfg.Storage.Path == "" {
			errs = append(errs, "storage.path required for boltdb backend")
		}
	case "postgres":
		if cfg.Storage.DSN == "" {
			errs = append(errs, "storage.dsn required for postgres backend")
		}
	default:
		errs = append(errs, fmt.Sprintf("storage.backend must be 'boltdb' or 'postgres', got %q", cfg.Storage.Backend))
	}

	// --- Seal ---
	if cfg.Seal.TotalShares <= 0 {
		errs = append(errs, "seal.total_shares must be > 0")
	}
	if cfg.Seal.Threshold <= 0 || cfg.Seal.Threshold > cfg.Seal.TotalShares {
		errs = append(errs, "seal.threshold must be in 1..total_shares")
	}

	// --- Crypto ---
	// DEKSize 按 suite 动态校验（standard=32 AES-256, gmsm=16 SM4-128）。
	expectedDEKSize := 32 // 默认 standard
	if cfg.Crypto.Suite == "gmsm" {
		expectedDEKSize = 16
	}
	if cfg.Crypto.DEKSize != 0 && cfg.Crypto.DEKSize != expectedDEKSize {
		errs = append(errs, fmt.Sprintf("crypto.dek_size must be %d for suite %q (or leave unset for auto)", expectedDEKSize, cfg.Crypto.Suite))
	}
	if cfg.Crypto.RSAKeyBits != 0 && cfg.Crypto.RSAKeyBits != 4096 {
		errs = append(errs, "crypto.rsa_key_bits must be 4096")
	}
	if cfg.Crypto.ECDSACurve != "" && cfg.Crypto.ECDSACurve != "P-256" && cfg.Crypto.ECDSACurve != "P-384" {
		errs = append(errs, "crypto.ecdsa_curve must be P-256 or P-384")
	}

	// --- Auth ---
	if cfg.Auth.AppRole.RoleIDLength < 16 {
		errs = append(errs, "auth.approle.role_id_length must be >= 16")
	}
	if cfg.Auth.AppRole.SecretIDLength < 32 {
		errs = append(errs, "auth.approle.secret_id_length must be >= 32")
	}
	switch cfg.Auth.JWT.SigningMethod {
	case "RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"HS256", "HS384", "HS512",
		"": // JWT 未启用时允许空
	default:
		errs = append(errs, "auth.jwt.signing_method must be RS256/384/512, ES256/384/512, or HS256/384/512")
	}
	// JWT 验签密钥校验：非对称必须有公钥文件，HMAC 必须有 secret。
	if cfg.Auth.JWT.SigningMethod != "" {
		if cfg.Auth.JWT.Issuer == "" {
			errs = append(errs, "auth.jwt.issuer is required when jwt is enabled")
		}
		switch cfg.Auth.JWT.SigningMethod[:2] {
		case "RS", "ES":
			if cfg.Auth.JWT.VerifyingKeyPath == "" {
				errs = append(errs, "auth.jwt.verifying_key_path is required for RSA/ECDSA")
			}
		case "HS":
			if cfg.Auth.JWT.Secret == "" {
				errs = append(errs, "auth.jwt.secret is required for HMAC")
			}
		}
	}

	// --- Audit ---
	if cfg.Audit.LogPath == "" {
		errs = append(errs, "audit.log_path required")
	}
	if cfg.Audit.AuditKeyDerivationSalt == "" {
		errs = append(errs, "audit.audit_key_derivation_salt required (hex HKDF salt)")
	}
	if cfg.Audit.MaxEntryBytes <= 0 || cfg.Audit.MaxEntryBytes > 1<<20 {
		errs = append(errs, "audit.max_entry_bytes must be in 1..1MiB")
	}

	// --- Logging ---
	if !cfg.Logging.RedactSecrets {
		errs = append(errs, "logging.redact_secrets must be true (security hard requirement)")
	}
	switch cfg.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "logging.level must be one of debug|info|warn|error")
	}

	// --- Crypto（v1.1 新增）---
	switch cfg.Crypto.Suite {
	case "", "standard", "gmsm":
		// 合法值
	default:
		errs = append(errs, "crypto.suite must be standard or gmsm")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
