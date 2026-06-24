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
	if cfg.Crypto.DEKSize != 32 {
		errs = append(errs, "crypto.dek_size must be 32 (AES-256)")
	}
	if cfg.Crypto.RSAKeyBits != 4096 {
		errs = append(errs, "crypto.rsa_key_bits must be 4096")
	}
	if cfg.Crypto.ECDSACurve != "P-256" && cfg.Crypto.ECDSACurve != "P-384" {
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
	case "RS256", "ES256":
	default:
		errs = append(errs, "auth.jwt.signing_method must be RS256 or ES256")
	}
	if cfg.Auth.JWT.TokenTTL <= 0 {
		errs = append(errs, "auth.jwt.token_ttl must be > 0")
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

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
