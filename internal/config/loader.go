// Package config - 配置加载器：合并默认值、环境变量、配置文件。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Default 返回带安全默认值的 Config。
// 所有"安全关键"字段都给最严格的默认值，避免遗漏配置导致暴露面扩大。
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddr:     "127.0.0.1",
			BindPort:     8200,
			ReadTimeout:  Duration(10 * time.Second),
			WriteTimeout: Duration(10 * time.Second),
			MaxConns:     1024,
			TLS: TLSConfig{
				Enabled:    false, // 默认关，Validator 会在生产模式下强制要求开启
				MinVersion: "TLS1.3",
			},
			Admin: AdminServerConfig{
				Enabled:  true,
				BindAddr: "127.0.0.1", // 强制 loopback
				BindPort: 8250,
			},
		},
		Storage: StorageConfig{
			Backend: "boltdb",
			Path:    "data/yvonne.db",
		},
		Seal: SealConfig{
			TotalShares:     5,
			Threshold:       3,
			AutoResealAfter: Duration(30 * time.Minute),
		},
		Crypto: CryptoConfig{
			DEKSize:           32,
			RSAKeyBits:        4096,
			ECDSACurve:        "P-256",
			DEKRotationPeriod: 0, // 默认禁用，按需开启
		},
		Auth: AuthConfig{
			AppRole: AppRoleConfig{
				RoleIDLength:   16,
				SecretIDLength: 32,
				SecretIDTTL:    Duration(24 * time.Hour),
				BindSecretID:   true,
			},
			JWT: JWTConfig{
				SigningMethod: "RS256",
				TokenTTL:      Duration(15 * time.Minute),
				Issuer:        "yvonne-kms",
			},
		},
		Audit: AuditConfig{
			LogPath:                "logs/audit.log",
			AuditKeyDerivationSalt: "", // 必须由部署时填入，Validator 强制非空
			Fsync:                  true,
			MaxEntryBytes:          64 * 1024,
		},
		Memory: MemoryConfig{
			EnableMLock: true,
			UseMmap:     false,
			GCPolicy:    "avoid_gc_for_secure_buffer",
		},
		Logging: LoggingConfig{
			Level:         "info",
			Format:        "json",
			Output:        "stdout",
			RedactSecrets: true,
		},
	}
}

// Load 从配置文件加载并合并环境变量覆盖。
// configPath 为空时仅使用默认值 + 环境变量。
func Load(configPath string) (*Config, error) {
	cfg := Default()

	if configPath != "" {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnvOverrides 让关键安全参数可通过环境变量覆盖（12-factor）。
// 仅暴露少数关键字段，避免 env 配置爆炸。
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("YVONNE_SERVER_BIND_ADDR"); v != "" {
		cfg.Server.BindAddr = v
	}
	if v := os.Getenv("YVONNE_SERVER_BIND_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.BindPort = p
		}
	}
	if v := os.Getenv("YVONNE_STORAGE_BACKEND"); v != "" {
		cfg.Storage.Backend = v
	}
	if v := os.Getenv("YVONNE_STORAGE_DSN"); v != "" {
		cfg.Storage.DSN = v
	}
	if v := os.Getenv("YVONNE_STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("YVONNE_ADMIN_BIND_ADDR"); v != "" {
		cfg.Server.Admin.BindAddr = v
	}
	if v := os.Getenv("YVONNE_ADMIN_BIND_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Admin.BindPort = p
		}
	}
	if v := os.Getenv("YVONNE_AUDIT_SALT"); v != "" {
		cfg.Audit.AuditKeyDerivationSalt = v
	}
}
