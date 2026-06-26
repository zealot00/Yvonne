package config

import (
	"strings"
	"testing"
)

// validConfig 返回一个通过所有校验的配置模板。
func validConfig() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 8400,
		},
		Storage: StorageConfig{
			Backend: "boltdb",
			Path:    "/tmp/yvonne.boltdb",
		},
		Seal: SealConfig{
			TotalShares: 5,
			Threshold:   3,
		},
		Crypto: CryptoConfig{
			DEKSize:    32,
			RSAKeyBits: 4096,
		},
		Auth: AuthConfig{
			AppRole: AppRoleConfig{
				RoleIDLength:   16,
				SecretIDLength: 32,
			},
		},
		Audit: AuditConfig{
			LogPath:                "/var/log/yvonne/audit.log",
			AuditKeyDerivationSalt: "aabbccdd",
			MaxEntryBytes:          4096,
		},
		Logging: LoggingConfig{
			RedactSecrets: true,
			Level:         "info",
		},
	}
}

// TestValidate_ValidConfig 合法配置通过。
func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid config should pass: %v", err)
	}
}

// TestValidate_BindPortInvalid 端口越界。
func TestValidate_BindPortInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.Server.BindPort = 0
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "bind_port") {
		t.Fatalf("port=0 should fail: %v", err)
	}

	cfg = validConfig()
	cfg.Server.BindPort = 70000
	err = Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "bind_port") {
		t.Fatalf("port=70000 should fail: %v", err)
	}
}

// TestValidate_BindAddrWildcardRequiresTLS 0.0.0.0 需要 TLS。
func TestValidate_BindAddrWildcardRequiresTLS(t *testing.T) {
	cfg := validConfig()
	cfg.Server.BindAddr = "0.0.0.0"
	cfg.Server.TLS.Enabled = false
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0") {
		t.Fatalf("0.0.0.0 without TLS should fail: %v", err)
	}

	// 启用 TLS 后应通过。
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "cert.pem"
	cfg.Server.TLS.KeyFile = "key.pem"
	cfg.Server.TLS.MinVersion = "TLS1.3"
	if err := Validate(cfg); err != nil {
		t.Fatalf("0.0.0.0 with TLS should pass: %v", err)
	}
}

// TestValidate_TLSMissingCert TLS 启用但缺证书。
func TestValidate_TLSMissingCert(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = ""
	cfg.Server.TLS.KeyFile = "key.pem"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "cert_file") {
		t.Fatalf("missing cert should fail: %v", err)
	}
}

// TestValidate_TLSMinVersion 无效版本。
func TestValidate_TLSMinVersion(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "cert.pem"
	cfg.Server.TLS.KeyFile = "key.pem"
	cfg.Server.TLS.MinVersion = "TLS1.0"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "min_version") {
		t.Fatalf("TLS1.0 should fail: %v", err)
	}
}

// TestValidate_mTLSRequireNoCA require 模式无 CA。
func TestValidate_mTLSRequireNoCA(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "cert.pem"
	cfg.Server.TLS.KeyFile = "key.pem"
	cfg.Server.TLS.MinVersion = "TLS1.3"
	cfg.Server.TLS.ClientAuth = "require"
	// 无 ClientCAFile
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "client_ca_file") {
		t.Fatalf("require without CA should fail: %v", err)
	}
}

// TestValidate_mTLSInvalidAuth 无效 client_auth。
func TestValidate_mTLSInvalidAuth(t *testing.T) {
	cfg := validConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "cert.pem"
	cfg.Server.TLS.KeyFile = "key.pem"
	cfg.Server.TLS.MinVersion = "TLS1.3"
	cfg.Server.TLS.ClientAuth = "invalid"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "client_auth") {
		t.Fatalf("invalid client_auth should fail: %v", err)
	}
}

// TestValidate_AdminBindAddrNotLoopback Admin 非 loopback。
func TestValidate_AdminBindAddrNotLoopback(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Admin.Enabled = true
	cfg.Server.Admin.BindAddr = "0.0.0.0"
	cfg.Server.Admin.BindPort = 8250
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("admin 0.0.0.0 should fail: %v", err)
	}
}

// TestValidate_StorageInvalidBackend 无效存储后端。
func TestValidate_StorageInvalidBackend(t *testing.T) {
	cfg := validConfig()
	cfg.Storage.Backend = "mysql"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "boltdb") {
		t.Fatalf("mysql backend should fail: %v", err)
	}
}

// TestValidate_StoragePostgresNoDSN Postgres 缺 DSN。
func TestValidate_StoragePostgresNoDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Storage.Backend = "postgres"
	cfg.Storage.DSN = ""
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dsn") {
		t.Fatalf("postgres without DSN should fail: %v", err)
	}
}

// TestValidate_SealThresholdExceedsShares threshold > shares。
func TestValidate_SealThresholdExceedsShares(t *testing.T) {
	cfg := validConfig()
	cfg.Seal.TotalShares = 3
	cfg.Seal.Threshold = 5
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("threshold>shares should fail: %v", err)
	}
}

// TestValidate_CryptoSuiteInvalid 无效 suite。
func TestValidate_CryptoSuiteInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.Crypto.Suite = "des"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "suite") {
		t.Fatalf("invalid suite should fail: %v", err)
	}
}

// TestValidate_CryptoDEKSizeMismatch gmsm 模式 DEKSize=32。
func TestValidate_CryptoDEKSizeMismatch(t *testing.T) {
	cfg := validConfig()
	cfg.Crypto.Suite = "gmsm"
	cfg.Crypto.DEKSize = 32 // 应该是 16
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "dek_size") {
		t.Fatalf("gmsm with DEKSize=32 should fail: %v", err)
	}
}

// TestValidate_CryptoGMSMCorrect gmsm 模式 DEKSize=16 通过。
func TestValidate_CryptoGMSMCorrect(t *testing.T) {
	cfg := validConfig()
	cfg.Crypto.Suite = "gmsm"
	cfg.Crypto.DEKSize = 16
	if err := Validate(cfg); err != nil {
		t.Fatalf("gmsm with DEKSize=16 should pass: %v", err)
	}
}

// TestValidate_CryptoDEKSizeZeroAuto DEKSize=0 自动推导。
func TestValidate_CryptoDEKSizeZeroAuto(t *testing.T) {
	cfg := validConfig()
	cfg.Crypto.DEKSize = 0 // 自动推导
	if err := Validate(cfg); err != nil {
		t.Fatalf("DEKSize=0 should pass (auto): %v", err)
	}
}

// TestValidate_JWTMissingIssuer JWT 启用但缺 issuer。
func TestValidate_JWTMissingIssuer(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.JWT.SigningMethod = "RS256"
	cfg.Auth.JWT.VerifyingKeyPath = "pub.pem"
	cfg.Auth.JWT.Issuer = ""
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("JWT without issuer should fail: %v", err)
	}
}

// TestValidate_JWTInvalidAlgo JWT 无效算法。
func TestValidate_JWTInvalidAlgo(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.JWT.SigningMethod = "PS256"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "signing_method") {
		t.Fatalf("PS256 should fail: %v", err)
	}
}

// TestValidate_JWTHMACMissingSecret HMAC 缺 secret。
func TestValidate_JWTHMACMissingSecret(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.JWT.SigningMethod = "HS256"
	cfg.Auth.JWT.Issuer = "test"
	cfg.Auth.JWT.Secret = ""
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("HMAC without secret should fail: %v", err)
	}
}

// TestValidate_AuditMissingPath 审计缺路径。
func TestValidate_AuditMissingPath(t *testing.T) {
	cfg := validConfig()
	cfg.Audit.LogPath = ""
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "log_path") {
		t.Fatalf("missing audit path should fail: %v", err)
	}
}

// TestValidate_LoggingRedactOff 脱敏关闭。
func TestValidate_LoggingRedactOff(t *testing.T) {
	cfg := validConfig()
	cfg.Logging.RedactSecrets = false
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "redact_secrets") {
		t.Fatalf("redact off should fail: %v", err)
	}
}

// TestValidate_LoggingInvalidLevel 无效日志级别。
func TestValidate_LoggingInvalidLevel(t *testing.T) {
	cfg := validConfig()
	cfg.Logging.Level = "trace"
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "level") {
		t.Fatalf("invalid level should fail: %v", err)
	}
}

// TestValidate_AppRoleTooShort AppRole 长度不足。
func TestValidate_AppRoleTooShort(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.AppRole.RoleIDLength = 8
	err := Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "role_id_length") {
		t.Fatalf("short role_id_length should fail: %v", err)
	}
}
