// Package config - 审计时区自动填充测试（v1.4.1）。
package config

import (
	"testing"
)

// TestApplyAuditTimezoneDefaults_StrictAutoFill 国密模式自动开 Asia/Shanghai。
func TestApplyAuditTimezoneDefaults_StrictAutoFill(t *testing.T) {
	cfg := &YvonneConfig{
		Crypto: CryptoConfig{Strict: true},
		Audit:  AuditModeConf{},
	}
	applyAuditTimezoneDefaults(cfg)
	if !cfg.Audit.TimezoneEnabled {
		t.Fatalf("strict mode should auto-enable timezone")
	}
	if cfg.Audit.Timezone != "Asia/Shanghai" {
		t.Fatalf("strict mode timezone=%q, want Asia/Shanghai", cfg.Audit.Timezone)
	}
	t.Logf("✅ strict mode → timezone=%s enabled=%v", cfg.Audit.Timezone, cfg.Audit.TimezoneEnabled)
}

// TestApplyAuditTimezoneDefaults_NonStrictDefaultClosed 非国密默认关闭。
func TestApplyAuditTimezoneDefaults_NonStrictDefaultClosed(t *testing.T) {
	cfg := &YvonneConfig{
		Crypto: CryptoConfig{Strict: false},
		Audit:  AuditModeConf{},
	}
	applyAuditTimezoneDefaults(cfg)
	if cfg.Audit.TimezoneEnabled {
		t.Fatalf("non-strict should NOT auto-enable (back-compat)")
	}
	if cfg.Audit.Timezone != "" {
		t.Fatalf("non-strict timezone=%q, want empty (UTC fallback)", cfg.Audit.Timezone)
	}
	t.Logf("✅ non-strict → timezone='%s' enabled=%v (UTC fallback)", cfg.Audit.Timezone, cfg.Audit.TimezoneEnabled)
}

// TestApplyAuditTimezoneDefaults_ExplicitTZ 即使非国密也以用户填写的时区为准。
func TestApplyAuditTimezoneDefaults_ExplicitTZ(t *testing.T) {
	cfg := &YvonneConfig{
		Crypto: CryptoConfig{Strict: false},
		Audit:  AuditModeConf{Timezone: "America/New_York"},
	}
	applyAuditTimezoneDefaults(cfg)
	if !cfg.Audit.TimezoneEnabled {
		t.Fatalf("explicit tz should force enabled=true")
	}
	if cfg.Audit.Timezone != "America/New_York" {
		t.Fatalf("explicit tz dropped: got %q", cfg.Audit.Timezone)
	}
	t.Logf("✅ explicit tz respected: %s", cfg.Audit.Timezone)
}

// TestValidateClusterConfig_BadTimezone 验证非法时区名被拒绝。
func TestValidateClusterConfig_BadTimezone(t *testing.T) {
	cfg := &YvonneConfig{
		Mode: ModeCluster,
		Crypto: CryptoConfig{
			Strict: true,
		},
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://x"},
		Unseal:  UnsealModeConf{Type: "local_pki", PKIKeyPath: "/tmp/k"},
		Auth:    AuthModeConf{AppRoles: []AppRoleEntry{{RoleID: "r", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}}}},
		Audit:   AuditModeConf{Dir: "/tmp/a"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	applyAuditTimezoneDefaults(cfg) // 自动填 Asia/Shanghai

	// 用合法名替换。
	cfg.Audit.Timezone = "Mars/Olympus_Mons"
	cfg.Audit.TimezoneEnabled = true

	err := validateClusterConfig(cfg)
	if err == nil {
		t.Fatalf("expected validation error for bad IANA TZ, got nil")
	}
	t.Logf("✅ validator rejected bad TZ: %v", err)
}

// TestValidateClusterConfig_GoodTimezone 合法 IANA 名通过校验。
func TestValidateClusterConfig_GoodTimezone(t *testing.T) {
	for _, tz := range []string{"UTC", "Asia/Shanghai", "America/New_York", "Europe/London"} {
		cfg := &YvonneConfig{
			Mode:    ModeCluster,
			Crypto:  CryptoConfig{Strict: true},
			Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://x"},
			Unseal:  UnsealModeConf{Type: "local_pki", PKIKeyPath: "/tmp/k"},
			Auth:    AuthModeConf{AppRoles: []AppRoleEntry{{RoleID: "r", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}}}},
			Audit:   AuditModeConf{Dir: "/tmp/a", Timezone: tz, TimezoneEnabled: true},
			Logging: LoggingConfig{RedactSecrets: true},
		}
		if err := validateClusterConfig(cfg); err != nil {
			t.Fatalf("TZ %q should pass: %v", tz, err)
		}
	}
}
