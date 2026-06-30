// Package config - Duration + Loader + YvonneConfig 辅助函数单元测试。
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// === Duration 测试 ===

func TestDuration_UnmarshalString(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"30s"`), &d); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if d.Std() != 30*time.Second {
		t.Fatalf("got %v, want 30s", d.Std())
	}
	t.Log("✅ Duration unmarshal string \"30s\"")
}

func TestDuration_UnmarshalNumber(t *testing.T) {
	var d Duration
	// 5 秒 = 5000000000 纳秒
	if err := json.Unmarshal([]byte("5000000000"), &d); err != nil {
		t.Fatalf("unmarshal number: %v", err)
	}
	if d.Std() != 5*time.Second {
		t.Fatalf("got %v, want 5s", d.Std())
	}
	t.Log("✅ Duration unmarshal number 5000000000")
}

func TestDuration_UnmarshalInvalid(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"invalid"`), &d); err == nil {
		t.Fatal("should fail for invalid string")
	}
	t.Log("✅ Duration unmarshal invalid → error")
}

func TestDuration_Marshal(t *testing.T) {
	d := Duration(30 * time.Second)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"30s"` {
		t.Fatalf("got %s, want \"30s\"", string(b))
	}
	t.Log("✅ Duration marshal → \"30s\"")
}

func TestDuration_Std(t *testing.T) {
	d := Duration(2 * time.Hour)
	if d.Std() != 2*time.Hour {
		t.Fatalf("got %v, want 2h", d.Std())
	}
	t.Log("✅ Duration.Std()")
}

// === Loader 测试 ===

func TestLoad_Default(t *testing.T) {
	// Default() 不触发 Validate，只返回默认配置。
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() should not return nil")
	}
	if cfg.Server.BindAddr != "127.0.0.1" {
		t.Fatalf("addr = %s, want 127.0.0.1", cfg.Server.BindAddr)
	}
	t.Log("✅ Default() returns secure defaults")
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("should fail for nonexistent file")
	}
	t.Logf("✅ Load file not found: %v", err)
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// 用完整有效配置（通过 Validate）。
	os.WriteFile(path, []byte(`{
		"server": {"bind_addr": "127.0.0.1", "bind_port": 9999, "tls": {"enabled": false}},
		"storage": {"backend": "boltdb", "path": "`+filepath.Join(dir, "test.db")+`"},
		"seal": {"type": "auto"},
		"auth": {"jwt": {"signing_method": "HS256", "secret": "test-secret-32-bytes-long-xxxxx", "issuer": "test"}},
		"audit": {"audit_key_derivation_salt": "aabbccdd"}
	}`), 0o600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.BindPort != 9999 {
		t.Fatalf("port = %d, want 9999", cfg.Server.BindPort)
	}
	t.Log("✅ Load valid file")
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{invalid`), 0o600)

	_, err := Load(path)
	if err == nil {
		t.Fatal("should fail for invalid JSON")
	}
	t.Logf("✅ Load invalid JSON: %v", err)
}

func TestLoad_EnvOverrides(t *testing.T) {
	os.Setenv("YVONNE_SERVER_BIND_ADDR", "1.2.3.4")
	os.Setenv("YVONNE_SERVER_BIND_PORT", "5555")
	os.Setenv("YVONNE_STORAGE_BACKEND", "boltdb")
	os.Setenv("YVONNE_STORAGE_PATH", "/tmp/test-env.db")
	defer func() {
		os.Unsetenv("YVONNE_SERVER_BIND_ADDR")
		os.Unsetenv("YVONNE_SERVER_BIND_PORT")
		os.Unsetenv("YVONNE_STORAGE_BACKEND")
		os.Unsetenv("YVONNE_STORAGE_PATH")
	}()

	cfg := Default()
	applyEnvOverrides(cfg)
	if cfg.Server.BindAddr != "1.2.3.4" {
		t.Fatalf("addr = %s, want 1.2.3.4", cfg.Server.BindAddr)
	}
	if cfg.Server.BindPort != 5555 {
		t.Fatalf("port = %d, want 5555", cfg.Server.BindPort)
	}
	if cfg.Storage.Backend != "boltdb" {
		t.Fatalf("backend = %s, want boltdb", cfg.Storage.Backend)
	}
	t.Log("✅ applyEnvOverrides")
}

func TestLoad_EnvInvalidPort(t *testing.T) {
	os.Setenv("YVONNE_SERVER_BIND_PORT", "not-a-number")
	defer os.Unsetenv("YVONNE_SERVER_BIND_PORT")

	cfg := Default()
	applyEnvOverrides(cfg)
	t.Logf("✅ applyEnvOverrides invalid port ignored (port=%d)", cfg.Server.BindPort)
}

// === YvonneConfig 辅助函数测试 ===

func TestPrintSummary_Dev(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "dev",
		Storage: StorageModeConf{Type: "memory"},
		Unseal:  UnsealModeConf{Type: "auto"},
		Server:  ServerConfig{BindAddr: "127.0.0.1", BindPort: 8200},
	}
	summary := cfg.PrintSummary()
	if summary == "" {
		t.Fatal("summary should not be empty")
	}
	t.Logf("✅ PrintSummary dev: %s", summary)
}

func TestPrintSummary_ClusterWithDSN(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://postgres:secret@host/db"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 2, TotalShares: 3},
		Server:  ServerConfig{BindAddr: "0.0.0.0", BindPort: 8400},
	}
	summary := cfg.PrintSummary()
	// DSN 密码应被脱敏。
	if contains(summary, "secret") {
		t.Fatal("DSN password should be redacted")
	}
	t.Logf("✅ PrintSummary cluster: %s", summary)
}

func TestPrintSummary_Shamir(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 3, TotalShares: 5},
		Server:  ServerConfig{BindAddr: "127.0.0.1", BindPort: 8400},
	}
	summary := cfg.PrintSummary()
	if !contains(summary, "3/5") {
		t.Fatal("should show shamir threshold/total")
	}
	t.Logf("✅ PrintSummary shamir: %s", summary)
}

func TestRedactDSN_URL(t *testing.T) {
	result := redactDSN("postgresql://postgres:secret@172.20.0.16:5432/yvonne")
	if contains(result, "secret") {
		t.Fatal("password should be redacted")
	}
	if !contains(result, "xxxxx") {
		t.Fatal("should contain xxxxx")
	}
	t.Logf("✅ redactDSN URL: %s", result)
}

func TestRedactDSN_KeyValue(t *testing.T) {
	result := redactDSN("host=localhost password=mypass dbname=test")
	if contains(result, "mypass") {
		t.Fatal("password should be redacted")
	}
	t.Logf("✅ redactDSN key=value: %s", result)
}

func TestRedactDSN_NoPassword(t *testing.T) {
	result := redactDSN("host=localhost dbname=test")
	if result != "host=localhost dbname=test" {
		t.Fatalf("should not modify: %s", result)
	}
	t.Log("✅ redactDSN no password → unchanged")
}

func TestRegexpReplacePassword(t *testing.T) {
	result := regexpReplacePassword("password=secret dbname=test")
	if contains(result, "secret") {
		t.Fatal("password should be replaced")
	}
	t.Logf("✅ regexpReplacePassword: %s", result)
}

func TestRegexpReplacePassword_NoMatch(t *testing.T) {
	result := regexpReplacePassword("host=localhost")
	if result != "host=localhost" {
		t.Fatalf("should not modify: %s", result)
	}
	t.Log("✅ regexpReplacePassword no match → unchanged")
}

// === validateClusterConfig 测试 ===

func TestValidateClusterConfig_Valid(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://u:p@h/db"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 2, TotalShares: 3},
		Auth: AuthModeConf{
			AppRoles: []AppRoleEntry{
				{RoleID: "admin", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}},
			},
		},
		Audit:   AuditModeConf{Dir: "/var/log/yvonne"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	if err := ValidateYvonneConfig(cfg); err != nil {
		t.Fatalf("valid cluster config: %v", err)
	}
	t.Log("✅ validateClusterConfig valid")
}

func TestValidateClusterConfig_MemoryStorage(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "memory"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 2, TotalShares: 3},
		Auth: AuthModeConf{
			AppRoles: []AppRoleEntry{
				{RoleID: "admin", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}},
			},
		},
		Audit:   AuditModeConf{Dir: "/var/log/yvonne"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	err := ValidateYvonneConfig(cfg)
	if err == nil {
		t.Fatal("should reject memory storage in cluster mode")
	}
	t.Logf("✅ validateClusterConfig memory storage rejected: %v", err)
}

func TestValidateClusterConfig_AutoUnseal(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://u:p@h/db"},
		Unseal:  UnsealModeConf{Type: "auto"},
		Auth: AuthModeConf{
			AppRoles: []AppRoleEntry{
				{RoleID: "admin", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}},
			},
		},
		Audit:   AuditModeConf{Dir: "/var/log/yvonne"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	err := ValidateYvonneConfig(cfg)
	if err == nil {
		t.Fatal("should reject auto unseal in cluster mode")
	}
	t.Logf("✅ validateClusterConfig auto unseal rejected: %v", err)
}

func TestValidateClusterConfig_InvalidShamir(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://u:p@h/db"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 1, TotalShares: 3},
		Auth: AuthModeConf{
			AppRoles: []AppRoleEntry{
				{RoleID: "admin", Token: "t", AllowedKeys: []string{"*"}, AllowedActions: []string{"*"}},
			},
		},
		Audit:   AuditModeConf{Dir: "/var/log/yvonne"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	err := ValidateYvonneConfig(cfg)
	if err == nil {
		t.Fatal("should reject threshold < 2")
	}
	t.Logf("✅ validateClusterConfig invalid shamir rejected: %v", err)
}

func TestValidateClusterConfig_NoAppRoles(t *testing.T) {
	cfg := &YvonneConfig{
		Mode:    "cluster",
		Storage: StorageModeConf{Type: "postgres", DSN: "postgresql://u:p@h/db"},
		Unseal:  UnsealModeConf{Type: "shamir", Threshold: 2, TotalShares: 3},
		Audit:   AuditModeConf{Dir: "/var/log/yvonne"},
		Logging: LoggingConfig{RedactSecrets: true},
	}
	err := ValidateYvonneConfig(cfg)
	if err == nil {
		t.Fatal("should reject no app_roles")
	}
	t.Logf("✅ validateClusterConfig no app_roles rejected: %v", err)
}

func TestValidateYvonneConfig_InvalidMode(t *testing.T) {
	cfg := &YvonneConfig{Mode: "invalid"}
	err := ValidateYvonneConfig(cfg)
	if err == nil {
		t.Fatal("should reject invalid mode")
	}
	t.Logf("✅ validateYvonneConfig invalid mode: %v", err)
}

func TestValidateYvonneConfig_Dev(t *testing.T) {
	cfg := &YvonneConfig{Mode: "dev"}
	if err := ValidateYvonneConfig(cfg); err != nil {
		t.Fatalf("dev mode should be valid: %v", err)
	}
	t.Log("✅ validateYvonneConfig dev mode")
}

func TestApplyYvonneEnvOverrides(t *testing.T) {
	os.Setenv("YVONNE_MODE", "cluster")
	defer os.Unsetenv("YVONNE_MODE")

	cfg := &YvonneConfig{Mode: "dev"}
	applyYvonneEnvOverrides(cfg)
	if cfg.Mode != "cluster" {
		t.Fatalf("mode = %s, want cluster", cfg.Mode)
	}
	t.Log("✅ applyYvonneEnvOverrides YVONNE_MODE")
}

// 辅助函数。
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
