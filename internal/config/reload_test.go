// Package config - ReloadableConfig 测试。
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTestConfig 写入测试配置文件。
func writeTestConfig(t *testing.T, path string, retentionDays int) {
	t.Helper()
	content := `{
  "mode": "dev",
  "server": {
    "bind_addr": "127.0.0.1",
    "bind_port": 8200,
    "tls": {"enabled": false}
  },
  "storage": {"type": "memory"},
  "unseal": {"type": "auto"},
  "audit": {
    "dir": "/tmp/test-audit",
    "retention_days": ` + intToStr(retentionDays) + `
  },
  "logging": {"level": "info"},
  "observability": {
    "tracing": {"enabled": false},
    "alerting": {"enabled": false}
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// intToStr 简单整数转字符串（避免 import strconv）。
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

// TestReloadableConfig_Load 初始加载。
func TestReloadableConfig_Load(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, 180)

	rc, err := NewReloadableConfig(path)
	if err != nil {
		t.Fatalf("NewReloadableConfig: %v", err)
	}

	cfg := rc.Get()
	if cfg.Audit.RetentionDays != 180 {
		t.Fatalf("retention_days = %d, want 180", cfg.Audit.RetentionDays)
	}
	t.Logf("✅ Initial load: retention_days=%d", cfg.Audit.RetentionDays)
}

// TestReloadableConfig_Reload 热更新。
func TestReloadableConfig_Reload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, 180)

	rc, err := NewReloadableConfig(path)
	if err != nil {
		t.Fatalf("NewReloadableConfig: %v", err)
	}

	// 修改配置文件。
	writeTestConfig(t, path, 90)

	// 重载。
	if err := rc.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	cfg := rc.Get()
	if cfg.Audit.RetentionDays != 90 {
		t.Fatalf("after reload, retention_days = %d, want 90", cfg.Audit.RetentionDays)
	}
	t.Logf("✅ Reload: retention_days 180 → 90")
}

// TestReloadableConfig_ColdFieldsPreserved 冷更新字段保留旧值。
func TestReloadableConfig_ColdFieldsPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, 180)

	rc, err := NewReloadableConfig(path)
	if err != nil {
		t.Fatalf("NewReloadableConfig: %v", err)
	}

	oldPort := rc.Get().Server.BindPort

	// 修改配置文件（改端口 = 冷更新字段）。
	content := `{
  "mode": "dev",
  "server": {"bind_addr": "127.0.0.1", "bind_port": 9999, "tls": {"enabled": false}},
  "storage": {"type": "memory"},
  "unseal": {"type": "auto"},
  "audit": {"dir": "/tmp/test-audit", "retention_days": 90},
  "logging": {"level": "info"}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// 重载。
	if err := rc.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	newCfg := rc.Get()
	// 端口应保留旧值（冷更新字段）。
	if newCfg.Server.BindPort != oldPort {
		t.Fatalf("cold field (bind_port) should be preserved: got %d, want %d", newCfg.Server.BindPort, oldPort)
	}
	// retention_days 应更新（热更新字段）。
	if newCfg.Audit.RetentionDays != 90 {
		t.Fatalf("hot field (retention_days) should be updated: got %d, want 90", newCfg.Audit.RetentionDays)
	}
	t.Logf("✅ Cold field preserved: bind_port=%d (old), retention_days=%d (new)", oldPort, newCfg.Audit.RetentionDays)
}

// TestReloadableConfig_InvalidPath 无效路径拒绝。
func TestReloadableConfig_InvalidPath(t *testing.T) {
	_, err := NewReloadableConfig("/nonexistent/config.json")
	if err == nil {
		t.Fatal("should fail with nonexistent path")
	}
	t.Logf("✅ Invalid path rejected: %v", err)
}

// TestHotReloadableFields 热更新字段列表。
func TestHotReloadableFields(t *testing.T) {
	fields := HotReloadableFields()
	if len(fields) == 0 {
		t.Fatal("hot reloadable fields should not be empty")
	}
	t.Logf("✅ Hot reloadable fields: %v", fields)
}

// TestColdReloadFields 冷更新字段列表。
func TestColdReloadFields(t *testing.T) {
	fields := ColdReloadFields()
	if len(fields) == 0 {
		t.Fatal("cold reload fields should not be empty")
	}
	t.Logf("✅ Cold reload fields: %v", fields)
}
