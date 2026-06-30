// Package config - 热配置重载（SIGHUP）。
//
// ReloadableConfig 包装 atomic.Pointer[YvonneConfig]，支持无重启热更新。
//
// 热更新白名单（可热更）：
//   - logging: 日志级别
//   - audit: 留存天数、syslog
//   - observability: tracing、alerting
//
// 冷更新（需重启）：
//   - storage: 数据库连接
//   - auth: 认证器配置
//   - server: 端口、TLS
//   - unseal: 解封配置
package config

import (
	"fmt"
	"log"
	"sync/atomic"

	"yvonne/internal/memguard"
)

// ReloadableConfig 是线程安全的热配置容器。
type ReloadableConfig struct {
	current atomic.Pointer[YvonneConfig]
	path    string
}

// NewReloadableConfig 创建热配置容器。
// 初始配置从 path 加载。
func NewReloadableConfig(path string) (*ReloadableConfig, error) {
	cfg, err := LoadYvonneConfig(path)
	if err != nil {
		return nil, fmt.Errorf("config: initial load: %w", err)
	}

	rc := &ReloadableConfig{path: path}
	rc.current.Store(cfg)
	return rc, nil
}

// Get 返回当前配置（线程安全）。
func (rc *ReloadableConfig) Get() *YvonneConfig {
	return rc.current.Load()
}

// Reload 从磁盘重新加载配置。
// 仅热更新白名单字段生效，冷更新字段需重启。
func (rc *ReloadableConfig) Reload() error {
	newCfg, err := LoadYvonneConfig(rc.path)
	if err != nil {
		return fmt.Errorf("config: reload: %w", err)
	}

	oldCfg := rc.current.Load()

	// 合并：热更新字段用 newCfg，冷更新字段保留 oldCfg。
	merged := mergeHotReloadable(oldCfg, newCfg)

	rc.current.Store(merged)
	log.Printf("config reloaded: hot fields updated (logging/audit/observability)")

	return nil
}

// mergeHotReloadable 合并热更新字段。
// 冷更新字段（storage/auth/server/unseal）保留旧值。
func mergeHotReloadable(old, new *YvonneConfig) *YvonneConfig {
	merged := *new // 浅拷贝 new

	// 冷更新字段保留旧值。
	merged.Server = old.Server
	merged.Storage = old.Storage
	merged.Unseal = old.Unseal
	merged.Auth = old.Auth

	// 热更新字段用新值。
	// merged.Logging = new.Logging  // 已在浅拷贝中
	// merged.Audit = new.Audit
	// merged.Crypto = new.Crypto
	// merged.MFA = new.MFA
	// merged.Observability = new.Observability

	return &merged
}

// HotReloadableFields 返回可热更新的字段名列表（文档化用）。
func HotReloadableFields() []string {
	return []string{
		"logging",
		"audit",
		"crypto",
		"mfa",
		"observability",
	}
}

// ColdReloadFields 返回需重启的字段名列表（文档化用）。
func ColdReloadFields() []string {
	return []string{
		"server",
		"storage",
		"unseal",
		"auth",
	}
}

// 确保 memguard 被引用（config 包可能用到 SecureBuffer）。
var _ = memguard.NewSecureBuffer
