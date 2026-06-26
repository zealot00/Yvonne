// Package config - YvonneConfig：统一模式配置（Dev/Cluster）。
//
// 本文件定义 YvonneConfig 结构体，支持从 JSON 配置文件或环境变量加载，
// 控制 Yvonne 在"单机开发者模式（Dev）"与"集群生产模式（Cluster）"间切换。
//
// 与 Config 的关系：
//   - Config：底层子系统配置（Server/Storage/Seal/Crypto/Auth/Audit/Memory/Logging），
//     由 bootstrap 解析后传递给各模块。
//   - YvonneConfig：顶层模式开关 + 模式相关的高层参数。
//
// 安全：
//   - 配置文件密码脱敏：PrintSummary 输出配置摘要时不打印 DSN 中的密码。
//   - Dev 模式强制降级 Storage 为 memory，忽略 cluster 配置。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Mode 是运行模式。
type Mode string

const (
	// ModeDev 单机开发者模式：开箱即用，MemoryStore + 自动生成临时 Master Key。
	ModeDev Mode = "dev"
	// ModeCluster 集群生产模式：严格校验，PostgreSQL + 真实 Unseal 策略。
	ModeCluster Mode = "cluster"
)

// YvonneConfig 是顶层配置，决定 Yvonne 的运行模式与依赖装配。
type YvonneConfig struct {
	Mode    Mode            `json:"mode"    yaml:"mode"`    // "dev" | "cluster"
	Server  ServerConfig    `json:"server"  yaml:"server"`  // 复用既有 ServerConfig
	Storage StorageModeConf `json:"storage" yaml:"storage"` // 模式相关存储配置
	Unseal  UnsealModeConf  `json:"unseal"  yaml:"unseal"`  // 模式相关解封配置
	Auth    AuthModeConf    `json:"auth"    yaml:"auth"`    // 认证配置（Cluster 必填）
	Audit   AuditModeConf   `json:"audit"   yaml:"audit"`   // 审计配置（Cluster 必填）
	Logging LoggingConfig   `json:"logging" yaml:"logging"` // 复用既有 LoggingConfig
}

// AuditModeConf 是审计配置（Cluster 模式必填）。
type AuditModeConf struct {
	Dir           string `json:"dir"             yaml:"dir"`            // 日志目录（如 /var/log/yvonne）
	Filename      string `json:"filename"        yaml:"filename"`       // 当前日志文件名（默认 audit.log）
	RetentionDays int    `json:"retention_days"  yaml:"retention_days"` // 留存天数（默认 180）
	SyslogEnabled bool   `json:"syslog_enabled"  yaml:"syslog_enabled"` // 是否启用 Syslog 双写
	SyslogTag     string `json:"syslog_tag"      yaml:"syslog_tag"`     // Syslog tag（默认 yvonne-kms）
}

// AuthModeConf 是认证配置（Cluster 模式必填，Dev 模式忽略）。
//
// AppRoles 是 AppRole 列表，每个角色包含 Token + Policy。
// Cluster 模式启动时必须至少配置一个角色，否则 panic。
type AuthModeConf struct {
	AppRoles []AppRoleEntry `json:"app_roles" yaml:"app_roles"`
	JWT      JWTConfig      `json:"jwt"       yaml:"jwt"`
	K8s      K8sAuthConfig  `json:"k8s"       yaml:"k8s"`
}

// K8sAuthConfig 是 Kubernetes ServiceAccount JWT 认证配置。
type K8sAuthConfig struct {
	Enabled     bool                      `json:"enabled"      yaml:"enabled"`
	Issuer      string                    `json:"issuer"       yaml:"issuer"`
	Audience    []string                  `json:"audience"     yaml:"audience"`
	RoleMapping map[string]K8sRoleMapping `json:"role_mapping" yaml:"role_mapping"`
	JWKSURL     string                    `json:"jwks_url"     yaml:"jwks_url"`
}

// K8sRoleMapping 是 K8s SA 到 Policy 的映射。
type K8sRoleMapping struct {
	RoleID         string   `json:"role_id"          yaml:"role_id"`
	AllowedKeys    []string `json:"allowed_keys"     yaml:"allowed_keys"`
	AllowedActions []string `json:"allowed_actions"  yaml:"allowed_actions"`
}

// AppRoleEntry 是单个 AppRole 的配置（Cluster 模式认证）。
type AppRoleEntry struct {
	RoleID         string   `json:"role_id"          yaml:"role_id"`
	Token          string   `json:"token"            yaml:"token"`
	AllowedKeys    []string `json:"allowed_keys"     yaml:"allowed_keys"`
	AllowedActions []string `json:"allowed_actions"  yaml:"allowed_actions"`
}

// StorageModeConf 是模式相关的存储配置。
//
// Type 取值：
//   - "memory"：纯内存（Dev 默认，Cluster 禁用）
//   - "postgres"：PostgreSQL（Cluster 必选）
//
// DSN 仅在 Type=="postgres" 时生效。
// 安全：DSN 中的密码不应被打印到日志，PrintSummary 会脱敏。
type StorageModeConf struct {
	Type string `json:"type" yaml:"type"` // "memory" | "postgres"
	DSN  string `json:"dsn"  yaml:"dsn"`  // Postgres 连接串（含密码，脱敏打印）
}

// UnsealModeConf 是模式相关的解封配置。
//
// Type 取值：
//   - "shamir"：Shamir 门限解封（Cluster 默认）
//   - "local_pki"：本地 PKI 自动解封（用本地私钥解封 Master Key）
//   - "hsm"：HSM 硬件安全模块（CMK 永不离开芯片，需 -tags hsm 编译）
//   - "auto"：Dev 模式专用，自动生成临时 Master Key 跳过解封
type UnsealModeConf struct {
	Type            string `json:"type"              yaml:"type"`
	TotalShares     int    `json:"total_shares"      yaml:"total_shares"`
	Threshold       int    `json:"threshold"         yaml:"threshold"`
	PKIKeyPath      string `json:"pki_key_path"      yaml:"pki_key_path"`
	AutoResealAfter string `json:"auto_reseal_after" yaml:"auto_reseal_after"`

	// HSM 字段（Type=="hsm" 时生效，需 -tags hsm 编译）。
	HSMBackend string `json:"hsm_backend,omitempty" yaml:"hsm_backend,omitempty"` // "mock"|"pkcs11"（未来）|"tpm"（未来）
	HSMKeyID   string `json:"hsm_key_id,omitempty"  yaml:"hsm_key_id,omitempty"`  // HSM 内密钥标识
}

// LoadYvonneConfig 从 JSON 配置文件加载 YvonneConfig。
//
// 配置文件格式示例：
//
//	{
//	  "mode": "dev",
//	  "storage": {"type": "memory"},
//	  "unseal": {"type": "auto"}
//	}
//
// 环境变量覆盖（优先级高于配置文件）：
//
//	YVONNE_MODE: 覆盖 mode
//	YVONNE_STORAGE_TYPE: 覆盖 storage.type
//	YVONNE_STORAGE_DSN: 覆盖 storage.dsn
//	YVONNE_UNSEAL_TYPE: 覆盖 unseal.type
func LoadYvonneConfig(path string) (*YvonneConfig, error) {
	cfg := &YvonneConfig{
		Mode: ModeDev, // 默认 dev，防误用 cluster 配置缺失导致启动失败
		Storage: StorageModeConf{
			Type: "memory",
		},
		Unseal: UnsealModeConf{
			Type:        "auto",
			TotalShares: 5,
			Threshold:   3,
		},
		Server: ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 8200,
			Admin: AdminServerConfig{
				Enabled:  true,
				BindAddr: "127.0.0.1",
				BindPort: 8250,
			},
		},
		Logging: LoggingConfig{
			Level:         "info",
			Format:        "json",
			Output:        "stdout",
			RedactSecrets: true,
		},
	}

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}

	applyYvonneEnvOverrides(cfg)

	if err := ValidateYvonneConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyYvonneEnvOverrides 用环境变量覆盖配置。
func applyYvonneEnvOverrides(cfg *YvonneConfig) {
	if v := os.Getenv("YVONNE_MODE"); v != "" {
		cfg.Mode = Mode(v)
	}
	if v := os.Getenv("YVONNE_STORAGE_TYPE"); v != "" {
		cfg.Storage.Type = v
	}
	if v := os.Getenv("YVONNE_STORAGE_DSN"); v != "" {
		cfg.Storage.DSN = v
	}
	if v := os.Getenv("YVONNE_UNSEAL_TYPE"); v != "" {
		cfg.Unseal.Type = v
	}
	if v := os.Getenv("YVONNE_UNSEAL_THRESHOLD"); v != "" {
		// 简单 Atoi，失败忽略。
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			cfg.Unseal.Threshold = n
		}
	}
}

// ValidateYvonneConfig 校验配置。
//
// Dev 模式：宽松校验，允许缺失 storage/unseal（用默认值）。
// Cluster 模式：严格校验，storage.type 必须 postgres，unseal.type 必须 shamir 或 local_pki。
func ValidateYvonneConfig(cfg *YvonneConfig) error {
	switch cfg.Mode {
	case ModeDev:
		// Dev 模式：强制降级，不校验 cluster 配置。
		// bootstrap 会强制 storage=memory + unseal=auto。
		return nil
	case ModeCluster:
		return validateClusterConfig(cfg)
	default:
		return fmt.Errorf("config: invalid mode %q, must be 'dev' or 'cluster'", cfg.Mode)
	}
}

// validateClusterConfig 严格校验 Cluster 模式配置。
func validateClusterConfig(cfg *YvonneConfig) error {
	var errs []string

	if cfg.Storage.Type != "postgres" {
		errs = append(errs, fmt.Sprintf("cluster mode requires storage.type='postgres', got %q", cfg.Storage.Type))
	}
	if cfg.Storage.DSN == "" {
		errs = append(errs, "cluster mode requires storage.dsn")
	}

	switch cfg.Unseal.Type {
	case "shamir", "local_pki", "hsm":
		// 合法。
	case "auto":
		errs = append(errs, "cluster mode must NOT use unseal.type='auto' (dev-only)")
	case "":
		errs = append(errs, "cluster mode requires unseal.type")
	default:
		errs = append(errs, fmt.Sprintf("cluster mode: unsupported unseal.type %q", cfg.Unseal.Type))
	}

	if cfg.Unseal.Type == "shamir" {
		if cfg.Unseal.TotalShares < 2 || cfg.Unseal.TotalShares > 255 {
			errs = append(errs, fmt.Sprintf("shamir total_shares must be in [2,255], got %d", cfg.Unseal.TotalShares))
		}
		if cfg.Unseal.Threshold < 2 || cfg.Unseal.Threshold > cfg.Unseal.TotalShares {
			errs = append(errs, fmt.Sprintf("shamir threshold must be in [2,total_shares], got %d", cfg.Unseal.Threshold))
		}
	}

	if cfg.Unseal.Type == "local_pki" && cfg.Unseal.PKIKeyPath == "" {
		errs = append(errs, "local_pki requires unseal.pki_key_path")
	}

	if !cfg.Logging.RedactSecrets {
		errs = append(errs, "cluster mode requires logging.redact_secrets=true")
	}

	// Cluster 模式必须配置审计落盘目录。
	if cfg.Audit.Dir == "" {
		errs = append(errs, "cluster mode requires audit.dir (e.g. /var/log/yvonne)")
	}

	// Cluster 模式必须配置至少一个 AppRole。
	if len(cfg.Auth.AppRoles) == 0 {
		errs = append(errs, "cluster mode requires at least one auth.app_roles entry")
	}
	for i, r := range cfg.Auth.AppRoles {
		if r.RoleID == "" {
			errs = append(errs, fmt.Sprintf("auth.app_roles[%d].role_id is required", i))
		}
		if r.Token == "" {
			errs = append(errs, fmt.Sprintf("auth.app_roles[%d].token is required", i))
		}
		if len(r.AllowedKeys) == 0 {
			errs = append(errs, fmt.Sprintf("auth.app_roles[%d].allowed_keys is required", i))
		}
		if len(r.AllowedActions) == 0 {
			errs = append(errs, fmt.Sprintf("auth.app_roles[%d].allowed_actions is required", i))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cluster config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// PrintSummary 返回配置摘要字符串，用于启动日志。
//
// 安全：DSN 中的密码被脱敏（用 redactDSN 函数处理）。
func (c *YvonneConfig) PrintSummary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "mode=%s", c.Mode)
	fmt.Fprintf(&sb, " storage.type=%s", c.Storage.Type)
	if c.Storage.DSN != "" {
		fmt.Fprintf(&sb, " storage.dsn=%s", redactDSN(c.Storage.DSN))
	}
	fmt.Fprintf(&sb, " unseal.type=%s", c.Unseal.Type)
	if c.Unseal.Type == "shamir" {
		fmt.Fprintf(&sb, " unseal.shamir=%d/%d", c.Unseal.Threshold, c.Unseal.TotalShares)
	}
	fmt.Fprintf(&sb, " server=%s:%d", c.Server.BindAddr, c.Server.BindPort)
	return sb.String()
}

// redactDSN 脱敏 DSN 中的密码。
//
// 支持两种格式：
//   - URL 形式：postgres://user:pass@host/db → postgres://user:xxxxx@host/db
//   - key=value 形式：password=pass → password=xxxxx
func redactDSN(dsn string) string {
	// URL 形式：处理 user:pass@ 模式。
	if strings.Contains(dsn, "://") {
		atIdx := strings.LastIndex(dsn, "@")
		schemeEnd := strings.Index(dsn, "://") + 3
		if atIdx > schemeEnd {
			userEnd := strings.Index(dsn[schemeEnd:], ":")
			if userEnd >= 0 {
				userEnd += schemeEnd
				return dsn[:userEnd+1] + "xxxxx" + dsn[atIdx:]
			}
		}
	}
	// key=value 形式：替换 password=xxx。
	if strings.Contains(dsn, "password=") {
		return regexpReplacePassword(dsn)
	}
	return dsn
}

// regexpReplacePassword 用简单字符串替换处理 password=xxx（避免引入 regexp 依赖）。
func regexpReplacePassword(dsn string) string {
	idx := strings.Index(dsn, "password=")
	if idx < 0 {
		return dsn
	}
	rest := dsn[idx+len("password="):]
	// 找到下一个空格或字符串末尾。
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	return dsn[:idx+len("password=")] + "xxxxx" + rest[end:]
}
