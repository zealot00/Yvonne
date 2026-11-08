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
	"time"
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
	Mode          Mode                `json:"mode"           yaml:"mode"`         // "dev" | "cluster"
	Server        ServerConfig        `json:"server"         yaml:"server"`       // 复用既有 ServerConfig
	Storage       StorageModeConf     `json:"storage"        yaml:"storage"`      // 模式相关存储配置
	Unseal        UnsealModeConf      `json:"unseal"         yaml:"unseal"`       // 模式相关解封配置
	Auth          AuthModeConf        `json:"auth"           yaml:"auth"`         // 认证配置（Cluster 必填）
	Audit         AuditModeConf       `json:"audit"          yaml:"audit"`        // 审计配置（Cluster 必填）
	Logging       LoggingConfig       `json:"logging"        yaml:"logging"`      // 复用既有 LoggingConfig
	Crypto        CryptoConfig        `json:"crypto"         yaml:"crypto"`       // 密码套件配置（v1.1 新增 Suite 字段）
	MFA           MFAConfig           `json:"mfa"            yaml:"mfa"`          // v1.3: MFA TOTP 配置
	Observability ObservabilityConfig `json:"observability" yaml:"observability"` // v1.3: OTel + Alerting
	MultiTenant   MultiTenantConfig   `json:"multi_tenant"  yaml:"multi_tenant"`  // v1.3.1: 多租户配置
	SDF           SDFConfig           `json:"sdf"           yaml:"sdf"`           // v1.5: SDF 软件密码机配置
	PKI           PKIConfig           `json:"pki"           yaml:"pki"`           // v1.4.x: PKI（CA / 证书 / OCSP）配置
}

// PKIConfig 是 PKI 子系统配置（v1.4.x 新增）。
//
// 包含 CA 管理、证书签发、OCSP Responder 等子模块的开关。
type PKIConfig struct {
	// Enabled 启用 PKI 子系统（CA 创建 + 证书签发 + 验证 + 吊销 + CRL）。
	// 默认 false（向后兼容）。
	Enabled bool `json:"enabled" yaml:"enabled"`
	// OCSPEnabled 启用 OCSP Responder（/api/v1/ocsp）。需要 PKI.Enabled = true。
	// 默认 false。
	OCSPEnabled bool `json:"ocsp_enabled" yaml:"ocsp_enabled"`
	// OCSPToken OCSP 可选 Bearer token；空 = 无认证（公网部署由前置网关负责访问控制）。
	// 设置后 OCSP 请求需带 Authorization: Bearer {token}。
	OCSPToken string `json:"ocsp_token" yaml:"ocsp_token"`
}

// SDFConfig 是 SDF 软件密码机配置（v1.5）。
type SDFConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"` // 是否启用 SDF 接口
	Token   string `json:"token"   yaml:"token"`   // SDF 专用认证 token
}

// MultiTenantConfig 是多租户配置（v1.3.1）。
type MultiTenantConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"` // 是否启用多租户隔离
}

// MFAConfig 是 MFA TOTP 配置（v1.3）。
type MFAConfig struct {
	Enabled       bool   `json:"enabled"        yaml:"enabled"`        // 是否启用 MFA
	Issuer        string `json:"issuer"         yaml:"issuer"`         // TOTP 发行方（默认 "Yvonne KMS"）
	WindowSeconds int    `json:"window_seconds" yaml:"window_seconds"` // TOTP 窗口秒数（默认 30）
	// SensitiveOperations 需 MFA 的敏感操作列表。
	SensitiveOperations []string `json:"sensitive_operations" yaml:"sensitive_operations"`
}

// ObservabilityConfig 是可观测性配置（v1.3）。
type ObservabilityConfig struct {
	Tracing  TracingConfig  `json:"tracing"   yaml:"tracing"`  // OTel tracing
	Alerting AlertingConfig `json:"alerting"  yaml:"alerting"` // Webhook 告警
}

// TracingConfig 是 OpenTelemetry tracing 配置。
type TracingConfig struct {
	Enabled     bool   `json:"enabled"     yaml:"enabled"`       // 是否启用 tracing
	Endpoint    string `json:"endpoint"    yaml:"endpoint"`      // OTLP endpoint（如 localhost:4317）
	ServiceName string `json:"service_name" yaml:"service_name"` // 服务名（默认 yvonne-kms）
}

// AlertingConfig 是 Webhook 告警配置。
type AlertingConfig struct {
	Enabled            bool     `json:"enabled"               yaml:"enabled"`
	WebhookURL         string   `json:"webhook_url"           yaml:"webhook_url"`          // Slack/钉钉/PagerDuty webhook
	HighRiskOperations []string `json:"high_risk_operations"  yaml:"high_risk_operations"` // 触发告警的操作
}

// AuditModeConf 是审计配置（Cluster 模式必填）。
//
// 时区开关（v1.4.1）：
//
//	TimezoneEnabled=false（默认，国际部署）：文件名 + 留存 cutoff 用 UTC（v1.4.0 行为，向后兼容）。
//	TimezoneEnabled=true（国密/crypto.strict=true 自动启用）：
//	  文件名 + 留存 cutoff 切换至 Timezone 字段指定的 IANA 时区；
//	  envelope JSON 的 timestamp 字段**仍保持 UTC**（wire-format 规范，跨时区一致）。
//
// 国密部署默认 TimezoneEnabled=true, Timezone="Asia/Shanghai"，
// 运维/合规审查员在 CN 时区下文件名与日历日期对齐。
type AuditModeConf struct {
	Dir             string `json:"dir"               yaml:"dir"`              // 日志目录（如 /var/log/yvonne）
	Filename        string `json:"filename"          yaml:"filename"`         // 当前日志文件名（默认 audit.log）
	RetentionDays   int    `json:"retention_days"    yaml:"retention_days"`   // 留存天数（默认 180）
	SyslogEnabled   bool   `json:"syslog_enabled"    yaml:"syslog_enabled"`   // 是否启用 Syslog 双写
	SyslogTag       string `json:"syslog_tag"        yaml:"syslog_tag"`       // Syslog tag（默认 yvonne-kms）
	TimezoneEnabled bool   `json:"timezone_enabled"  yaml:"timezone_enabled"` // 是否按本地时区切文件 + 留存
	Timezone        string `json:"timezone"          yaml:"timezone"`         // IANA 时区名（如 Asia/Shanghai），TimezoneEnabled=true 时必填
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
	TenantID       string   `json:"tenant_id"        yaml:"tenant_id"` // v1.3.1: 多租户 ID（空=非多租户）
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
				Enabled:  false, // Dev 模式由 bootstrap 强制启用；Cluster 模式显式启用时必须配置 admin_token
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
		raw, err := os.ReadFile(path) // #nosec G304 -- path 由管理员配置
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}

	applyYvonneEnvOverrides(cfg)
	applyAuditTimezoneDefaults(cfg)

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
	if v := os.Getenv("YVONNE_SERVER_BIND_ADDR"); v != "" {
		cfg.Server.BindAddr = v
	}
	if v := os.Getenv("YVONNE_SERVER_BIND_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil {
			cfg.Server.BindPort = p
		}
	}
	if v := os.Getenv("YVONNE_STORAGE_TYPE"); v != "" {
		cfg.Storage.Type = v
	} else if v := os.Getenv("YVONNE_STORAGE_BACKEND"); v != "" {
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
	if v := os.Getenv("YVONNE_AUDIT_DIR"); v != "" {
		cfg.Audit.Dir = v
	}
	if v := os.Getenv("YVONNE_AUDIT_TIMEZONE_ENABLED"); v != "" {
		cfg.Audit.TimezoneEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("YVONNE_AUDIT_TIMEZONE"); v != "" {
		cfg.Audit.Timezone = v
	}
	if v := os.Getenv("YVONNE_ADMIN_TOKEN"); v != "" {
		cfg.Server.Admin.AdminToken = v
	} else if v := os.Getenv("YVONNE_SERVER_ADMIN_ADMIN_TOKEN"); v != "" {
		cfg.Server.Admin.AdminToken = v
	}
	if v := os.Getenv("YVONNE_SERVER_MCP_TOKEN"); v != "" {
		cfg.Server.MCP.Token = v
	}
	if v := os.Getenv("YVONNE_AUTH_JWT_SECRET"); v != "" {
		cfg.Auth.JWT.Secret = v
	}
}

// applyAuditTimezoneDefaults 自动填充审计时区默认值（v1.4.1）。
//
// 规则（最小惊讶）：
//   - cfg.Audit.Timezone != "" → 用户配置了时区名 → 强制启用开关（信任用户）。
//   - cfg.Audit.Timezone == "" + cfg.Crypto.Strict == true（国密模式） → 自动开启 Asia/Shanghai。
//   - 其他 → 保持默认 UTC（开 = false / 名称 = "" → 运行期 fallback UTC，向后兼容 v1.4.0）。
//
// 简化为：开关只在"填了时区名"或"国密模式"两种情况下为 true。
func applyAuditTimezoneDefaults(cfg *YvonneConfig) {
	if cfg.Audit.Timezone != "" {
		// 用户填了时区名（含显式 "UTC" 也算填了）→ 视为开启。
		cfg.Audit.TimezoneEnabled = true
		return
	}
	if cfg.Crypto.Strict {
		// 国密模式默认开 CN 时区。
		cfg.Audit.TimezoneEnabled = true
		cfg.Audit.Timezone = "Asia/Shanghai"
		return
	}
	// 其余：留空（运行期 fallback UTC，向后兼容 v1.4.0）。
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

	// v1.4.1: 审计时区 IANA 名必须合法（用 Go time.LoadLocation 验证）。
	// 校验失败立即失败 → 防止启动后才发现文件名错乱。
	if cfg.Audit.TimezoneEnabled && cfg.Audit.Timezone != "" {
		if _, err := time.LoadLocation(cfg.Audit.Timezone); err != nil {
			errs = append(errs, fmt.Sprintf("audit.timezone %q is not a valid IANA name: %v (try 'UTC', 'Asia/Shanghai', 'America/New_York', etc.)",
				cfg.Audit.Timezone, err))
		}
	}

	// Cluster 模式管理台若启用，必须绑定 loopback 且配置非空 admin_token（拒绝 fail-open）。
	if cfg.Server.Admin.Enabled {
		if cfg.Server.Admin.BindAddr != "" && cfg.Server.Admin.BindAddr != "127.0.0.1" && cfg.Server.Admin.BindAddr != "localhost" {
			errs = append(errs, "cluster mode requires server.admin.bind_addr to be 127.0.0.1 or localhost")
		}
		if cfg.Server.Admin.AdminToken == "" {
			errs = append(errs, "cluster mode requires server.admin.admin_token when server.admin.enabled=true")
		}
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
