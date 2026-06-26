// Package config 定义 Yvonne KMS 的全局配置结构。
// 所有敏感字段（路径、盐值）仅在此处声明，绝不内嵌明文密钥。
package config

// Config 是 Yvonne KMS 的根配置。
// 加载完成后会经过 Validator 强制校验，未通过则进程拒绝启动。
type Config struct {
	Server  ServerConfig  `json:"server"  yaml:"server"`
	Storage StorageConfig `json:"storage" yaml:"storage"`
	Seal    SealConfig    `json:"seal"    yaml:"seal"`
	Crypto  CryptoConfig  `json:"crypto"  yaml:"crypto"`
	Auth    AuthConfig    `json:"auth"    yaml:"auth"`
	Audit   AuditConfig   `json:"audit"   yaml:"audit"`
	Memory  MemoryConfig  `json:"memory"  yaml:"memory"`
	Logging LoggingConfig `json:"logging" yaml:"logging"`
}

// ServerConfig 控制 HTTP 监听与 TLS。
type ServerConfig struct {
	BindAddr     string            `json:"bind_addr"     yaml:"bind_addr"` // 默认 127.0.0.1，禁止 0.0.0.0 除非显式声明
	BindPort     int               `json:"bind_port"     yaml:"bind_port"`
	ReadTimeout  Duration          `json:"read_timeout"  yaml:"read_timeout"`
	WriteTimeout Duration          `json:"write_timeout" yaml:"write_timeout"`
	MaxConns     int               `json:"max_conns"     yaml:"max_conns"`
	TLS          TLSConfig         `json:"tls"           yaml:"tls"` // 生产环境强制 Enabled=true
	Admin        AdminServerConfig `json:"admin"         yaml:"admin"`
	GRPC         GRPCServerConfig  `json:"grpc"          yaml:"grpc"`
	MCP          MCPServerConfig   `json:"mcp"           yaml:"mcp"`
}

// GRPCServerConfig 是 gRPC server 配置。
type GRPCServerConfig struct {
	Enabled  bool      `json:"enabled"   yaml:"enabled"`
	BindAddr string    `json:"bind_addr" yaml:"bind_addr"` // 默认 127.0.0.1
	BindPort int       `json:"bind_port" yaml:"bind_port"` // 默认 8251
	TLS      TLSConfig `json:"tls"       yaml:"tls"`
}

// MCPServerConfig 是 MCP server 配置。
type MCPServerConfig struct {
	Enabled      bool     `json:"enabled"       yaml:"enabled"`
	Stdio        bool     `json:"stdio"         yaml:"stdio"`           // stdio 传输（子进程模式）
	HTTPBindAddr string   `json:"http_bind_addr" yaml:"http_bind_addr"` // Streamable HTTP 传输
	HTTPBindPort int      `json:"http_bind_port" yaml:"http_bind_port"`
	Token        string   `json:"token"         yaml:"token"`        // MCP 专用 token（必填）
	AllowedKeys  []string `json:"allowed_keys"  yaml:"allowed_keys"` // Decrypt 白名单
}

type TLSConfig struct {
	Enabled      bool   `json:"enabled"       yaml:"enabled"`
	CertFile     string `json:"cert_file"     yaml:"cert_file"`
	KeyFile      string `json:"key_file"      yaml:"key_file"`
	MinVersion   string `json:"min_version"   yaml:"min_version"`     // "TLS1.2" | "TLS1.3"
	ClientCAFile string `json:"client_ca_file" yaml:"client_ca_file"` // 客户端 CA 证书池（mTLS）
	ClientAuth   string `json:"client_auth"   yaml:"client_auth"`     // "require" | "optional" | "none"(默认)
}

// AdminServerConfig 管理页面相关配置。
// 管理页面默认仅绑定 127.0.0.1，生产环境强烈建议通过反向代理 + mTLS 暴露。
type AdminServerConfig struct {
	Enabled    bool   `json:"enabled"     yaml:"enabled"`
	BindAddr   string `json:"bind_addr"   yaml:"bind_addr"` // 强制 127.0.0.1，禁止 0.0.0.0
	BindPort   int    `json:"bind_port"   yaml:"bind_port"`
	AdminToken string `json:"admin_token" yaml:"admin_token"` // 全站认证 Token（Basic Auth password 或 Bearer）
}

// StorageConfig 持久化后端配置。
// 仅允许 "boltdb"（嵌入式，单机）或 "postgres"（HA/共享存储）。
type StorageConfig struct {
	Backend string `json:"backend" yaml:"backend"` // "boltdb" | "postgres"
	DSN     string `json:"dsn"     yaml:"dsn"`     // Postgres 连接串；BoltDB 留空
	Path    string `json:"path"    yaml:"path"`    // BoltDB 文件路径；Postgres 留空
}

// SealConfig 封印机制（Shamir 门限）配置。
type SealConfig struct {
	TotalShares     int      `json:"total_shares"      yaml:"total_shares"`      // 默认 5
	Threshold       int      `json:"threshold"         yaml:"threshold"`         // 默认 3，必须 <= TotalShares
	AutoResealAfter Duration `json:"auto_reseal_after" yaml:"auto_reseal_after"` // Unsealed 后超时自动重新封印，0 表示禁用
}

// CryptoConfig 密码学引擎参数。
// 算法白名单在此固化，运行时不允许越界。
type CryptoConfig struct {
	DEKSize           int      `json:"dek_size"            yaml:"dek_size"`            // 固定 32（AES-256）
	RSAKeyBits        int      `json:"rsa_key_bits"        yaml:"rsa_key_bits"`        // 固定 4096
	ECDSACurve        string   `json:"ecdsa_curve"         yaml:"ecdsa_curve"`         // "P-256" | "P-384"
	DEKRotationPeriod Duration `json:"dek_rotation_period" yaml:"dek_rotation_period"` // 0 表示禁用自动轮转
}

// AuthConfig 认证与授权配置。
type AuthConfig struct {
	AppRole AppRoleConfig `json:"approle" yaml:"approle"`
	JWT     JWTConfig     `json:"jwt"     yaml:"jwt"`
}

type AppRoleConfig struct {
	RoleIDLength   int      `json:"role_id_length"   yaml:"role_id_length"`   // 默认 16
	SecretIDLength int      `json:"secret_id_length" yaml:"secret_id_length"` // 默认 32
	SecretIDTTL    Duration `json:"secret_id_ttl"    yaml:"secret_id_ttl"`
	BindSecretID   bool     `json:"bind_secret_id"   yaml:"bind_secret_id"`
}

type JWTConfig struct {
	// 算法配置：支持 RS256/RS384/RS512、ES256/ES384/ES512、HS256/HS384/HS512。
	SigningMethod string `json:"signing_method" yaml:"signing_method"`

	// HMAC 对称密钥（仅 HS256/384/512 使用）。生产建议用非对称。
	Secret string `json:"secret" yaml:"secret"`

	// 非对称密钥文件路径（RSA 公钥 PEM 或 ECDSA 公钥 PEM）。
	VerifyingKeyPath string `json:"verifying_key_path" yaml:"verifying_key_path"`

	// 标准 Claims 校验。
	Issuer   string   `json:"issuer"   yaml:"issuer"`   // 必须匹配
	Audience []string `json:"audience" yaml:"audience"` // 必须匹配其一

	// 角色字段提取：从哪个 claim 中读取 RoleID。
	// 常见值："sub"（默认）、"role"、"roles"（取第一个）、"x-role-id"。
	// 支持嵌套点号路径，如 "custom.role"。
	RoleClaim string `json:"role_claim" yaml:"role_claim"`

	// TokenTTL 仅用于签发场景（Yvonne 作为 IdP）。验签时不限制 TTL（由 exp claim 决定）。
	TokenTTL Duration `json:"token_ttl" yaml:"token_ttl"`

	// SigningKeyPath 仅用于签发场景（Yvonne 作为 IdP）。验签不需要。
	SigningKeyPath string `json:"signing_key_path" yaml:"signing_key_path"`
}

// AuditConfig 防篡改审计配置。
// Audit Key 不直接存配置，运行期由 Master Key 经 HKDF 派生。
type AuditConfig struct {
	LogPath                string `json:"log_path"                  yaml:"log_path"`                  // 审计日志落盘路径
	AuditKeyDerivationSalt string `json:"audit_key_derivation_salt" yaml:"audit_key_derivation_salt"` // HKDF salt（hex），Unsealed 后生效
	Fsync                  bool   `json:"fsync"                     yaml:"fsync"`                     // 强烈建议 true，满足不可篡改
	MaxEntryBytes          int    `json:"max_entry_bytes"           yaml:"max_entry_bytes"`           // 防单条日志爆炸
}

// MemoryConfig 极寒内存防御配置。
type MemoryConfig struct {
	EnableMLock bool   `json:"enable_mlock" yaml:"enable_mlock"` // 是否调用 mlock 锁定物理内存（防 Swap）
	UseMmap     bool   `json:"use_mmap"     yaml:"use_mmap"`     // 是否走 mmap 分配敏感 buffer
	GCPolicy    string `json:"gc_policy"    yaml:"gc_policy"`    // 保留扩展：当前固定 "avoid_gc_for_secure_buffer"
}

// LoggingConfig 系统日志（区别于审计日志）。
// 关键：所有日志必须脱敏，禁止打印任何明文密钥/Token。
type LoggingConfig struct {
	Level         string `json:"level"          yaml:"level"`          // "info" | "warn" | "error"
	Format        string `json:"format"         yaml:"format"`         // "json" | "console"
	Output        string `json:"output"         yaml:"output"`         // "stdout" | 文件路径
	RedactSecrets bool   `json:"redact_secrets" yaml:"redact_secrets"` // 强制 true，否则 Validator 拒绝启动
}
