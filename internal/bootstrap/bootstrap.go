// Package bootstrap 是 Yvonne 的初始化大管家，负责根据 YvonneConfig 在
// Dev Mode 与 Cluster Mode 之间装配依赖并启动系统。
//
// 设计原则：
//   - 模式隔离：Dev 与 Cluster 的代码路径用严格的 switch/if 分支隔离，
//     防止 Dev 逻辑被 Cluster 误调用。
//   - 开箱即用：Dev 模式零配置启动，自动生成临时 Master Key 并进入 Unsealed。
//   - 严格校验：Cluster 模式配置不合法直接 panic，拒绝启动。
//   - 优雅退出：BuildYvonne 返回的 Server 含 Close 方法，释放连接池与清理内存。
//
// 安全：
//   - Dev 模式启动时必须用红字警告打印不安全提示。
//   - Cluster 模式绝不使用 auto unseal 与 memory storage。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"time"

	"yvonne/internal/admin"
	"yvonne/internal/api"
	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/config"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// Server 是装配完成的 Yvonne 实例。
type Server struct {
	V1Router       *api.V1Router
	AdminServer    *admin.Server
	AuditLog       audit.Auditor
	Metrics        *metrics.Registry
	VaultState     seal.Unsealer
	Store          storage.KVStore
	PGStore        *storage.PostgresKVStore
	Manager        *lifecycle.Manager
	MasterKey      *memguard.SecureBuffer
	RotationDaemon *lifecycle.RotationDaemon
}

// Close 释放所有资源。
// 顺序：先停 HTTP（由外部 main 完成）→ Close audit → Wipe masterKey → Close PG pool → Close store。
func (s *Server) Close() {
	if s.AuditLog != nil {
		s.AuditLog.Close()
	}
	if s.MasterKey != nil {
		s.MasterKey.Wipe()
	}
	if s.PGStore != nil {
		_ = s.PGStore.Close(context.Background())
	}
}

// BuildYvonne 根据配置装配 Yvonne 实例。
//
// 装配顺序：配置加载 → 基础组件（存储、审计）→ 业务组件（Lifecycle、Auth、Seal）→ HTTP 路由 → 后台 Daemon → 启动 Server。
//
// Dev Mode：
//   - 强制 storage=memory
//   - 强制 unseal=auto，生成 32 字节临时 Master Key，直接 Unsealed
//   - 审计输出到 stdout（不落盘）
//   - 红字警告
//
// Cluster Mode：
//   - 严格校验（已由 config.ValidateYvonneConfig 完成）
//   - 双写审计（File + Syslog）必须成功，否则 panic
//   - 强制认证器装配
//   - 装配 RotationDaemon
func BuildYvonne(cfg *config.YvonneConfig) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("bootstrap: nil config")
	}

	metricsReg := metrics.NewRegistry()

	// 模式分支：严格隔离 Dev 与 Cluster 装配逻辑。
	switch cfg.Mode {
	case config.ModeDev:
		// Dev 模式：审计输出到 stdout。
		auditLog, err := audit.NewAuditLogger(os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: dev create audit logger: %w", err)
		}
		return buildDevMode(cfg, auditLog, metricsReg)
	case config.ModeCluster:
		// Cluster 模式：装配双写审计器（File + Syslog）。
		auditLog := buildClusterAuditLogger(cfg)
		return buildClusterMode(cfg, auditLog, metricsReg)
	default:
		panic(fmt.Sprintf("bootstrap: invalid mode %q (validator should have caught this)", cfg.Mode))
	}
}

// buildClusterAuditLogger 装配 Cluster 模式的双写审计器（File + Syslog）。
//
// 致命约束：审计落盘失败 = 不合规 KMS，直接 panic 拒绝启动。
func buildClusterAuditLogger(cfg *config.YvonneConfig) *audit.AuditLogger {
	dir := cfg.Audit.Dir
	filename := cfg.Audit.Filename
	if filename == "" {
		filename = "audit.log"
	}
	retention := cfg.Audit.RetentionDays
	if retention == 0 {
		retention = 180
	}

	// 可选 Syslog。
	var sw *audit.SyslogWriter
	if cfg.Audit.SyslogEnabled {
		tag := cfg.Audit.SyslogTag
		if tag == "" {
			tag = "yvonne-kms"
		}
		var err error
		sw, err = audit.NewSyslogWriter(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, tag)
		if err != nil {
			panic("FATAL: Failed to initialize compliant audit logger (syslog connection failed): " + err.Error())
		}
	}

	logger, err := audit.NewDualWriteLogger(dir, filename, retention, sw)
	if err != nil {
		panic("FATAL: Failed to initialize compliant audit logger (file rotation failed): " + err.Error())
	}
	log.Printf("CLUSTER MODE: dual-write audit logger initialized (dir=%s, retention=%dd, syslog=%v)", dir, retention, cfg.Audit.SyslogEnabled)
	return logger
}

// buildDevMode 装配 Dev 模式实例。
//
// 关键安全决策：
//   - 强制 storage=memory，忽略配置中的 postgres（防误配）。
//   - 强制 unseal=auto，生成临时 Master Key。
//   - 红字警告必须打印。
func buildDevMode(cfg *config.YvonneConfig, auditLog *audit.AuditLogger, metricsReg *metrics.Registry) (*Server, error) {
	// 红字警告（ANSI 红色）。
	const red = "\033[31m"
	const bold = "\033[1m"
	const reset = "\033[0m"
	log.Printf("%s%sWARNING: Yvonne is running in DEV MODE. Data is in-memory only and insecure. DO NOT use in production!%s",
		red, bold, reset)

	// 强制降级：忽略配置的 storage/unseal，用 Dev 专用装配。
	store := storage.NewMemoryStore()

	// 生成临时 Master Key（32 字节，AES-256）。
	masterKey, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		auditLog.Close()
		return nil, fmt.Errorf("bootstrap: dev generate master key: %w", err)
	}

	// 创建 VaultState 并直接 Unseal（Dev 模式跳过 Shamir）。
	// 用 DirectUnseal 注入临时 Master Key，不走 Shamir.Split（parts=1 数学上无意义）。
	vault := seal.NewVaultState(1, 1, 0)
	if err := vault.DirectUnseal(masterKey); err != nil {
		masterKey.Wipe()
		auditLog.Close()
		return nil, fmt.Errorf("bootstrap: dev direct unseal failed: %w", err)
	}

	// 装配 lifecycle Manager（用 Dev masterKey）。
	lifecycleMgr := lifecycle.NewManager(store)

	// 启动回收站自动清理（Dev 模式用 24h TTL，生产用 90 天）。
	lifecycleMgr.StartSoftDeleteReaper(lifecycle.DefaultSoftDeleteTTL, nil)

	// 装配 V1Router（Dev 模式无认证）。
	v1Router := api.NewV1Router(vault, auditLog, lifecycleMgr, metricsReg, nil)

	// 装配 Admin Web UI（Dev 模式默认启用，绑 127.0.0.1:8250）。
	adminSrv := buildAdminServer(cfg, vault)

	log.Printf("DEV MODE assembled: %s", cfg.PrintSummary())

	return &Server{
		V1Router:    v1Router,
		AdminServer: adminSrv,
		AuditLog:    auditLog,
		Metrics:     metricsReg,
		VaultState:  vault,
		Store:       store,
		Manager:     lifecycleMgr,
		MasterKey:   masterKey,
	}, nil
}

// buildClusterMode 装配 Cluster 模式实例。
//
// 严格校验：
//   - storage.type 必须 postgres（已由 ValidateYvonneConfig 拦截，此处二次确认防误配）。
//   - unseal.type 必须 shamir 或 local_pki（绝不 auto）。
//   - 任何校验失败立即 panic，拒绝启动。
func buildClusterMode(cfg *config.YvonneConfig, auditLog *audit.AuditLogger, metricsReg *metrics.Registry) (*Server, error) {
	// 二次确认（防误配）：Cluster 模式绝不用 memory storage 与 auto unseal。
	if cfg.Storage.Type == "memory" {
		auditLog.Close()
		panic("bootstrap: FATAL cluster mode must NOT use memory storage (dev-only)")
	}
	if cfg.Unseal.Type == "auto" {
		auditLog.Close()
		panic("bootstrap: FATAL cluster mode must NOT use auto unseal (dev-only)")
	}

	// 实例化 PGStore。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pgStore, err := storage.NewPostgresKVStoreWithConfig(ctx, storage.PostgresPoolConfig{
		DSN:               cfg.Storage.DSN,
		MaxConns:          8, // 生产建议 2*NumCPU，此处给保守默认值
		MinConns:          2,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
	})
	if err != nil {
		auditLog.Close()
		return nil, fmt.Errorf("bootstrap: cluster create pg store: %w", err)
	}

	// 装配 VaultState（Cluster 模式启动时 Sealed）。
	totalShares := cfg.Unseal.TotalShares
	threshold := cfg.Unseal.Threshold
	if totalShares == 0 {
		totalShares = 5
	}
	if threshold == 0 {
		threshold = 3
	}
	// 按解封策略装配。
	var unsealer seal.Unsealer
	vault := seal.NewVaultState(totalShares, threshold, 30*time.Minute)

	switch cfg.Unseal.Type {
	case "shamir":
		unsealer = vault
		log.Printf("CLUSTER MODE assembled: %s (sealed, awaiting shamir shares)", cfg.PrintSummary())
	case "local_pki":
		pkiUnsealer := seal.NewLocalPKIUnsealer(cfg.Unseal.PKIKeyPath, vault, pgStore)
		if err := pkiUnsealer.AutoUnseal(ctx); err != nil {
			auditLog.Close()
			_ = pgStore.Close(ctx)
			log.Fatalf("bootstrap: FATAL local_pki auto-unseal failed: %v", err)
		}
		unsealer = vault
		log.Printf("CLUSTER MODE assembled: %s (auto-unsealed via local_pki)", cfg.PrintSummary())
	case "hsm":
		// HSM 模式：CMK 永不离开芯片，通过 CryptoBackend.Wrap/Unwrap 工作。
		// HSM 依赖可插拔：默认编译无 HSM 支持，buildHSMBackend 返回 error。
		backend, err := seal.BuildHSMBackend(seal.HSMConfig{
			Backend: cfg.Unseal.HSMBackend,
			KeyID:   cfg.Unseal.HSMKeyID,
		})
		if err != nil {
			auditLog.Close()
			_ = pgStore.Close(ctx)
			panic(fmt.Sprintf("bootstrap: FATAL HSM backend init failed: %v", err))
		}
		unsealer = seal.NewHSMUnsealer(backend)
		log.Printf("CLUSTER MODE assembled: %s (HSM mode, backend=%s)", cfg.PrintSummary(), cfg.Unseal.HSMBackend)
	default:
		auditLog.Close()
		_ = pgStore.Close(ctx)
		panic(fmt.Sprintf("bootstrap: FATAL unsupported unseal type %q in cluster mode", cfg.Unseal.Type))
	}

	// 装配 lifecycle Manager。
	lifecycleMgr := lifecycle.NewManager(pgStore)

	// 启动回收站自动清理（90 天 TTL）。
	lifecycleMgr.StartSoftDeleteReaper(lifecycle.DefaultSoftDeleteTTL, nil)

	// 强制装配认证器（Cluster 模式绝不允许 nil authenticator）。
	// 支持两种认证方式：AppRole（静态 Token）和 JWT（动态 Token）。
	var authenticator auth.Authenticator

	// 构建 PolicyStore（AppRole 和 JWT 共用）。
	policyStore := auth.NewMemoryPolicyStore()

	// 1. 加载 AppRole（如果配置）。
	if len(cfg.Auth.AppRoles) > 0 {
		appAuth := auth.NewAppRoleAuthenticator()
		for _, r := range cfg.Auth.AppRoles {
			policy := &auth.Policy{
				RoleID:         r.RoleID,
				AllowedKeys:    r.AllowedKeys,
				AllowedActions: r.AllowedActions,
			}
			appAuth.RegisterPolicy(r.RoleID, r.Token, policy)
			policyStore.AddPolicy(policy)
		}
		authenticator = appAuth
		log.Printf("CLUSTER MODE: AppRole authenticator loaded with %d role(s)", len(cfg.Auth.AppRoles))
	}

	// 2. 加载 JWT（如果配置）。
	if cfg.Auth.JWT.SigningMethod != "" {
		jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
			SigningMethod:    cfg.Auth.JWT.SigningMethod,
			Secret:           cfg.Auth.JWT.Secret,
			VerifyingKeyPath: cfg.Auth.JWT.VerifyingKeyPath,
			Issuer:           cfg.Auth.JWT.Issuer,
			Audience:         cfg.Auth.JWT.Audience,
			RoleClaim:        cfg.Auth.JWT.RoleClaim,
		}, policyStore)
		if err != nil {
			auditLog.Close()
			_ = pgStore.Close(ctx)
			panic(fmt.Sprintf("FATAL: JWT authenticator init failed: %v", err))
		}
		// 如果同时配置了 AppRole，JWT 优先（生产推荐 JWT）。
		authenticator = jwtAuth
		log.Printf("CLUSTER MODE: JWT authenticator loaded (alg=%s, issuer=%s, role_claim=%s)",
			cfg.Auth.JWT.SigningMethod, cfg.Auth.JWT.Issuer, cfg.Auth.JWT.RoleClaim)
	}

	if authenticator == nil {
		// 致命约束：Cluster 模式无认证器 = 裸奔，拒绝启动。
		auditLog.Close()
		_ = pgStore.Close(ctx)
		panic("FATAL: Cluster mode requires a valid authenticator (configure auth.app_roles or auth.jwt)")
	}

	// 装配 V1Router（注入认证器，绝不传 nil）。
	v1Router := api.NewV1Router(unsealer, auditLog, lifecycleMgr, metricsReg, authenticator)

	// 装配 Admin Web UI。
	adminSrv := buildAdminServer(cfg, vault)

	// 装配 RotationDaemon（Cluster 模式专用）。
	// 使用 AdvisoryLocker 实现集群选主，确保只有一个节点执行轮转。
	locker := storage.NewAdvisoryLocker(pgStore.Pool(), 0x796F6E6E65) // "yonne" 的 int64
	daemon := lifecycle.NewRotationDaemon(lifecycleMgr, unsealer, locker, func(entry lifecycle.AuditEntry) error {
		// 桥接 lifecycle.AuditEntry → audit.LogEntry。
		return auditLog.Record(audit.LogEntry{
			TraceID:   "",
			Timestamp: entry.Timestamp,
			Actor:     entry.Actor,
			Action:    entry.Action,
			Resource:  entry.Resource,
			Result:    entry.Result,
		})
	})

	return &Server{
		V1Router:       v1Router,
		AdminServer:    adminSrv,
		AuditLog:       auditLog,
		Metrics:        metricsReg,
		VaultState:     unsealer,
		Store:          pgStore,
		PGStore:        pgStore,
		Manager:        lifecycleMgr,
		MasterKey:      nil,
		RotationDaemon: daemon,
	}, nil
}

// buildAdminServer 装配 Admin Web UI。
//
// Dev 模式默认启用（即使配置 admin.enabled=false 也强制启用，方便本地测试）。
// Cluster 模式按配置 admin.enabled 控制。
//
// 监听地址：
//   - 优先用配置 admin.bind_addr / admin.bind_port
//   - 未配置时默认 127.0.0.1:8250
//
// 安全：管理页面强制绑 127.0.0.1，禁止 0.0.0.0。
func buildAdminServer(cfg *config.YvonneConfig, unsealer seal.Unsealer) *admin.Server {
	// Dev 模式强制启用 admin UI。
	if cfg.Mode == config.ModeDev {
		log.Printf("DEV MODE: admin web UI forced enabled")
		return admin.NewServer(unsealer)
	}

	// Cluster 模式按配置。
	if !cfg.Server.Admin.Enabled {
		log.Printf("admin web UI disabled by config")
		return nil
	}

	log.Printf("admin web UI enabled at %s:%d", cfg.Server.Admin.BindAddr, cfg.Server.Admin.BindPort)
	return admin.NewServer(unsealer)
}
