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
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"time"

	"yvonne/internal/admin"
	"yvonne/internal/api"
	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/config"
	"yvonne/internal/crypto"
	grpcsrv "yvonne/internal/grpc"
	"yvonne/internal/lifecycle"
	"yvonne/internal/mcp"
	"yvonne/internal/memguard"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/service"
	"yvonne/internal/storage"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "yvonne/gen/proto/yvonne/v1"
)

// Server 是装配完成的 Yvonne 实例。
type Server struct {
	V1Router       *api.V1Router
	AdminServer    *admin.Server
	GRPCServer     *grpc.Server
	MCPServer      *mcp.Server
	MCPHTTPServer  *http.Server
	Core           *service.Core
	AuditLog       audit.Auditor
	Metrics        *metrics.Registry
	VaultState     seal.Unsealer
	Store          storage.KVStore
	PGStore        *storage.PostgresKVStore
	Manager        *lifecycle.Manager
	MasterKey      *memguard.SecureBuffer
	RotationDaemon *lifecycle.RotationDaemon
}

// setVaultCryptoSuite 根据 crypto.suite 配置设置 vault 的密码套件。
// "gmsm" 需 -tags gmsm 编译，否则 NewGMSMSuite 返回 error。
func setVaultCryptoSuite(vault *seal.VaultState, cfg *config.YvonneConfig) {
	switch cfg.Crypto.Suite {
	case "gmsm":
		suite, err := crypto.NewGMSMSuite()
		if err != nil {
			log.Fatalf("crypto.suite=gmsm but GMSM not compiled in: %v (rebuild with -tags gmsm)", err)
		}
		vault.SetCryptoSuite(suite)
		log.Printf("crypto suite: gmsm (SM4-GCM + SM3)")
	case "standard", "":
		vault.SetCryptoSuite(crypto.NewStandardSuite())
		log.Printf("crypto suite: standard (AES-256-GCM + SHA-256)")
	}
}

// buildGRPCServer 创建 gRPC server 实例（含拦截器链 + 敏感数据擦除 codec + 可选 mTLS）。
func buildGRPCServer(core *service.Core, authenticator auth.Authenticator, vault seal.Unsealer, tlsCfg *tls.Config) *grpc.Server {
	// 注册 wipingCodec（覆盖默认 proto codec，序列化后清理明文 DEK）。
	grpcsrv.RegisterWipingCodec()

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpcsrv.InterceptorChain(authenticator, vault),
		),
	}
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	srv := grpc.NewServer(opts...)
	pbServer := grpcsrv.NewServer(core, authenticator)
	pb.RegisterYvonneServiceServer(srv, pbServer)
	return srv
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
	setVaultCryptoSuite(vault, cfg)
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
	adminSrv.SetManager(lifecycleMgr) // P1: Admin UI 密钥列表

	// Core service 层（共享给 gRPC/MCP）。
	core := service.NewManager(lifecycleMgr, vault, auditLog)
	core.SetAdminToken(cfg.Server.Admin.AdminToken)

	// gRPC server（Dev 模式可选，默认启用）。
	var grpcSrv *grpc.Server
	if cfg.Server.GRPC.Enabled {
		grpcSrv = buildGRPCServer(core, nil, vault, nil) // Dev 模式无 authenticator 无 TLS
		log.Printf("DEV MODE: gRPC server enabled")
	}

	// MCP server（Dev 模式可选）。
	var mcpSrv *mcp.Server
	if cfg.Server.MCP.Enabled {
		mcpSrv = mcp.NewServer(core, mcp.Config{
			Token:       cfg.Server.MCP.Token,
			AllowedKeys: cfg.Server.MCP.AllowedKeys,
		})
		log.Printf("DEV MODE: MCP server enabled")
	}

	log.Printf("DEV MODE assembled: %s", cfg.PrintSummary())

	return &Server{
		V1Router:    v1Router,
		AdminServer: adminSrv,
		GRPCServer:  grpcSrv,
		MCPServer:   mcpSrv,
		Core:        core,
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
	setVaultCryptoSuite(vault, cfg)

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

	// 启动 PG 健康检查（degraded 模式：PG 断连时写操作拒绝，缓存 DEK 仍可解密）。
	pgStore.StartHealthCheck(10 * time.Second)
	log.Printf("PG health check started (10s interval, degraded mode on disconnect)")

	// 启动回收站自动清理（90 天 TTL）。
	lifecycleMgr.StartSoftDeleteReaper(lifecycle.DefaultSoftDeleteTTL, nil)

	// 紧急封印联动：EmergencySeal 时同步清空 DEK 缓存。
	if vs, ok := unsealer.(*seal.VaultState); ok {
		vs.SetEmergencySealCallback(func() {
			lifecycleMgr.ClearCache()
		})
	}

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
				TenantID:       r.TenantID,
			}
			appAuth.RegisterPolicy(r.RoleID, r.Token, policy)
			policyStore.AddPolicy(policy)
		}
		authenticator = appAuth
		tenantCount := 0
		for _, r := range cfg.Auth.AppRoles {
			if r.TenantID != "" {
				tenantCount++
			}
		}
		if tenantCount > 0 {
			log.Printf("CLUSTER MODE: AppRole authenticator loaded with %d role(s) (%d tenant-scoped)", len(cfg.Auth.AppRoles), tenantCount)
		} else {
			log.Printf("CLUSTER MODE: AppRole authenticator loaded with %d role(s)", len(cfg.Auth.AppRoles))
		}
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

	// 3. 加载 K8s SA 认证（如果配置）。
	var k8sAuth *auth.K8sAuthenticator
	if cfg.Auth.K8s.Enabled {
		mappings := make(map[string]auth.K8sRoleMapping, len(cfg.Auth.K8s.RoleMapping))
		for sa, m := range cfg.Auth.K8s.RoleMapping {
			mappings[sa] = auth.K8sRoleMapping{
				RoleID:         m.RoleID,
				AllowedKeys:    m.AllowedKeys,
				AllowedActions: m.AllowedActions,
			}
		}
		k8sAuth, err = auth.NewK8sAuthenticator(auth.K8sAuthConfig{
			Issuer:      cfg.Auth.K8s.Issuer,
			Audience:    cfg.Auth.K8s.Audience,
			RoleMapping: mappings,
			JWKSURL:     cfg.Auth.K8s.JWKSURL,
		})
		if err != nil {
			auditLog.Close()
			_ = pgStore.Close(ctx)
			panic(fmt.Sprintf("FATAL: K8s authenticator init failed: %v", err))
		}
		log.Printf("CLUSTER MODE: K8s SA authenticator loaded (%d mappings, issuer=%s)",
			len(mappings), cfg.Auth.K8s.Issuer)
	}

	// 多认证器链：AppRole + JWT + K8s（按顺序尝试）。
	if k8sAuth != nil {
		authenticator = auth.NewMultiAuthenticator(authenticator, k8sAuth)
		log.Printf("CLUSTER MODE: MultiAuthenticator enabled (existing + K8s SA)")
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

	// Core service 层。
	core := service.NewManager(lifecycleMgr, unsealer, auditLog)
	core.SetAdminToken(cfg.Server.Admin.AdminToken)

	// v1.3: MFA TOTP 装配（内存存储，生产可换 PG 实现）。
	if cfg.MFA.Enabled {
		mfaStore := auth.NewMemoryMFAStore()
		v1Router.SetMFAStore(mfaStore)
		log.Printf("MFA TOTP enabled (issuer=%s)", cfg.MFA.Issuer)
	}

	// v1.3: Quorum Approval 装配（内存存储，生产可换 PG 实现）。
	approvalStore := auth.NewMemoryApprovalStore()
	v1Router.SetApprovalStore(approvalStore)
	log.Printf("Quorum Approval store initialized")

	// v1.3: OpenTelemetry tracing 装配。
	if cfg.Observability.Tracing.Enabled {
		v1Router.SetTracingEnabled(true)
		log.Printf("OTel tracing enabled on V1Router")
	}

	// gRPC server（含 mTLS，复用 HTTP 的 TLSConfig）。
	// BUG-18 修复：Cluster 模式下 gRPC 必须启用 TLS，明文暴露视为配置错误。
	var grpcSrv *grpc.Server
	if cfg.Server.GRPC.Enabled {
		grpcTLS, tlsErr := config.BuildTLSConfig(cfg.Server.GRPC.TLS)
		if tlsErr != nil {
			log.Fatalf("bootstrap: gRPC TLS config error: %v", tlsErr)
		}
		if cfg.Mode == "cluster" && grpcTLS == nil {
			log.Fatalf("bootstrap: gRPC TLS must be enabled in cluster mode (refusing to start plaintext gRPC)")
		}
		grpcSrv = buildGRPCServer(core, authenticator, unsealer, grpcTLS)
		log.Printf("gRPC server enabled at %s:%d (TLS=%v)", cfg.Server.GRPC.BindAddr, cfg.Server.GRPC.BindPort, grpcTLS != nil)
	}

	// MCP server。
	var mcpSrv *mcp.Server
	if cfg.Server.MCP.Enabled {
		if cfg.Server.MCP.Token == "" {
			return nil, errors.New("bootstrap: mcp.token is required when mcp.enabled=true")
		}
		mcpSrv = mcp.NewServer(core, mcp.Config{
			Token:       cfg.Server.MCP.Token,
			AllowedKeys: cfg.Server.MCP.AllowedKeys,
		})
		log.Printf("MCP server enabled (stdio=%v, http=%s:%d)", cfg.Server.MCP.Stdio, cfg.Server.MCP.HTTPBindAddr, cfg.Server.MCP.HTTPBindPort)
	}

	return &Server{
		V1Router:       v1Router,
		AdminServer:    adminSrv,
		GRPCServer:     grpcSrv,
		MCPServer:      mcpSrv,
		Core:           core,
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
		srv := admin.NewServer(unsealer)
		if cfg.Server.Admin.AdminToken != "" {
			srv.SetAdminToken(cfg.Server.Admin.AdminToken)
		}
		return srv
	}

	// Cluster 模式按配置。
	if !cfg.Server.Admin.Enabled {
		log.Printf("admin web UI disabled by config")
		return nil
	}

	log.Printf("admin web UI enabled at %s:%d", cfg.Server.Admin.BindAddr, cfg.Server.Admin.BindPort)
	srv := admin.NewServer(unsealer)
	if cfg.Server.Admin.AdminToken != "" {
		srv.SetAdminToken(cfg.Server.Admin.AdminToken)
		log.Printf("admin web UI: Basic Auth enabled (admin_token configured)")
	} else {
		log.Printf("WARNING: admin web UI has no admin_token — UNPROTECTED (bind 127.0.0.1 only)")
	}
	return srv
}
