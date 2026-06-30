// Package api - v1 API 路由（终极蓝图对齐版）。
//
// 路由清单：
//
//	GET  /api/v1/sys/health        健康检查
//	POST /api/v1/sys/unseal        提交 Shamir 碎片
//	POST /api/v1/keys              创建业务密钥
//	POST /api/v1/keys/{id}/rotate  轮转密钥
//	DELETE /api/v1/keys/{id}/shred 物理粉碎密钥
//	POST /api/v1/encrypt           信封加密
//	POST /api/v1/decrypt           信封解密
//	GET  /metrics                  Prometheus 指标
package api

import (
	"net"
	"net/http"
	"strings"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/service"
)

// V1Router 是 v1 API 路由器。
type V1Router struct {
	seal          seal.Unsealer
	auditLog      audit.Auditor
	manager       *lifecycle.Manager
	core          *service.Core // v1.2.2: Sign/Verify/ReEncrypt 用
	metrics       *metrics.Registry
	authenticator auth.Authenticator
	adminToken    string
	transitMgr    *lifecycle.TransitKeyManager
	auditDir      string // 审计日志目录（查询用），可为空
	rateLimiter   *RateLimiter
	mux           *http.ServeMux
	mfaStore      auth.MFAStore      // v1.3: MFA TOTP 存储
	approvalStore auth.ApprovalStore // v1.3: Quorum 审批存储
}

// NewV1Router 创建 v1 路由。
// authenticator 为 nil 时跳过认证（Dev 模式）。
// adminToken 为空时紧急封印接口返回 403。
func NewV1Router(s seal.Unsealer, auditLog audit.Auditor, mgr *lifecycle.Manager, reg *metrics.Registry, authenticator auth.Authenticator) *V1Router {
	r := &V1Router{
		seal:          s,
		auditLog:      auditLog,
		manager:       mgr,
		core:          service.NewCore(mgr, s, auditLog), // v1.2.2: 注入 Core
		metrics:       reg,
		authenticator: authenticator,
		transitMgr:    lifecycle.NewTransitKeyManager(),
		rateLimiter:   NewRateLimiter(100, 1000), // 默认 100 req/s，突发 1000（测试友好）
		mux:           http.NewServeMux(),
	}
	r.register()
	return r
}

// SetRateLimit 调整速率限制参数。
func (r *V1Router) SetRateLimit(rate float64, burst int) {
	r.rateLimiter = NewRateLimiter(rate, burst)
}

// SetAdminToken 设置紧急封印 Admin Token。
func (r *V1Router) SetAdminToken(token string) {
	r.adminToken = token
}

// SetMFAStore 设置 MFA 存储（v1.3）。
func (r *V1Router) SetMFAStore(store auth.MFAStore) {
	r.mfaStore = store
}

// SetApprovalStore 设置审批存储（v1.3）。
func (r *V1Router) SetApprovalStore(store auth.ApprovalStore) {
	r.approvalStore = store
}

func (r *V1Router) register() {
	// 系统管理（health 不走 auditMiddleware，避免探活流量污染审计日志）。
	r.mux.HandleFunc("/api/v1/sys/health", r.handleHealth)
	r.mux.HandleFunc("/api/v1/sys/unseal", r.auditMiddleware("Unseal", r.handleSysUnseal))
	r.mux.HandleFunc("/api/v1/sys/panic", r.auditMiddleware("EmergencySeal", r.handleEmergencySeal))

	// 密钥生命周期（需认证 + Unsealed）。
	r.mux.HandleFunc("/api/v1/keys", r.auditMiddleware("CreateKey", r.authAndSeal("CreateKey", r.handleCreateKey)))
	r.mux.HandleFunc("/api/v1/keys/transit-pub", r.auditMiddleware("TransitKey", r.handleTransitPub))
	r.mux.HandleFunc("/api/v1/keys/import", r.auditMiddleware("ImportKey", r.authAndSeal("ImportKey", r.handleImportKey)))
	r.mux.HandleFunc("/api/v1/keys/", r.auditMiddleware("KeyOp", r.authAndSeal("KeyOp", r.handleKeyOps)))

	// 审计日志查询（需认证 + AuditQuery action 权限）。
	r.mux.HandleFunc("/api/v1/audit/query", r.auditMiddleware("AuditQuery", r.authAndSeal("AuditQuery", r.handleAuditQuery)))

	// 密码学运算（需认证 + Unsealed）。
	r.mux.HandleFunc("/api/v1/encrypt", r.auditMiddleware("Encrypt", r.authAndSeal("Encrypt", r.handleV1Encrypt)))
	r.mux.HandleFunc("/api/v1/decrypt", r.auditMiddleware("Decrypt", r.authAndSeal("Decrypt", r.handleV1Decrypt)))

	// v1.2 新增路由。
	r.mux.HandleFunc("/api/v1/sign", r.auditMiddleware("Sign", r.authAndSeal("Sign", r.handleV1Sign)))
	r.mux.HandleFunc("/api/v1/verify", r.auditMiddleware("Verify", r.authAndSeal("Verify", r.handleV1Verify)))
	r.mux.HandleFunc("/api/v1/mac/generate", r.auditMiddleware("GenerateMac", r.authAndSeal("GenerateMac", r.handleV1GenerateMac)))
	r.mux.HandleFunc("/api/v1/mac/verify", r.auditMiddleware("VerifyMac", r.authAndSeal("VerifyMac", r.handleV1VerifyMac)))
	r.mux.HandleFunc("/api/v1/re-encrypt", r.auditMiddleware("ReEncrypt", r.authAndSeal("ReEncrypt", r.handleV1ReEncrypt)))
	r.mux.HandleFunc("/api/v1/keys/gdk-no-plaintext", r.auditMiddleware("GenerateDataKeyWithoutPlaintext", r.authAndSeal("KeyOp", r.handleV1GDKWithoutPlaintext)))
	r.mux.HandleFunc("/api/v1/keys/public-key", r.auditMiddleware("GetPublicKey", r.authAndSeal("KeyOp", r.handleV1GetPublicKey)))

	// v1.2.2 新增：非对称密钥创建。
	r.mux.HandleFunc("/api/v1/keys/asymmetric", r.auditMiddleware("CreateAsymmetricKey", r.authAndSeal("KeyOp", r.handleCreateAsymmetricKey)))

	// v1.3 新增：MFA TOTP。
	r.mux.HandleFunc("/api/v1/auth/mfa/setup", r.auditMiddleware("MFASetup", r.RequireAuth(r.authenticator, "MFASetup", r.handleMFASetup)))
	r.mux.HandleFunc("/api/v1/auth/mfa/verify", r.auditMiddleware("MFAVerify", r.RequireAuth(r.authenticator, "MFAVerify", r.handleMFAVerify)))
	r.mux.HandleFunc("/api/v1/auth/mfa/disable", r.auditMiddleware("MFADisable", r.RequireAuth(r.authenticator, "MFADisable", r.handleMFADisable)))

	// v1.3 新增：Quorum Approval。
	r.mux.HandleFunc("/api/v1/approvals", r.auditMiddleware("Approval", r.RequireAuth(r.authenticator, "Approval", r.handleApprovals)))
	r.mux.HandleFunc("/api/v1/approvals/approve", r.auditMiddleware("ApprovalApprove", r.RequireAuth(r.authenticator, "ApprovalApprove", r.handleApprove)))
	r.mux.HandleFunc("/api/v1/approvals/reject", r.auditMiddleware("ApprovalReject", r.RequireAuth(r.authenticator, "ApprovalReject", r.handleReject)))

	// 可观测性。
	// metrics 含内部状态（请求量/延迟/失败率），生产应认证保护。
	// Cluster 模式有 authenticator → 包裹 RequireAuth("Metrics")。
	// Dev 模式无 authenticator → 仅允许 127.0.0.1 loopback 访问。
	if r.metrics != nil {
		if r.authenticator != nil {
			r.mux.Handle("/metrics", r.auditMiddleware("Metrics", r.RequireAuth(r.authenticator, "Metrics", metricsHandler(r.metrics).ServeHTTP)))
		} else {
			r.mux.Handle("/metrics", r.loopbackOnly(metricsHandler(r.metrics)))
		}
	}
}

// loopbackOnly 限制仅 127.0.0.1 / ::1 可访问（Dev 模式防护）。
// RemoteAddr 为空时放行（兼容 httptest 等无网络地址的测试场景）。
func (r *V1Router) loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if host == "" {
			// 无 RemoteAddr（httptest 内联测试），放行。
			next.ServeHTTP(w, req)
			return
		}
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			writeJSONError(w, http.StatusForbidden, "metrics endpoint allows loopback only")
			return
		}
		next.ServeHTTP(w, req)
	})
}

// authAndSeal 组合认证 + Sealed 检查。
// 若 authenticator 为 nil（Dev 模式），跳过认证只检查 Sealed。
func (r *V1Router) authAndSeal(action string, next http.HandlerFunc) http.HandlerFunc {
	handler := next
	if r.authenticator != nil {
		handler = r.RequireAuth(r.authenticator, action, next)
	}
	return r.requireUnsealedV1(handler)
}

func metricsHandler(reg *metrics.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		reg.ServeHTTP(w, req)
	})
}

// maxRequestBodyBytes 限制请求体大小（1MB），防止内存耗尽 DoS。
// 加密/解密请求的密文 + plaintext base64 不会超过 1MB（业务大 payload 应用 GDK）。
const maxRequestBodyBytes = 1 << 20 // 1MB

// corsConfig 是全局 CORS 配置（ServeHTTP 用）。
var corsConfig = DefaultCORSConfig()

// SetCORSConfig 设置全局 CORS 配置（Cluster 模式应覆盖默认 "*" 配置）。
func (r *V1Router) SetCORSConfig(cfg CORSConfig) {
	corsConfig = cfg
}

func (r *V1Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// 最外层：IP 级速率限制（防暴力枚举）。
	if r.rateLimiter != nil {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if !r.rateLimiter.Allow(host) {
			w.Header().Set("Retry-After", "1")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
	}

	// 全局请求体大小限制（防内存耗尽 DoS）。
	// GET 请求无 body 不受影响；POST/PUT/PATCH/DELETE 请求体被限制为 1MB。
	if req.Body != nil {
		req.Body = http.MaxBytesReader(w, req.Body, maxRequestBodyBytes)
	}

	// CORS 处理：所有请求（含预检 + 实际请求）都加 CORS 头。
	origin := req.Header.Get("Origin")
	if origin != "" && isOriginAllowed(origin, corsConfig.AllowedOrigins) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsConfig.AllowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsConfig.AllowedHeaders, ", "))
		if corsConfig.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Max-Age", "600")
	}

	// CORS 预检短路：OPTIONS 请求不路由到 mux。
	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	r.mux.ServeHTTP(w, req)
}

// requireUnsealedV1 拒绝 Sealed/EmergencySealed 状态下的业务请求，返回 503。
func (r *V1Router) requireUnsealedV1(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if r.seal.IsEmergencySealed() {
			writeJSONError(w, http.StatusServiceUnavailable, "vault is emergency sealed")
			return
		}
		if r.seal.IsSealed() {
			writeJSONError(w, http.StatusServiceUnavailable, "kms is sealed")
			return
		}
		next(w, req)
	}
}
