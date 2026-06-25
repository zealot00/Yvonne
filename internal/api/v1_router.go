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
	"net/http"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
)

// V1Router 是 v1 API 路由器。
type V1Router struct {
	seal          seal.Unsealer
	auditLog      audit.Auditor
	manager       *lifecycle.Manager
	metrics       *metrics.Registry
	authenticator auth.Authenticator
	adminToken    string
	transitMgr    *lifecycle.TransitKeyManager
	auditDir      string // 审计日志目录（查询用），可为空
	mux           *http.ServeMux
}

// NewV1Router 创建 v1 路由。
// authenticator 为 nil 时跳过认证（Dev 模式）。
// adminToken 为空时紧急封印接口返回 403。
func NewV1Router(s seal.Unsealer, auditLog audit.Auditor, mgr *lifecycle.Manager, reg *metrics.Registry, authenticator auth.Authenticator) *V1Router {
	r := &V1Router{
		seal:          s,
		auditLog:      auditLog,
		manager:       mgr,
		metrics:       reg,
		authenticator: authenticator,
		transitMgr:    lifecycle.NewTransitKeyManager(),
		mux:           http.NewServeMux(),
	}
	r.register()
	return r
}

// SetAdminToken 设置紧急封印 Admin Token。
func (r *V1Router) SetAdminToken(token string) {
	r.adminToken = token
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

	// 可观测性。
	if r.metrics != nil {
		r.mux.Handle("/metrics", metricsHandler(r.metrics))
	}
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

func (r *V1Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
