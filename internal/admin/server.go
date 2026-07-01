// Package admin 提供 Yvonne KMS 的最基本 Web 管理页面。
//
// 设计原则（最小可用版）：
//   - 仅 4 个视图：登录、概览（Seal 状态）、Unseal、密钥列表。
//   - 所有静态资源 embed 进二进制，无外部依赖。
//   - 默认只绑 127.0.0.1；生产环境通过反向代理 + mTLS 暴露。
//   - 严禁显示任何明文密钥；列表仅展示 KeyID / 状态 / 版本 / 算法。
//
// 后续扩展（不在本期）：
//   - AppRole / JWT 登录流程
//   - 密钥创建 / 轮转 / 销毁操作
//   - 审计日志查询
package admin

import (
	"context"
	"crypto/subtle"
	"embed"
	"io/fs"
	"net/http"

	"yvonne/internal/seal"
)

//go:embed web/static/* web/index.html web/app.js
var staticFS embed.FS

// 确保 context 包被引用。
var _ = context.Background

// Server 是管理页面的 HTTP 服务器。
type Server struct {
	seal       seal.Unsealer
	manager    keyLister // 可选：密钥列表查询
	adminToken string
	mux        *http.ServeMux
}

// keyLister 是 admin 查询密钥列表所需的最小接口。
type keyLister interface {
	ListKeyIDs(ctx context.Context) ([]string, error)
}

// NewServer 创建管理页面 Server。Sealed 状态下也允许访问（否则无法 Unseal）。
func NewServer(s seal.Unsealer) *Server {
	srv := &Server{
		seal: s,
		mux:  http.NewServeMux(),
	}
	srv.register()
	return srv
}

// SetAdminToken 设置管理操作认证 Token。
// 设置后 /admin/api/seal 和 /admin/api/unseal 需要 `Authorization: Bearer <token>`。
// seal-status 和静态资源不需认证（用于查看状态）。
func (s *Server) SetAdminToken(token string) {
	s.adminToken = token
}

// SetManager 注入 lifecycle.Manager 用于密钥列表查询。
func (s *Server) SetManager(mgr keyLister) {
	s.manager = mgr
}

func (s *Server) register() {
	// 静态资源：/static/* 来自 embed.FS
	// Go 1.21 ServeMux 不支持 "GET /path" 方法前缀，用 path 注册 + handler 内检查 Method。
	staticRoot, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		panic("admin: embed static fs: " + err.Error())
	}
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))

	// v1.3.1: Vue SPA 资源。
	s.mux.HandleFunc("/app.js", s.handleSPAFile("web/app.js", "application/javascript"))

	// 页面路由：返回入口 HTML，由前端 JS 调用 /api/* 与 /sys/*。
	s.mux.HandleFunc("/", s.handleIndex)

	// 管理页面 API。
	// seal-status 不需认证（用于探活/概览）。
	s.mux.HandleFunc("/admin/api/seal-status", s.handleSealStatus)
	// keys 列表需认证（含密钥元数据）。
	s.mux.HandleFunc("/admin/api/keys", s.requireAdminToken(s.handleAPIKeys))
	// v1.3.1: Web 控制台 API。
	s.mux.HandleFunc("/admin/api/crypto/encrypt", s.requireAdminToken(s.handleAPIEncrypt))
	s.mux.HandleFunc("/admin/api/crypto/decrypt", s.requireAdminToken(s.handleAPIDecrypt))
	s.mux.HandleFunc("/admin/api/audit", s.requireAdminToken(s.handleAPIAudit))
	s.mux.HandleFunc("/admin/api/dashboard", s.requireAdminToken(s.handleAPIDashboard))
	// seal/unseal 需要认证（如果设置了 adminToken）。
	s.mux.HandleFunc("/admin/api/seal", s.requireAdminToken(s.handleSeal))
	s.mux.HandleFunc("/admin/api/unseal", s.requireAdminToken(s.handleUnseal))
}

// handleSPAFile 返回内嵌的 SPA 文件。
func (s *Server) handleSPAFile(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		data, err := staticFS.ReadFile(path)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	}
}

// requireAdminToken 包装 handler，要求 Bearer Token 认证。
// adminToken 为空时跳过认证（向后兼容 Dev 模式）。
func (s *Server) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if s.adminToken == "" {
			next(w, req)
			return
		}
		auth := req.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, req)
	}
}

// ServeHTTP 实现 http.Handler。
// 若设置了 adminToken，所有请求（含页面）必须通过 Basic Auth 或 Bearer Token。
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// 统一安全响应头。
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

	// 若设置了 adminToken，强制全站认证（含页面 + API + 静态资源）。
	if s.adminToken != "" {
		if !s.authenticate(req) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Yvonne Admin"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}
	s.mux.ServeHTTP(w, req)
}

// authenticate 支持两种认证方式：
// 1. Basic Auth: username 任意，password = adminToken
// 2. Bearer Token: Authorization: Bearer <adminToken>
func (s *Server) authenticate(req *http.Request) bool {
	// 尝试 Basic Auth。
	if user, pass, ok := req.BasicAuth(); ok {
		// username 不校验（任意），password 必须等于 adminToken。
		if subtle.ConstantTimeCompare([]byte(pass), []byte(s.adminToken)) == 1 {
			_ = user // username 不参与校验
			return true
		}
		return false
	}
	// 尝试 Bearer Token。
	auth := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) == 1 {
			return true
		}
	}
	return false
}
