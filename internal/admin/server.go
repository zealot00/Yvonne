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
	"crypto/subtle"
	"embed"
	"io/fs"
	"net/http"

	"yvonne/internal/seal"
)

//go:embed web/static/*
var staticFS embed.FS

// Server 是管理页面的 HTTP 服务器。
type Server struct {
	seal       seal.Unsealer
	adminToken string
	mux        *http.ServeMux
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

func (s *Server) register() {
	// 静态资源：/static/* 来自 embed.FS
	// Go 1.21 ServeMux 不支持 "GET /path" 方法前缀，用 path 注册 + handler 内检查 Method。
	staticRoot, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		panic("admin: embed static fs: " + err.Error())
	}
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))

	// 页面路由：返回入口 HTML，由前端 JS 调用 /api/* 与 /sys/*。
	s.mux.HandleFunc("/", s.handleIndex)

	// 管理页面 API。
	// seal-status 不需认证（用于探活/概览）。
	s.mux.HandleFunc("/admin/api/seal-status", s.handleSealStatus)
	// seal/unseal 需要认证（如果设置了 adminToken）。
	s.mux.HandleFunc("/admin/api/seal", s.requireAdminToken(s.handleSeal))
	s.mux.HandleFunc("/admin/api/unseal", s.requireAdminToken(s.handleUnseal))
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
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// 统一安全响应头。
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	s.mux.ServeHTTP(w, req)
}
