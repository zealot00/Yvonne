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
	"sync"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/seal"
)

//go:embed web/static/* web/index.html web/login.html
var staticFS embed.FS

// 确保 context 包被引用。
var _ = context.Background

// Server 是管理页面的 HTTP 服务器。
type Server struct {
	seal       seal.Unsealer
	manager    keyLister // 可选：密钥列表查询
	adminToken string
	mux        *http.ServeMux
	apiHandler http.Handler // 可选：V1Router 引用（转发 API 请求）

	// v1.4.2: 双因子登录 / session / 设备 token
	totpSecret    string       // 从 YVONNE_ADMIN_TOTP_SECRET 读；空时跳过 TOTP
	sessionSecret []byte       // 设备指纹 HMAC salt
	sessions      SessionStore // session 存储
	captchaStore  CaptchaStore // 验证码存储
	loginStates   LoginStateStore
	devices       DeviceStore
	auditor       audit.Auditor // 审计（可空）

	devMode       bool // true 时启用 /admin/api/_dev_captcha_text 及空 token 自动放行（仅 dev 模式）
	secureCookies bool // 生产模式强制 Cookie Secure=true

	idleTimeout time.Duration // 默认 30 min
	hardCap     time.Duration // 默认 8 h

	// TOTP 防重放（支持集群共享 KVStore 或进程内内存回退）
	totpReplay TOTPReplayStore
	totpUsedMu sync.Mutex
	totpUsed   map[string]time.Time
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

// SetAPIHandler 注入 V1Router 用于转发 API 请求（加密/解密等）。
func (s *Server) SetAPIHandler(h http.Handler) {
	s.apiHandler = h
}

// =====================================================================
// v1.4.2 Setter（bootstrap 接线用）
// =====================================================================

// SetTOTPSecret 设置 TOTP secret（base32）。空 → 跳过 TOTP 校验。
func (s *Server) SetTOTPSecret(secret string) {
	s.totpSecret = secret
}

// SetSessionSecret 设置 session 加密 salt（≥32 字节）。
func (s *Server) SetSessionSecret(b []byte) {
	s.sessionSecret = b
}

// SetSessionStore 注入 session 存储。
func (s *Server) SetSessionStore(store SessionStore) {
	s.sessions = store
}

// SetCaptchaStore 注入 captcha 存储。
func (s *Server) SetCaptchaStore(store CaptchaStore) {
	s.captchaStore = store
}

// SetLoginStateStore 注入登录失败计数存储。
func (s *Server) SetLoginStateStore(store LoginStateStore) {
	s.loginStates = store
}

// SetDeviceStore 注入设备 token 存储。
func (s *Server) SetDeviceStore(store DeviceStore) {
	s.devices = store
}

// SetAuditor 注入审计 logger。
func (s *Server) SetAuditor(a audit.Auditor) {
	s.auditor = a
}

// SetIdleTimeout 设置 session idle 超时（默认 30 min）。
func (s *Server) SetIdleTimeout(d time.Duration) {
	s.idleTimeout = d
}

// SetHardCap 设置 session hard cap（默认 8 h）。
func (s *Server) SetHardCap(d time.Duration) {
	s.hardCap = d
}

// SetDevMode 启用 dev mode（暴露 _dev_captcha_text 等调试端点，并允许空 adminToken 免认证）。
// 生产环境必须 false（空 adminToken 时强制拒绝）。
func (s *Server) SetDevMode(b bool) {
	s.devMode = b
}

// SetSecureCookies 设置会话/设备/CSRF Cookie 的 Secure 属性（生产模式应设为 true）。
func (s *Server) SetSecureCookies(b bool) {
	s.secureCookies = b
}

// SecureCookies 返回当前是否启用 Secure Cookie。
func (s *Server) SecureCookies() bool {
	return s.secureCookies
}

// SetTOTPReplayStore 注入 TOTP 防重放存储（集群模式注入 KVTOTPReplayStore）。
func (s *Server) SetTOTPReplayStore(store TOTPReplayStore) {
	s.totpReplay = store
}

// StartReaper 启动后台清理 goroutine，返回 stop 函数。
func (s *Server) StartReaper(interval time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case now := <-ticker.C:
				if s.sessions != nil {
					_ = s.sessions.Reap(now)
				}
				if s.captchaStore != nil {
					_ = s.captchaStore.Reap(now)
				}
				if s.devices != nil {
					_ = s.devices.Reap(now)
				}
				if s.totpReplay != nil {
					_ = s.totpReplay.Reap(now)
				}
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(stop) }
}

// requireAdminToken 已废弃（v1.4.2）：请用 sessionOrBearer 替代。
// 保留作为 Bearer-only 兼容路径（curl / 自动化），不强制 session。
func (s *Server) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if s.adminToken == "" {
			if s.devMode {
				next(w, req)
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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

// sessionHandlerFn 把接受 *Session 的 handler 转成 http.Handler（从 ctx 取出）。
type sessionHandlerFn func(w http.ResponseWriter, r *http.Request, sess *Session)

func (s *Server) withSession(h sessionHandlerFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		h(w, r, sess)
	}
}

func (s *Server) register() {
	// 静态资源：/static/* 来自 embed.FS
	staticRoot, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		panic("admin: embed static fs: " + err.Error())
	}
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))

	// 页面路由：根路径返回 SPA index.html（由前端 JS 决定登录/主界面）。
	s.mux.HandleFunc("/", s.handleIndex)

	// v1.4.2: 登录入口（不需要 session）
	s.mux.HandleFunc("/admin/login", s.handleLoginPage)
	s.mux.HandleFunc("/admin/api/captcha", s.handleCaptcha)
	s.mux.HandleFunc("/admin/api/_dev_captcha_text", s.handleDevCaptchaText) // dev only
	// 登录本身需要 CSRF（双提交 cookie）
	s.mux.Handle("/admin/api/login", CSRFProtect(http.HandlerFunc(s.handleLogin)))

	// v1.4.2: 注销 / 会话信息 / 设备撤销（需 session + CSRF for state-changing）
	s.mux.Handle("/admin/api/logout",
		CSRFProtect(s.sessionOrBearer(http.HandlerFunc(s.handleLogout))))
	s.mux.Handle("/admin/api/session",
		s.sessionOrBearer(http.HandlerFunc(s.withSession(s.handleSession))))
	s.mux.Handle("/admin/api/device",
		CSRFProtect(s.sessionOrBearer(http.HandlerFunc(s.handleDeviceRevoke))))

	// 受保护 API（向后兼容 Bearer 自动化路径）。
	// seal-status 公开（用于探活/概览）。
	s.mux.HandleFunc("/admin/api/seal-status", s.handleSealStatus)
	// 其他需 session 或 Bearer。
	s.mux.Handle("/admin/api/keys", s.sessionOrBearer(http.HandlerFunc(s.handleAPIKeys)))
	s.mux.Handle("/admin/api/crypto/encrypt", s.sessionOrBearer(http.HandlerFunc(s.handleAPIEncrypt)))
	s.mux.Handle("/admin/api/crypto/decrypt", s.sessionOrBearer(http.HandlerFunc(s.handleAPIDecrypt)))
	s.mux.Handle("/admin/api/audit", s.sessionOrBearer(http.HandlerFunc(s.handleAPIAudit)))
	s.mux.Handle("/admin/api/dashboard", s.sessionOrBearer(http.HandlerFunc(s.handleAPIDashboard)))
	s.mux.Handle("/admin/api/seal", s.sessionOrBearer(http.HandlerFunc(s.handleSeal)))
	s.mux.Handle("/admin/api/unseal", s.sessionOrBearer(http.HandlerFunc(s.handleUnseal)))
}

// ServeHTTP 实现 http.Handler（v1.4.2：移除双层 auth）。
// 顶层不再做 Basic/Bearer 拦截；统一在 register() 用 sessionOrBearer/CSRFProtect 包裹。
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// 统一安全响应头。
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://rsms.me; img-src 'self' data:; font-src 'self' https://rsms.me data:; connect-src 'self'")

	s.mux.ServeHTTP(w, req)
}
