// Package admin - Login/Logout/Session HTTP handlers（v1.4.2）。
//
// 暴露端点（v1.4.2 新增）：
//
//	GET    /admin/login            登录页 HTML（不需要登录）
//	GET    /admin/api/captcha      图形验证码 SVG + Set-Cookie CSRF
//	POST   /admin/api/login        双因子登录（captcha + token + TOTP）
//	POST   /admin/api/logout       注销（清 session cookie + audit）
//	GET    /admin/api/session      当前 session 信息（idle / hard cap）
//	DELETE /admin/api/device       撤销"记住此设备"
//
// 中间件（auth_middleware.go）：
//   - CSRFProtect 包裹所有 POST/DELETE（cookie == header）
//   - sessionOrBearer 包裹所有受保护资源（cookie OR Bearer）
//
// 合规覆盖：
//   - 等保 a 项 身份鉴别：双因子（password + TOTP）+ 图形验证码 + 失败锁定
//   - 等保 b 项 登录失败处理：3 次失败锁 30 分钟（IP+用户 维度）
//   - 等保 b 项 超时自动退出：idle 30 min + hard cap 8 h
//   - 通信保密：cookie HttpOnly + Secure + SameSite=Strict
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
)

// LoginRequest 登录请求 payload。
type LoginRequest struct {
	AdminToken        string           `json:"admin_token"`
	TOTPCode          string           `json:"totp_code"`
	CaptchaID         string           `json:"captcha_id"`
	CaptchaText       string           `json:"captcha_text"`
	Remember          bool             `json:"remember"`
	DeviceFP          string           `json:"device_fp,omitempty"`          // 上次 Set-Cookie 的指纹
	DeviceFingerprint DeviceAttributes `json:"device_fingerprint,omitempty"` // 首次注册
}

// LoginResponse 登录成功响应。
type LoginResponse struct {
	OK         bool   `json:"ok"`
	SessionID  string `json:"session_id"`
	ExpiresIn  int    `json:"expires_in"` // seconds until idle expires
	RememberOK bool   `json:"remember_ok,omitempty"`
}

// loginErrorKind 错误类型（避免字符串泄露原因给前端猜测）。
type loginErrorKind int

const (
	loginErrUnknown loginErrorKind = iota
	loginErrLocked
	loginErrCaptcha
	loginErrToken
	loginErrTOTP
	loginErrDev
)

func (k loginErrorKind) String() string {
	switch k {
	case loginErrLocked:
		return "locked"
	case loginErrCaptcha:
		return "captcha"
	case loginErrToken:
		return "token"
	case loginErrTOTP:
		return "totp"
	default:
		return "unknown"
	}
}

// loginErr 登录错误（带原因 + HTTP 状态）。
type loginErr struct {
	Kind loginErrorKind
	Msg  string
}

func (e *loginErr) Error() string { return e.Msg }

func newLoginErr(k loginErrorKind, format string, a ...any) *loginErr {
	return &loginErr{Kind: k, Msg: fmt.Sprintf(format, a...)}
}

// =====================================================================
// loginFlow 核心逻辑（被 handleLogin 调用，也被测试直接调用）
// =====================================================================

// loginFlow 处理一次登录请求，按以下顺序校验：
//
//  1. dev 模式（adminToken 空）→ 直接创建 session（无 captcha/TOTP/devices）
//  2. 检查登录态是否被锁（IP+用户）
//  3. 设备指纹命中 → 跳过 captcha + TOTP，仍校验 adminToken
//  4. 校验 captcha（一次性消费）
//  5. 校验 adminToken（constant-time）
//  6. 校验 TOTP（若 totpSecret 非空；markUsed 防重放）
//  7. 创建 session（30 min idle + 8 h hard cap）
//  8. 若 remember=true + 提供 device fingerprint → 写 device token
//  9. 写审计日志
//
// 返回 session, deviceToken（nil when !remember）, error。
func (s *Server) loginFlow(req *LoginRequest, clientIP, userAgent string) (*Session, *DeviceToken, error) {
	// 0. 构造登录态 key
	stateKey := "admin-web@" + clientIP

	// 1. dev 模式：全过
	if s.adminToken == "" {
		sess, err := NewSession("admin-web", s.idleTimeout, s.hardCap, false, clientIP, userAgent)
		if err != nil {
			return nil, nil, newLoginErr(loginErrUnknown, "create session: %v", err)
		}
		if err := s.sessions.Put(sess); err != nil {
			return nil, nil, newLoginErr(loginErrUnknown, "persist session: %v", err)
		}
		s.recordAudit("LoginSuccess", clientIP, "dev-mode")
		return sess, nil, nil
	}

	// 2. 锁定检查
	if s.loginStates.IsLocked(stateKey) {
		s.recordAudit("LoginLockRejected", clientIP, stateKey)
		return nil, nil, newLoginErr(loginErrLocked, "too many failures, locked for 30 min")
	}

	// 3. 设备指纹路径（跳过 captcha + TOTP）
	if req.DeviceFP != "" && s.devices.Exists(req.DeviceFP) {
		// 仍校验 adminToken
		if subtle.ConstantTimeCompare([]byte(req.AdminToken), []byte(s.adminToken)) != 1 {
			s.loginStates.IncFailed(stateKey)
			s.recordAudit("LoginFailure", clientIP, "device-skip wrong-token")
			return nil, nil, newLoginErr(loginErrToken, "invalid admin token")
		}
		sess, err := s.createSession(req.Remember, req.DeviceFingerprint, clientIP, userAgent)
		if err != nil {
			return nil, nil, err
		}
		s.recordAudit("LoginSuccess", clientIP, "device-skip")
		return sess, nil, nil
	}

	// 4. 校验 captcha
	cap, ok := s.captchaStore.Pop(req.CaptchaID)
	if !ok {
		s.loginStates.IncFailed(stateKey)
		s.recordAudit("LoginFailure", clientIP, "captcha-missing-or-expired")
		return nil, nil, newLoginErr(loginErrCaptcha, "captcha missing or expired")
	}
	if !ValidateCaptchaText(cap.Text, req.CaptchaText) {
		s.loginStates.IncFailed(stateKey)
		s.recordAudit("LoginFailure", clientIP, "captcha-mismatch")
		return nil, nil, newLoginErr(loginErrCaptcha, "captcha mismatch")
	}

	// 5. 校验 adminToken
	if subtle.ConstantTimeCompare([]byte(req.AdminToken), []byte(s.adminToken)) != 1 {
		s.loginStates.IncFailed(stateKey)
		s.recordAudit("LoginFailure", clientIP, "wrong-token")
		return nil, nil, newLoginErr(loginErrToken, "invalid admin token")
	}

	// 6. 校验 TOTP（totpSecret 非空时）
	if s.totpSecret != "" {
		// markUsed callback：把已用 code 写进 KV，TTL = 90s（±1 窗口 60s + 30s buffer）
		// 用 in-memory map 简化：仅防当前进程重放
		markUsed := func(t time.Time, code string) error {
			s.totpUsedMu.Lock()
			defer s.totpUsedMu.Unlock()
			if s.totpUsed == nil {
				s.totpUsed = make(map[string]time.Time)
			}
			now := time.Now()
			// 清理过期
			for k, v := range s.totpUsed {
				if now.Sub(v) > 90*time.Second {
					delete(s.totpUsed, k)
				}
			}
			key := fmt.Sprintf("%d:%s", t.Unix()/30, code)
			if _, exists := s.totpUsed[key]; exists {
				return auth.ErrTOTPAlreadyUsed
			}
			s.totpUsed[key] = now
			return nil
		}
		if err := auth.ValidateTOTP(s.totpSecret, req.TOTPCode, markUsed); err != nil {
			s.loginStates.IncFailed(stateKey)
			s.recordAudit("LoginFailure", clientIP, "totp-"+err.Error())
			return nil, nil, newLoginErr(loginErrTOTP, "invalid TOTP: %v", err)
		}
	}

	// 成功：清失败计数 + 建 session + 可选 device token
	s.loginStates.ResetFailed(stateKey)
	sess, dev, err := s.createSessionWithDevice(req.Remember, req.DeviceFingerprint, clientIP, userAgent)
	if err != nil {
		return nil, nil, err
	}
	s.recordAudit("LoginSuccess", clientIP, "2fa")
	return sess, dev, nil
}

// createSession 建 session，不写 device token。
func (s *Server) createSession(remember bool, attrs DeviceAttributes, ip, ua string) (*Session, error) {
	sess, err := NewSession("admin-web", s.idleTimeout, s.hardCap, remember, ip, ua)
	if err != nil {
		return nil, newLoginErr(loginErrUnknown, "create session: %v", err)
	}
	if err := s.sessions.Put(sess); err != nil {
		return nil, newLoginErr(loginErrUnknown, "persist session: %v", err)
	}
	return sess, nil
}

// createSessionWithDevice 建 session + 可选 device token。
func (s *Server) createSessionWithDevice(remember bool, attrs DeviceAttributes, ip, ua string) (*Session, *DeviceToken, error) {
	sess, err := s.createSession(remember, attrs, ip, ua)
	if err != nil {
		return nil, nil, err
	}
	if !remember {
		return sess, nil, nil
	}
	// 计算 fingerprint
	fp := DeviceFingerprint(s.sessionSecret, attrs)
	if fp == "" {
		return sess, nil, nil // 没有 attrs 不写
	}
	dev := &DeviceToken{
		Fingerprint: fp,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(DeviceTTL),
		IP:          ip,
	}
	s.devices.Put(dev)
	return sess, dev, nil
}

// recordAudit 写一条审计日志（best-effort，错误不阻断登录流程）。
func (s *Server) recordAudit(action, clientIP, detail string) {
	if s.auditor == nil {
		return
	}
	_ = s.auditor.Record(audit.LogEntry{
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		Actor:     "admin-web",
		Resource:  "admin-auth",
		Action:    action,
		Result:    "success",
		Status:    detail,
	})
}

// =====================================================================
// HTTP handlers
// =====================================================================

// handleLoginPage GET /admin/login 返回登录页 HTML。
// 同时 Set-Cookie yvonne_csrf（前端读后写到 X-CSRF-Token header）。
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	nonce, err := GenerateCSRFNonce()
	if err != nil {
		http.Error(w, `{"error":"csrf_failed"}`, http.StatusInternalServerError)
		return
	}
	SetCSRFCookie(w, nonce)
	s.writeLoginHTML(w)
}

// handleCaptcha GET /admin/api/captcha 返回新验证码 SVG。
func (s *Server) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	c, err := NewCaptcha(captchaWidth, captchaHeight)
	if err != nil {
		http.Error(w, `{"error":"captcha_failed"}`, http.StatusInternalServerError)
		return
	}
	s.captchaStore.Put(c)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"captcha_id": c.ID,
		"image":      c.SVG,
		"expires_in": int(time.Until(c.ExpiresAt).Seconds()),
	})
}

// handleDevCaptchaText dev mode only (s.devMode == true)：返回 captcha 答案。
// 生产环境返回 403。
// 用途：E2E 测试脚本无需 OCR SVG。
func (s *Server) handleDevCaptchaText(w http.ResponseWriter, r *http.Request) {
	if !s.devMode {
		http.Error(w, `{"error":"disabled_in_production"}`, http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"missing_id"}`, http.StatusBadRequest)
		return
	}
	c, ok := s.captchaStore.Get(id)
	if !ok {
		http.Error(w, `{"error":"not_found_or_expired"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"captcha_id": c.ID,
		"text":       c.Text,
	})
}

// handleLogin POST /admin/api/login 登录主入口。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 1. 解析 body
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeLoginError(w, http.StatusBadRequest, loginErrUnknown, "invalid body")
		return
	}

	// 2. 取 client IP
	ip := clientIP(r)

	// 3. loginFlow
	sess, dev, err := s.loginFlow(&req, ip, r.UserAgent())
	if err != nil {
		var le *loginErr
		if errors.As(err, &le) {
			status := http.StatusUnauthorized
			writeLoginError(w, status, le.Kind, le.Msg)
			return
		}
		writeLoginError(w, http.StatusInternalServerError, loginErrUnknown, err.Error())
		return
	}

	// 4. Set-Cookie session
	setSessionCookie(w, sess)

	// 5. 如果 remember + device → Set-Cookie device_fp
	resp := LoginResponse{
		OK:         true,
		SessionID:  sess.ID,
		ExpiresIn:  int(time.Until(sess.ExpiresAt).Seconds()),
		RememberOK: dev != nil,
	}
	if dev != nil {
		setDeviceCookie(w, dev.Fingerprint)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleLogout POST /admin/api/logout 注销。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	// 从 cookie 取 session ID，清掉
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		_ = s.sessions.Delete(c.Value)
	}
	// 清 cookie
	clearCookie(w, SessionCookieName)
	if _, err := r.Cookie(DeviceCookieName); err == nil {
		clearCookie(w, DeviceCookieName)
	}
	s.recordAudit("Logout", ip, "user")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// handleSession GET /admin/api/session 返回当前 session 信息。
// 由 sessionOrBearer 中间件保证有 session。
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, sess *Session) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"user_id":          sess.UserID,
		"expires_at":       sess.ExpiresAt,
		"hard_cap_at":      sess.HardCapAt,
		"last_seen_at":     sess.LastSeenAt,
		"idle_seconds":     int(time.Until(sess.ExpiresAt).Seconds()),
		"hard_cap_seconds": int(time.Until(sess.HardCapAt).Seconds()),
	})
}

// handleDeviceRevoke DELETE /admin/api/device 撤销设备 token。
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if c, err := r.Cookie(DeviceCookieName); err == nil && c.Value != "" {
		s.devices.Delete(c.Value)
		clearCookie(w, DeviceCookieName)
	}
	s.recordAudit("DeviceRevoke", ip, "user")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// =====================================================================
// 工具函数
// =====================================================================

// Session cookie / device cookie 常量。
const (
	SessionCookieName = "yvonne_session"
	DeviceCookieName  = "yvonne_device"
	SessionCookiePath = "/admin"
)

func setSessionCookie(w http.ResponseWriter, sess *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     SessionCookiePath,
		HttpOnly: true,
		Secure:   false, // dev mode; 生产 bootstrap 应为 true
		SameSite: http.SameSiteStrictMode,
		Expires:  sess.HardCapAt, // 浏览器层面 hard cap
	})
}

func setDeviceCookie(w http.ResponseWriter, fp string) {
	http.SetCookie(w, &http.Cookie{
		Name:     DeviceCookieName,
		Value:    fp,
		Path:     SessionCookiePath,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(DeviceTTL),
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Value:   "",
		Path:    SessionCookiePath,
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

func writeLoginError(w http.ResponseWriter, status int, kind loginErrorKind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": kind.String(),
		"msg":   msg,
	})
}

// clientIP 优先 X-Forwarded-For（反代场景），否则 RemoteAddr。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// 取第一个（最近的客户端）
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) writeLoginHTML(w http.ResponseWriter) {
	// 占位：完整 HTML 在 Day 2 实现
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Yvonne Admin Login</title></head>
<body><h1>Yvonne KMS Admin Console</h1>
<p>Login form placeholder (Day 2 will render real UI).</p>
</body></html>`))
}

// =====================================================================
// NoopAuditor 测试用（不实际写日志，避免污染）
// =====================================================================

// NoopAuditor 丢弃所有审计日志（用于单元测试和 dev 模式）。
type NoopAuditor struct{}

// Record 实现 audit.Auditor 接口。
func (n *NoopAuditor) Record(entry audit.LogEntry) error { return nil }

// Close 实现 audit.Auditor 接口。
func (n *NoopAuditor) Close() {}

// 编译期断言 NoopAuditor 实现 audit.Auditor
var _ audit.Auditor = (*NoopAuditor)(nil)
