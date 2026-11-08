// Package admin - CSRF 保护（v1.4.2）。
//
// 模式：double-submit cookie（OWASP 推荐，比同步 token 简单）。
//
// 流程：
//  1. 首次访问页面 → Set-Cookie yvonne_csrf=<nonce> (HttpOnly=false, Secure, SameSite=Strict)
//  2. 前端从 document.cookie 读 csrf token，写到请求 header X-CSRF-Token
//  3. CSRFProtect 中间件：cookie 值 vs header 值，必须一致
//  4. 不一致 → 403 Forbidden
//
// 豁免：GET / HEAD / OPTIONS（按 OWASP）
//
// 安全边界：
//   - 攻击者在第三方域无法读 cookie（浏览器 SameSite=Strict 阻止）→ 无法伪造
//   - Cookie 不设 HttpOnly=false 仅因为前端 JS 需要读（见 SetCSRFCookie）
//   - 实际部署必须 HTTPS（Secure flag 在 dev 模式 httptest 下不强制）
package admin

import (
	"crypto/subtle"
	"net/http"
)

// CSRF cookie 名 / header 名（前后端约定）。
const (
	CSRFCookieName = "yvonne_csrf"
	CSRFHeaderName = "X-CSRF-Token"
	CSRFCookiePath = "/admin"
	CSRFNonceBytes = 32
)

// SetCSRFCookie 设置 CSRF cookie（默认 Secure=false，兼容单元测试与 dev 模式）。
// 生产环境应通过 SetCSRFCookieWithSecure(w, nonce, true) 设置 Secure=true。
func SetCSRFCookie(w http.ResponseWriter, nonce string) {
	SetCSRFCookieWithSecure(w, nonce, false)
}

// SetCSRFCookieWithSecure 设置 CSRF cookie，由调用方指定 Secure 属性。
func SetCSRFCookieWithSecure(w http.ResponseWriter, nonce string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    nonce,
		Path:     CSRFCookiePath,
		HttpOnly: false, // 前端 JS 需要读
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// GenerateCSRFNonce 生成 32 字节随机 nonce → base64url。
func GenerateCSRFNonce() (string, error) {
	return randomID(CSRFNonceBytes)
}

// CSRFProtect double-submit cookie 中间件。
// 对非安全方法强制要求 cookie 和 header 一致。
func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 安全方法跳过
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		// 取 cookie
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			writeCSRFError(w, "missing csrf cookie")
			return
		}

		// 取 header
		header := r.Header.Get(CSRFHeaderName)
		if header == "" {
			writeCSRFError(w, "missing csrf header")
			return
		}

		// constant-time 比较
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeCSRFError(w, "csrf token mismatch")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeCSRFError(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"ok":false,"error":"csrf_failed","reason":"` + reason + `"}`))
}
