// Package admin - 认证中间件（v1.4.2）。
//
// sessionOrBearer 中间件：替换旧的 requireAdminToken
// 优先级：
//  1. dev 模式（adminToken 空）→ 直接通过
//  2. Cookie yvonne_session → 校验 idle + hard cap → 注入 context → 200
//  3. Authorization: Bearer <adminToken> → constant-time 比对 → 200
//  4. 都没有 → 401
//
// 关联：handleSession 用 SessionFromContext 取出 session 注入响应。
package admin

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"
)

// sessionContextKey context key（避免和其它包的 key 冲突）。
type sessionContextKey struct{}

// SessionFromContext 从 context 取出 session（middleware 注入）。
// 不存在返回 nil（说明是 Bearer 路径，未注入 session）。
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionContextKey{}).(*Session)
	return s
}

// sessionOrBearer 中间件：Cookie 优先，Bearer 兜底。
func (s *Server) sessionOrBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. 仅在显式 dev 模式且未配 token 时放行；生产环境空 token 强制拒绝（fail-closed）
		if s.adminToken == "" {
			if s.devMode {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// 2. Cookie 路径（浏览器）
		if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
			if _, ok := s.sessions.Get(c.Value); !ok {
				http.Error(w, `{"ok":false,"error":"session_expired"}`, http.StatusUnauthorized)
				return
			}
			// Touch 刷新 idle
			now := time.Now()
			_ = s.sessions.Touch(c.Value, now, now.Add(s.idleTimeout))
			updated, _ := s.sessions.Get(c.Value)
			// 注入 context
			ctx := context.WithValue(r.Context(), sessionContextKey{}, updated)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 3. Bearer 路径（curl / Selenium CDP / 服务对服务）
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
			token := authHeader[len(prefix):]
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 4. 都没 → 401
		http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
	})
}
