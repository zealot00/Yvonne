// Package admin - sessionOrBearer 中间件测试（v1.4.2）。
//
// 中间件优先级：
//  1. dev 模式（adminToken 空）→ 全过
//  2. Cookie session → 校验 session（idle + hard cap）→ 注入到 ctx
//  3. Bearer token → constant-time 比对 adminToken
//  4. 都没有 → 401
//
// 测试覆盖：
//  1. dev 模式跳过认证
//  2. Bearer token 通过（自动化 / curl）
//  3. Cookie session 通过（浏览器）
//  4. 错 Bearer → 401
//  5. 失效 session cookie → 401
//  6. session idle 超时 → 401
//  7. session hard cap 超时 → 401
//  8. 优先级：cookie 有效时忽略 Bearer
package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer 构造一个集成测试用 Server（HTTP 路由完整）。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		adminToken:    "test-admin-token",
		sessionSecret: []byte("test-session-secret-32-bytes-pad!"),
		sessions:      NewMemorySessionStore(),
		captchaStore:  NewMemoryCaptchaStore(),
		loginStates:   NewMemoryLoginStateStore(),
		devices:       NewMemoryDeviceStore(),
		auditor:       &NoopAuditor{},
		idleTimeout:   30 * time.Minute,
		hardCap:       8 * time.Hour,
	}
	s.mux = http.NewServeMux()
	return s
}

// protectedHandler 模拟一个受保护的资源（任何 auth_middleware 验证通过后访问）。
func (s *Server) protectedHandler(w http.ResponseWriter, r *http.Request) {
	sess := SessionFromContext(r.Context())
	if sess != nil {
		w.Write([]byte("session:" + sess.UserID))
		return
	}
	w.Write([]byte("bearer:ok"))
}

// middlewareTestHandler 套上 sessionOrBearer 的最终 handler。
func (s *Server) middlewareTestHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("protected:" + clientIP(r)))
}

func TestMiddleware_DevModeSkipsAuth(t *testing.T) {
	s := newTestServer(t)
	s.adminToken = "" // dev mode

	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("dev mode should skip auth, got %d", w.Code)
	}
}

func TestMiddleware_BearerTokenPasses(t *testing.T) {
	s := newTestServer(t)
	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.Header.Set("Authorization", "Bearer test-admin-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Bearer should pass, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMiddleware_WrongBearer_401(t *testing.T) {
	s := newTestServer(t)
	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong Bearer should be 401, got %d", w.Code)
	}
}

func TestMiddleware_NoAuth_401(t *testing.T) {
	s := newTestServer(t)
	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth should be 401, got %d", w.Code)
	}
}

func TestMiddleware_SessionCookiePasses(t *testing.T) {
	s := newTestServer(t)
	// 手动 Put 一个 session
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	s.sessions.Put(sess)

	handler := s.sessionOrBearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := SessionFromContext(r.Context())
		if got == nil {
			t.Error("session should be in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("session cookie should pass, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMiddleware_InvalidSessionCookie_401(t *testing.T) {
	s := newTestServer(t)
	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "nonexistent-session-id"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid session should be 401, got %d", w.Code)
	}
}

func TestMiddleware_IdleExpiredSession_401(t *testing.T) {
	s := newTestServer(t)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	s.sessions.Put(sess)
	// 把 session 拨成 31 分钟前 idle
	got, _ := s.sessions.Get(sess.ID)
	got.LastSeenAt = time.Now().Add(-31 * time.Minute)
	got.ExpiresAt = time.Now().Add(-1 * time.Minute)

	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("idle expired session should be 401, got %d", w.Code)
	}
}

func TestMiddleware_HardCapExpiredSession_401(t *testing.T) {
	s := newTestServer(t)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	s.sessions.Put(sess)
	// HardCapAt 拨到 1 秒前
	got, _ := s.sessions.Get(sess.ID)
	got.HardCapAt = time.Now().Add(-1 * time.Second)

	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("hard cap expired session should be 401, got %d", w.Code)
	}
}

func TestMiddleware_CookiePriority_IgnoresBearer(t *testing.T) {
	// session 有效时忽略 Bearer（cookie 优先）
	s := newTestServer(t)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	s.sessions.Put(sess)

	handler := s.sessionOrBearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := SessionFromContext(r.Context())
		if got == nil {
			t.Error("session should be in context (cookie priority)")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("cookie priority should ignore wrong Bearer, got %d", w.Code)
	}
}

func TestMiddleware_TouchRefreshesIdle(t *testing.T) {
	// session 有效时调用 middleware 应刷新 idle
	s := newTestServer(t)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test-ua")
	originalExpires := sess.ExpiresAt
	s.sessions.Put(sess)

	handler := s.sessionOrBearer(http.HandlerFunc(s.middlewareTestHandler))

	// sleep 一小段时间再请求，expires_at 应该被刷新
	time.Sleep(10 * time.Millisecond)
	req := httptest.NewRequest("GET", "/admin/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	updated, _ := s.sessions.Get(sess.ID)
	if !updated.ExpiresAt.After(originalExpires) {
		t.Fatalf("Touch should refresh expires_at: orig=%v new=%v", originalExpires, updated.ExpiresAt)
	}
}
