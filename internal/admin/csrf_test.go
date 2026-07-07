// Package admin - CSRF 校验单元测试（v1.4.2）。
//
// 模式：double-submit cookie
//  1. 服务端首次访问页面时 Set-Cookie yvonne_csrf=<nonce>
//  2. 前端从 cookie 读 csrf token，写到请求 body (或 header X-CSRF-Token)
//  3. 服务端比较 cookie 和 body，必须一致
//  4. GET / HEAD / OPTIONS 跳过（按 OWASP 建议）
//
// 安全：
//   - Cookie 路径 /admin，HttpOnly=false（前端需要读），Secure=true
//   - SameSite=Strict 防跨站
//   - 攻击者无法读 cookie → 无法在第三方页构造一致请求
package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCSRPServer() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/login", func(w http.ResponseWriter, r *http.Request) {
		SetCSRFCookie(w, "test-nonce-abc")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/admin/api/login", CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})).ServeHTTP)
	return mux
}

func TestCSRF_SetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetCSRFCookie(w, "test-nonce-xyz")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "yvonne_csrf" {
		t.Fatalf("cookie name: %q", c.Name)
	}
	if c.Value != "test-nonce-xyz" {
		t.Fatalf("cookie value: %q", c.Value)
	}
	if c.HttpOnly {
		t.Error("cookie should be HttpOnly=false (frontend needs to read)")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite: got %v want Strict", c.SameSite)
	}
	if c.Path != "/admin" {
		t.Errorf("cookie path: got %q want /admin", c.Path)
	}
}

func TestCSRF_GenerateNonce(t *testing.T) {
	n1, err := GenerateCSRFNonce()
	if err != nil {
		t.Fatalf("GenerateCSRFNonce: %v", err)
	}
	n2, _ := GenerateCSRFNonce()
	if n1 == n2 {
		t.Fatal("nonce should not collide")
	}
	if len(n1) < 32 {
		t.Fatalf("nonce too short: %d", len(n1))
	}
}

func TestCSRFProtect_GETSkipped(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/api/x", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for %s, got %d", method, w.Code)
			}
		})
	}
}

func TestCSRFProtect_MissingCookie_403(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/admin/api/login", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCSRFProtect_MissingHeader_403(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/admin/api/login", nil)
	req.AddCookie(&http.Cookie{Name: "yvonne_csrf", Value: "cookie-token"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCSRFProtect_Mismatch_403(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/admin/api/login", nil)
	req.AddCookie(&http.Cookie{Name: "yvonne_csrf", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "different-header-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCSRFProtect_Match_200(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest("POST", "/admin/api/login", nil)
	req.AddCookie(&http.Cookie{Name: "yvonne_csrf", Value: "matching-token"})
	req.Header.Set("X-CSRF-Token", "matching-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestCSRFProtect_ConstantTimeCompare(t *testing.T) {
	// 即使 token 完全不匹配，CSRFProtect 不应 panic
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// 极端情况：超长 token
	longToken := make([]byte, 10000)
	for i := range longToken {
		longToken[i] = 'A'
	}
	req := httptest.NewRequest("POST", "/admin/api/login", nil)
	req.AddCookie(&http.Cookie{Name: "yvonne_csrf", Value: string(longToken)})
	req.Header.Set("X-CSRF-Token", "short")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}
