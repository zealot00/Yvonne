package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/auth"
)

// TestAuthorizeBodyKeyID_NilPolicy Dev 模式放行。
func TestAuthorizeBodyKeyID_NilPolicy(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// 无 Policy 注入。
	if !authorizeBodyKeyID(req, "any-key") {
		t.Fatal("nil policy should allow all (Dev mode)")
	}
}

// TestAuthorizeBodyKeyID_Allowed Policy 允许。
func TestAuthorizeBodyKeyID_Allowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := auth.WithPolicy(req.Context(), &auth.Policy{
		RoleID:      "test",
		AllowedKeys: []string{"order-*"},
	})
	req = req.WithContext(ctx)

	if !authorizeBodyKeyID(req, "order-001") {
		t.Fatal("order-* should allow order-001")
	}
}

// TestAuthorizeBodyKeyID_Denied Policy 拒绝。
func TestAuthorizeBodyKeyID_Denied(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := auth.WithPolicy(req.Context(), &auth.Policy{
		RoleID:      "test",
		AllowedKeys: []string{"order-*"},
	})
	req = req.WithContext(ctx)

	if authorizeBodyKeyID(req, "payment-key") {
		t.Fatal("order-* should deny payment-key")
	}
}

// TestAuthorizeBodyKeyIDWithDetail_NilPolicy Dev 模式放行。
func TestAuthorizeBodyKeyIDWithDetail_NilPolicy(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := authorizeBodyKeyIDWithDetail(req, "any-key"); err != nil {
		t.Fatalf("nil policy should allow: %v", err)
	}
}

// TestAuthorizeBodyKeyIDWithDetail_Denied 拒绝含详情。
func TestAuthorizeBodyKeyIDWithDetail_Denied(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := auth.WithPolicy(req.Context(), &auth.Policy{
		RoleID:         "order-service",
		AllowedKeys:    []string{"order-*"},
		AllowedActions: []string{"Encrypt"},
	})
	req = req.WithContext(ctx)

	err := authorizeBodyKeyIDWithDetail(req, "payment-key")
	if err == nil {
		t.Fatal("should deny payment-key")
	}
}

// TestRequireMethod_Get GET 方法匹配。
func TestRequireMethod(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if !requireMethod(rec, req, http.MethodGet) {
		t.Fatal("GET should pass")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Code = %d, want 200", rec.Code)
	}

	// 方法不匹配。
	rec2 := httptest.NewRecorder()
	if requireMethod(rec2, req, http.MethodPost) {
		t.Fatal("GET should not pass POST check")
	}
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Code = %d, want 405", rec2.Code)
	}
}

// TestWriteJSONOK 成功响应格式。
func TestWriteJSONOK(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONOK(rec, map[string]string{"key": "value"})

	if rec.Code != http.StatusOK {
		t.Fatalf("Code = %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !contains(body, `"ok":true`) {
		t.Fatalf("body should contain ok:true: %s", body)
	}
	if !contains(body, `"key":"value"`) {
		t.Fatalf("body should contain data: %s", body)
	}
}

// TestWriteJSONError 错误响应格式。
func TestWriteJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, http.StatusForbidden, "access denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Code = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, `"ok":false`) {
		t.Fatalf("body should contain ok:false: %s", body)
	}
	if !contains(body, "access denied") {
		t.Fatalf("body should contain error: %s", body)
	}
}

// TestWriteJSON_SecurityHeaders 安全头。
func TestWriteJSON_SecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, nil)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing Referrer-Policy")
	}
}

// TestLoopbackOnly_AllowLoopback 127.0.0.1 放行。
func TestLoopbackOnly_AllowLoopback(t *testing.T) {
	r := &V1Router{}
	handler := r.loopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback should pass: %d", rec.Code)
	}
}

// TestLoopbackOnly_DenyNonLoopback 非 loopback 拒绝。
func TestLoopbackOnly_DenyNonLoopback(t *testing.T) {
	r := &V1Router{}
	handler := r.loopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("should not call handler")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback should be 403: %d", rec.Code)
	}
}

// TestLoopbackOnly_EmptyRemoteAddr 空地址放行（httptest 兼容）。
func TestLoopbackOnly_EmptyRemoteAddr(t *testing.T) {
	r := &V1Router{}
	called := false
	handler := r.loopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "" // httptest 场景
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("empty RemoteAddr should pass")
	}
}

// TestV1Router_SetRateLimit 设置限流参数。
func TestV1Router_SetRateLimit(t *testing.T) {
	r := &V1Router{}
	r.rateLimiter = NewRateLimiter(10, 20)
	r.SetRateLimit(100, 200)

	// 验证新限流器生效（100 req/s burst 200）。
	for i := 0; i < 200; i++ {
		if !r.rateLimiter.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed (burst=200)", i)
		}
	}
}

// TestStatusRecorder_Flush 透传 Flush。
func TestStatusRecorder_Flush(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}
	// httptest.ResponseRecorder 实现了 Flusher。
	sr.Flush() // 不应 panic
}

// TestStatusRecorder_Hijack 不支持时返回 error。
func TestStatusRecorder_Hijack_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}
	_, _, err := sr.Hijack()
	if err == nil {
		t.Fatal("Hijack should fail on httptest recorder")
	}
}

// TestStatusRecorder_Push_NotSupported 不支持时返回 error。
func TestStatusRecorder_Push_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}
	err := sr.Push("/test", nil)
	if err == nil {
		t.Fatal("Push should fail on httptest recorder")
	}
}

// TestCORSMiddleware_AllowAll CORS 通配符。
func TestCORSMiddleware_AllowAll(t *testing.T) {
	mw := CORSMiddleware(DefaultCORSConfig())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("ACAO = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORSMiddleware_OptionsPreflight OPTIONS 预检。
func TestCORSMiddleware_OptionsPreflight(t *testing.T) {
	mw := CORSMiddleware(DefaultCORSConfig())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("OPTIONS should not call next handler")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS Code = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("ACAM should be set")
	}
}

// contains 简易字符串包含。
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// 确保 context 引用。
var _ = context.Background
