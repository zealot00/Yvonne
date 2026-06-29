// Package api - CORS 跨域集成测试。
//
// 模拟浏览器跨域请求的完整流程：
//  1. OPTIONS 预检（Preflight）
//  2. 实际请求（POST/GET）
//  3. Origin 白名单校验
//  4. 允许的 Methods/Headers
//  5. 不允许的 Origin 拒绝
//  6. Credentials 模式
package api

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newCORSTestRouter 创建 CORS 测试 router（Dev 模式 + 自定义 CORS）。
func newCORSTestRouter(t *testing.T, corsCfg CORSConfig) *V1Router {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	router.SetCORSConfig(corsCfg)

	// 创建测试密钥。
	mgr.CreateKey(context.Background(), "cors-test-key", seal.NewSoftwareKEK(mk), 0)

	return router
}

// === OPTIONS 预检测试 ===

// TestCORS_Preflight_AllowAllOrigin Dev 模式 "*" Origin 允许所有。
func TestCORS_Preflight_AllowAllOrigin(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("preflight status = %d, want 204", w.Code)
	}
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://example.com" {
		t.Fatalf("Allow-Origin = %q, want %q", origin, "http://example.com")
	}
	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods == "" {
		t.Fatal("Allow-Methods should not be empty")
	}
	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers == "" {
		t.Fatal("Allow-Headers should not be empty")
	}
	t.Logf("✅ Preflight: 204, Allow-Origin=%s, Methods=%s", origin, methods)
}

// TestCORS_Preflight_SpecificOrigin 白名单 Origin 匹配。
func TestCORS_Preflight_SpecificOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com", "https://admin.example.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}
	router := newCORSTestRouter(t, cfg)

	// 允许的 Origin。
	req := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("Allow-Origin = %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("Allow-Credentials should be true")
	}
	t.Log("✅ Preflight specific origin: allowed")
}

// TestCORS_Preflight_DisallowedOrigin 白名单外的 Origin 不返回 CORS 头。
func TestCORS_Preflight_DisallowedOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Authorization"},
	}
	router := newCORSTestRouter(t, cfg)

	req := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 不允许的 Origin 不返回 Allow-Origin 头。
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Fatalf("disallowed origin should not get Allow-Origin, got %q", origin)
	}
	t.Log("✅ Preflight disallowed origin: no CORS headers")
}

// TestCORS_Preflight_NoOrigin 无 Origin 头不返回 CORS。
func TestCORS_Preflight_NoOrigin(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	// 不设 Origin
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no Origin header should not get Allow-Origin")
	}
	t.Log("✅ Preflight no Origin: no CORS headers")
}

// === 实际请求（非预检）CORS 头测试 ===

// TestCORS_ActualRequest_POST POST 请求带 CORS 头。
func TestCORS_ActualRequest_POST(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("POST", "/api/v1/sys/health", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://example.com" {
		t.Fatalf("actual request Allow-Origin = %q, want %q", origin, "http://example.com")
	}
	t.Logf("✅ Actual POST: Allow-Origin=%s, status=%d", origin, w.Code)
}

// TestCORS_ActualRequest_GET GET 请求带 CORS 头。
func TestCORS_ActualRequest_GET(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("GET", "/api/v1/sys/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://localhost:3000" {
		t.Fatalf("actual GET Allow-Origin = %q, want %q", origin, "http://localhost:3000")
	}
	t.Logf("✅ Actual GET: Allow-Origin=%s", origin)
}

// TestCORS_ActualRequest_DisallowedOrigin 实际请求白名单外不返回 CORS 头。
func TestCORS_ActualRequest_DisallowedOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}
	router := newCORSTestRouter(t, cfg)

	req := httptest.NewRequest("GET", "/api/v1/sys/health", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin should not get CORS headers in actual request")
	}
	t.Log("✅ Actual request disallowed origin: no CORS headers")
}

// TestCORS_ActualRequest_NoOrigin 无 Origin 不返回 CORS。
func TestCORS_ActualRequest_NoOrigin(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("GET", "/api/v1/sys/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no Origin should not get CORS headers")
	}
	t.Log("✅ Actual request no Origin: no CORS headers")
}

// === Credentials 模式测试 ===

// TestCORS_CredentialsMode AllowCredentials=true 返回正确头。
func TestCORS_CredentialsMode(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization"},
	}
	router := newCORSTestRouter(t, cfg)

	req := httptest.NewRequest("POST", "/api/v1/sys/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("Allow-Credentials should be true")
	}
	t.Log("✅ Credentials mode: Allow-Credentials=true")
}

// TestCORS_NoCredentials AllowCredentials=false 不返回 Credentials 头。
func TestCORS_NoCredentials(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	req := httptest.NewRequest("POST", "/api/v1/sys/health", nil)
	req.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("Allow-Credentials should not be set in default mode")
	}
	t.Log("✅ No credentials: Allow-Credentials not set")
}

// === 完整浏览器流程模拟 ===

// TestCORS_BrowserFlow_Full 浏览器完整流程：预检 → 实际请求。
func TestCORS_BrowserFlow_Full(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           600,
	}
	router := newCORSTestRouter(t, cfg)

	// 1. 浏览器发送预检请求。
	preflightReq := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	preflightReq.Header.Set("Origin", "https://app.example.com")
	preflightReq.Header.Set("Access-Control-Request-Method", "POST")
	preflightReq.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	preflightW := httptest.NewRecorder()
	router.ServeHTTP(preflightW, preflightReq)

	if preflightW.Code != 204 {
		t.Fatalf("preflight status = %d, want 204", preflightW.Code)
	}
	if preflightW.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatal("preflight: wrong Allow-Origin")
	}
	if preflightW.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("preflight: missing Allow-Credentials")
	}
	t.Log("✅ Step 1: Preflight passed")

	// 2. 浏览器发送实际 POST 请求。
	actualReq := httptest.NewRequest("POST", "/api/v1/sys/health", nil)
	actualReq.Header.Set("Origin", "https://app.example.com")
	actualReq.Header.Set("Content-Type", "application/json")
	actualW := httptest.NewRecorder()
	router.ServeHTTP(actualW, actualReq)

	if actualW.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatal("actual request: wrong Allow-Origin")
	}
	if actualW.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("actual request: missing Allow-Credentials")
	}
	t.Log("✅ Step 2: Actual request passed")

	// 3. 浏览器读取响应（CORS 头允许 JS 读取）。
	t.Log("✅ Full browser flow: preflight → actual request → JS readable")
}

// TestCORS_BrowserFlow_Disallowed 浏览器跨域被拒绝（Origin 不在白名单）。
func TestCORS_BrowserFlow_Disallowed(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}
	router := newCORSTestRouter(t, cfg)

	// 预检被拒。
	req := httptest.NewRequest("OPTIONS", "/api/v1/encrypt", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin should not get CORS headers")
	}

	// 浏览器 JS 会阻止实际请求发送（预检失败）。
	t.Log("✅ Browser flow disallowed: preflight rejected, browser blocks actual request")
}

// TestCORS_AllMethods 所有 HTTP 方法都带 CORS 头。
func TestCORS_AllMethods(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/v1/sys/health", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		origin := w.Header().Get("Access-Control-Allow-Origin")
		if origin != "http://example.com" {
			t.Fatalf("method %s: Allow-Origin = %q", method, origin)
		}
	}
	t.Log("✅ All HTTP methods: CORS headers present")
}

// TestCORS_WildcardOrigin Dev 模式 "*" 允许所有 Origin。
func TestCORS_WildcardOrigin(t *testing.T) {
	router := newCORSTestRouter(t, DefaultCORSConfig())

	origins := []string{
		"http://localhost:3000",
		"http://example.com",
		"https://app.example.com",
		"http://192.168.1.1:8080",
	}

	for _, origin := range origins {
		req := httptest.NewRequest("GET", "/api/v1/sys/health", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		got := w.Header().Get("Access-Control-Allow-Origin")
		if got != origin {
			t.Fatalf("wildcard origin %q: Allow-Origin = %q", origin, got)
		}
	}
	t.Log("✅ Wildcard origin: all origins allowed in Dev mode")
}
