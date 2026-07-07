// v1_router OCSP 路由注册测试（TDD 严格，先 RED）。
//
// 验证 SetOCSPHandler 注入的 handler 会被注册到 /api/v1/ocsp/ 前缀。
// 遵循 SetSDFHandler 既有模式（v1_router.go:105-108, 160-162）。
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
)

// TestSetOCSPHandler_NilByDefault 验证默认未注入时路由不存在（避免误暴露）。
func TestSetOCSPHandler_NilByDefault(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/anything", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 未注入 OCSP handler → mux 找不到路由 → Go 默认 404。
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when OCSP handler not injected, got %d", w.Code)
	}
}

// TestSetOCSPHandler_RoutesGET POST 验证注入后 GET /api/v1/ocsp/{base64} 能路由。
func TestSetOCSPHandler_RoutesGET(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	// 注入一个返回 200 + application/ocsp-response 的假 handler。
	router.SetOCSPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OCSP-RESPONSE"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/AAAA", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET OCSP: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("Content-Type: got %q, want application/ocsp-response", ct)
	}
	if w.Body.String() != "OCSP-RESPONSE" {
		t.Fatalf("body: got %q, want OCSP-RESPONSE", w.Body.String())
	}
	t.Log("✅ SetOCSPHandler routes GET /api/v1/ocsp/{base64}")
}

// TestSetOCSPHandler_RoutesPOST 验证 POST /api/v1/ocsp 也能路由。
func TestSetOCSPHandler_RoutesPOST(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	called := false
	router.SetOCSPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ocsp", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if !called {
		t.Fatal("OCSP handler should be called on POST")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("POST OCSP: got %d, want 200", w.Code)
	}
	t.Log("✅ SetOCSPHandler routes POST /api/v1/ocsp")
}

// TestSetOCSPHandler_OtherPathsUnaffected 验证注入 OCSP 不影响其他路由。
func TestSetOCSPHandler_OtherPathsUnaffected(t *testing.T) {
	router, _, _ := newPKITestRouter(t)
	router.SetOCSPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// /api/v1/sys/health 应该仍由 router 自身处理。
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sys/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/api/v1/sys/health should still work: got %d", w.Code)
	}
	t.Log("✅ SetOCSPHandler does not affect other routes")
}

// 引用包以确保 import 抖动被检测。
var (
	_ = lifecycle.CertStateActive
	_ = memguard.GenerateSecureRandom
)
