package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCORS_AllowAll 验证通配符 Origin 允许。
func TestCORS_AllowAll(t *testing.T) {
	mw := CORSMiddleware(DefaultCORSConfig())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("ACAO = %q, want https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORS_OptionsPreflight 验证 OPTIONS 预检返回 204。
func TestCORS_OptionsPreflight(t *testing.T) {
	mw := CORSMiddleware(DefaultCORSConfig())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("OPTIONS should not call next handler")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS: got %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("ACAM should be set")
	}
}

// TestCORS_DisallowedOrigin 验证不允许的 Origin 不加 CORS 头。
func TestCORS_DisallowedOrigin(t *testing.T) {
	mw := CORSMiddleware(CORSConfig{
		AllowedOrigins: []string{"https://allowed.com"},
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disallowed origin should not get CORS headers")
	}
}

// TestCORS_NoOrigin 验证无 Origin 头不加 CORS。
func TestCORS_NoOrigin(t *testing.T) {
	mw := CORSMiddleware(DefaultCORSConfig())
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// 不设 Origin
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no Origin header should not get CORS headers")
	}
}
