package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestRateLimiter_AllowsWithinBurst 验证突发请求通过。
func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := NewRateLimiter(1, 5) // 1 req/s, burst 5
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}
}

// TestRateLimiter_RejectsOverBurst 验证超突发被拒。
func TestRateLimiter_RejectsOverBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
		rl.Allow("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th request should be rejected (over burst)")
	}
}

// TestRateLimiter_DifferentIPsIndependent 验证不同 IP 独立限流。
func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := NewRateLimiter(1, 2)
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	// 1.1.1.1 已耗尽，但 2.2.2.2 仍可。
	if !rl.Allow("2.2.2.2") {
		t.Fatal("different IP should be independent")
	}
}

// TestRateLimiter_Middleware 验证中间件 429 响应。
func TestRateLimiter_Middleware(t *testing.T) {
	rl := NewRateLimiter(1, 2)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 前 2 个 200。
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}

	// 第 3 个 429。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request: got %d, want 429", rec.Code)
	}
}

// TestRateLimiter_ConcurrentSafe 验证并发安全。
func TestRateLimiter_ConcurrentSafe(t *testing.T) {
	rl := NewRateLimiter(100, 100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Allow("10.0.0.1")
		}()
	}
	wg.Wait()
}
