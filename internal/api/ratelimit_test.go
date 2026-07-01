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

// TestRateLimiter_TrustedProxyXFF Bug-3: 授信代理白名单 + X-Forwarded-For。
// RemoteAddr 是授信代理 IP，应信任 X-Forwarded-For 中的真实客户端 IP。
func TestRateLimiter_TrustedProxyXFF(t *testing.T) {
	rl := NewRateLimiter(1, 2)
	rl.SetTrustedProxies([]string{"10.0.0.1"}) // Nginx 内网 IP

	// 两个不同真实客户端，通过同一代理 → 应各自独立限流。
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "10.0.0.1:5678" // 代理 IP
	req1.Header.Set("X-Forwarded-For", "203.0.113.1")

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "10.0.0.1:5678" // 同一代理
	req2.Header.Set("X-Forwarded-For", "203.0.113.2")

	ip1 := rl.clientIP(req1)
	ip2 := rl.clientIP(req2)

	if ip1 != "203.0.113.1" {
		t.Fatalf("Bug-3: trusted proxy XFF not respected, got ip1=%s", ip1)
	}
	if ip2 != "203.0.113.2" {
		t.Fatalf("Bug-3: trusted proxy XFF not respected, got ip2=%s", ip2)
	}
	if ip1 == ip2 {
		t.Fatal("Bug-3: different XFF IPs should be distinguished (was sharing bucket!)")
	}
	t.Logf("✅ Bug-3: trusted proxy XFF respected: %s, %s", ip1, ip2)
}

// TestRateLimiter_UntrustedProxyIgnoresXFF Bug-3: 非授信代理忽略 X-Forwarded-For。
// RemoteAddr 不在白名单，应忽略 XFF，用 RemoteAddr 防伪造。
func TestRateLimiter_UntrustedProxyIgnoresXFF(t *testing.T) {
	rl := NewRateLimiter(1, 2)
	rl.SetTrustedProxies([]string{"10.0.0.1"}) // 仅 10.0.0.1 授信

	// 攻击者直连，伪造 XFF。
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "evil.client:5678" // 非授信
	req.Header.Set("X-Forwarded-For", "fake-ip")

	ip := rl.clientIP(req)
	if ip == "fake-ip" {
		t.Fatal("Bug-3: untrusted proxy should NOT respect XFF (forgery succeeded!)")
	}
	if ip != "evil.client" {
		t.Fatalf("Bug-3: expected RemoteAddr 'evil.client', got %s", ip)
	}
	t.Logf("✅ Bug-3: untrusted proxy ignores XFF, uses RemoteAddr=%s", ip)
}

// TestRateLimiter_NoTrustedProxiesBackwardCompat Bug-3: 默认无授信代理，向后兼容。
// 不调用 SetTrustedProxies 时，行为与旧版一致（用 RemoteAddr）。
func TestRateLimiter_NoTrustedProxiesBackwardCompat(t *testing.T) {
	rl := NewRateLimiter(1, 2)
	// 不设置 SetTrustedProxies

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("X-Forwarded-For", "5.6.7.8") // 应被忽略

	ip := rl.clientIP(req)
	if ip != "1.2.3.4" {
		t.Fatalf("Bug-3 backward compat: expected '1.2.3.4', got %s", ip)
	}
	t.Logf("✅ Bug-3 backward compat: no trusted proxies → RemoteAddr=%s", ip)
}
