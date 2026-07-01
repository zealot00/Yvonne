// Package api - 速率限制中间件（按 IP 令牌桶）。
//
// 防止暴力枚举 Token / 密钥 ID 等攻击。
// 策略：每个真实客户端 IP 独立桶，默认 10 req/s，突发 20。
//
// Bug-3 修复: 支持反向代理 X-Forwarded-For + 授信代理 IP 白名单，
// 避免在 Nginx/K8s Ingress 后端所有请求共享同一令牌桶导致全局误杀。
package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter 是按 IP 的令牌桶限流器。
type RateLimiter struct {
	mu             sync.Mutex
	buckets        map[string]*tokenBucket
	rate           float64         // 每秒令牌数
	burst          int             // 桶容量
	lastClean      time.Time       // 上次清理时间
	trustedProxies map[string]bool // Bug-3: 授信反向代理 IP 白名单
}

// tokenBucket 是单 IP 的令牌桶。
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter 创建限流器。
// rate: 每秒补充的令牌数；burst: 桶最大容量（突发上限）。
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		buckets:        make(map[string]*tokenBucket),
		rate:           rate,
		burst:          burst,
		lastClean:      time.Now(),
		trustedProxies: nil, // 默认无授信代理，回退到 RemoteAddr
	}
}

// SetTrustedProxies 设置授信反向代理 IP 白名单（Bug-3 修复）。
//
// 仅当 RemoteAddr 在白名单内时，才信任 X-Forwarded-For / X-Real-IP 头。
// 防止非授信客户端伪造 X-Forwarded-For 绕过限流。
//
// 默认空 = 不信任任何代理头，回退到 RemoteAddr（向后兼容）。
func (rl *RateLimiter) SetTrustedProxies(proxies []string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.trustedProxies = make(map[string]bool, len(proxies))
	for _, p := range proxies {
		rl.trustedProxies[p] = true
	}
}

// Allow 检查指定 IP 是否允许通过（消耗 1 令牌）。
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// 定期清理过期桶（防止内存泄漏）。
	if time.Since(rl.lastClean) > 5*time.Minute {
		for k, b := range rl.buckets {
			if time.Since(b.last) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.lastClean = time.Now()
	}

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &tokenBucket{
			tokens: float64(rl.burst),
			last:   now,
		}
		rl.buckets[ip] = b
	}

	// 补充令牌。
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// clientIPFromRequest 从请求提取真实客户端 IP（Bug-3 修复：授信代理白名单）。
//
// 仅当 directRemoteAddr 在 trustedProxies 白名单内时，才信任 X-Forwarded-For / X-Real-IP。
// 否则回退到 directRemoteAddr（防伪造）。
//
// 参数:
//   - req: HTTP 请求
//   - directRemoteAddr: req.RemoteAddr（网关直连 IP）
//   - trustedProxies: 授信代理 IP 集合（nil/空 = 不信任任何代理头）
func clientIPFromRequest(req *http.Request, directRemoteAddr string, trustedProxies map[string]bool) string {
	// 提取直连 IP（RemoteAddr 的 host 部分）。
	directHost := directRemoteAddr
	if host, _, err := net.SplitHostPort(directRemoteAddr); err == nil {
		directHost = host
	}

	// 仅授信代理才信任 X-Forwarded-For / X-Real-IP。
	if len(trustedProxies) > 0 && trustedProxies[directHost] {
		// X-Forwarded-For（反向代理链，第一个是真实客户端）。
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		// X-Real-IP（Nginx 常用）。
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// 回退到直连 IP。
	return directHost
}

// clientIP 从请求提取真实客户端 IP（RateLimiter 实例方法，Bug-3 修复）。
// 优先取 X-Forwarded-For 第一个 IP（仅授信代理），其次 X-Real-IP，最后 RemoteAddr。
func (rl *RateLimiter) clientIP(req *http.Request) string {
	return clientIPFromRequest(req, req.RemoteAddr, rl.trustedProxies)
}

// clientIP 旧版包级函数（向后兼容，无授信代理校验）。
// 已废弃：请使用 RateLimiter.clientIP 或 clientIPFromRequest。
func clientIP(req *http.Request) string {
	return clientIPFromRequest(req, req.RemoteAddr, nil)
}

// Middleware 返回 HTTP 中间件，按 IP 限流。
// 超限返回 429 Too Many Requests。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := rl.clientIP(req)
		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, req)
	})
}
