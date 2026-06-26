// Package api - 速率限制中间件（按 IP 令牌桶）。
//
// 防止暴力枚举 Token / 密钥 ID 等攻击。
// 策略：每个 RemoteAddr 独立桶，默认 10 req/s，突发 20。
package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter 是按 IP 的令牌桶限流器。
type RateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	rate      float64   // 每秒令牌数
	burst     int       // 桶容量
	lastClean time.Time // 上次清理时间
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
		buckets:   make(map[string]*tokenBucket),
		rate:      rate,
		burst:     burst,
		lastClean: time.Now(),
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

// Middleware 返回 HTTP 中间件，按 IP 限流。
// 超限返回 429 Too Many Requests。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		if !rl.Allow(host) {
			w.Header().Set("Retry-After", "1")
			writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, req)
	})
}
