// Package yvonne - Go SDK 重试/熔断/trace_id 透传。
package yvonne

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// RetryConfig 重试配置。
type RetryConfig struct {
	MaxRetries      int           // 最大重试次数（0=不重试）
	InitialBackoff  time.Duration // 初始退避
	MaxBackoff      time.Duration // 最大退避
	RetryableStatus map[int]bool  // 可重试的 HTTP 状态码
}

// DefaultRetryConfig 默认重试配置。
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:      3,
		InitialBackoff:  100 * time.Millisecond,
		MaxBackoff:      5 * time.Second,
		RetryableStatus: map[int]bool{502: true, 503: true, 504: true},
	}
}

// CircuitBreakerConfig 熔断器配置。
type CircuitBreakerConfig struct {
	FailureThreshold int           // 连续失败次数阈值
	ResetTimeout     time.Duration // 熔断后恢复等待时间
}

// DefaultCircuitBreakerConfig 默认熔断配置。
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureThreshold: 10,
		ResetTimeout:     60 * time.Second,
	}
}

// circuitState 熔断器状态。
type circuitState int32

const (
	circuitClosed   circuitState = 0 // 正常
	circuitOpen     circuitState = 1 // 熔断
	circuitHalfOpen circuitState = 2 // 半开
)

// CircuitBreaker 熔断器。
type CircuitBreaker struct {
	config          *CircuitBreakerConfig
	state           atomic.Int32
	failureCount    atomic.Int64
	lastFailureTime atomic.Int64
	mu              sync.Mutex
}

// NewCircuitBreaker 创建熔断器。
func NewCircuitBreaker(cfg *CircuitBreakerConfig) *CircuitBreaker {
	if cfg == nil {
		cfg = DefaultCircuitBreakerConfig()
	}
	return &CircuitBreaker{config: cfg}
}

// Allow 检查是否允许请求。
func (cb *CircuitBreaker) Allow() bool {
	state := circuitState(cb.state.Load())
	switch state {
	case circuitClosed:
		return true
	case circuitOpen:
		// 检查是否过了恢复时间。
		lastFail := time.Unix(0, cb.lastFailureTime.Load())
		if time.Since(lastFail) > cb.config.ResetTimeout {
			// 切换到半开状态。
			if cb.state.CompareAndSwap(int32(circuitOpen), int32(circuitHalfOpen)) {
				return true
			}
			return false
		}
		return false
	case circuitHalfOpen:
		return true
	default:
		return true
	}
}

// RecordSuccess 记录成功。
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failureCount.Store(0)
	cb.state.Store(int32(circuitClosed))
}

// RecordFailure 记录失败。
func (cb *CircuitBreaker) RecordFailure() {
	count := cb.failureCount.Add(1)
	cb.lastFailureTime.Store(time.Now().UnixNano())

	if count >= int64(cb.config.FailureThreshold) {
		cb.state.Store(int32(circuitOpen))
	}
}

// State 返回当前状态字符串。
func (cb *CircuitBreaker) State() string {
	switch circuitState(cb.state.Load()) {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen 熔断器开启错误。
var ErrCircuitOpen = fmt.Errorf("yvonne: circuit breaker is open")

// ClientOption 客户端配置选项。
type ClientOption func(*Client)

// WithRetry 设置重试配置。
func WithRetry(cfg *RetryConfig) ClientOption {
	return func(c *Client) {
		c.retryConfig = cfg
	}
}

// WithCircuitBreaker 设置熔断器。
func WithCircuitBreaker(cfg *CircuitBreakerConfig) ClientOption {
	return func(c *Client) {
		c.circuitBreaker = NewCircuitBreaker(cfg)
	}
}

// WithTraceID 启用 trace_id 透传。
func WithTraceID(header string) ClientOption {
	return func(c *Client) {
		c.traceIDHeader = header
	}
}

// WithTimeout 设置超时。
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.http.Timeout = d
	}
}

// NewWithOpts 创建带配置选项的客户端。
func NewWithOpts(baseURL, token string, opts ...ClientOption) *Client {
	c := New(baseURL, token)
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// doWithRetry 带重试 + 熔断的请求。
func (c *Client) doWithRetry(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	// 熔断检查。
	if c.circuitBreaker != nil && !c.circuitBreaker.Allow() {
		return ErrCircuitOpen
	}

	maxRetries := 0
	if c.retryConfig != nil {
		maxRetries = c.retryConfig.MaxRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 计算退避时间（指数退避 + 抖动）。
			backoff := c.calculateBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// 注入 trace_id。
		ctx = c.injectTraceID(ctx)

		lastErr = c.doOnce(ctx, method, path, body, out)
		if lastErr == nil {
			// 成功。
			if c.circuitBreaker != nil {
				c.circuitBreaker.RecordSuccess()
			}
			return nil
		}

		// 检查是否可重试。
		if !c.isRetryable(lastErr) {
			if c.circuitBreaker != nil {
				c.circuitBreaker.RecordFailure()
			}
			return lastErr
		}

		// 记录失败。
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordFailure()
		}
	}

	return fmt.Errorf("yvonne: max retries (%d) exceeded: %w", maxRetries, lastErr)
}

// calculateBackoff 计算退避时间。
func (c *Client) calculateBackoff(attempt int) time.Duration {
	if c.retryConfig == nil {
		return 100 * time.Millisecond
	}
	backoff := float64(c.retryConfig.InitialBackoff) * math.Pow(2, float64(attempt-1))
	if time.Duration(backoff) > c.retryConfig.MaxBackoff {
		return c.retryConfig.MaxBackoff
	}
	// 添加抖动（±20%）。
	jitter := backoff * 0.2 * (2*randFloat() - 1)
	return time.Duration(backoff + jitter)
}

// isRetryable 检查错误是否可重试。
func (c *Client) isRetryable(err error) bool {
	if c.retryConfig == nil || c.retryConfig.RetryableStatus == nil {
		return false
	}
	// 检查是否是 HTTP 错误（yvonne: HTTP %d 格式）。
	errStr := err.Error()
	for code := range c.retryConfig.RetryableStatus {
		// 检查错误消息是否包含可重试的状态码。
		if containsStr(errStr, fmt.Sprintf("HTTP %d", code)) {
			return true
		}
	}
	// 网络错误（非 HTTP 状态码错误）可重试。
	if !containsStr(errStr, "HTTP ") {
		return true
	}
	return false
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// injectTraceID 注入 trace_id 到请求头。
func (c *Client) injectTraceID(ctx context.Context) context.Context {
	if c.traceIDHeader == "" {
		return ctx
	}

	// 从 context 提取已有 trace_id。
	traceID, ok := ctx.Value(traceIDKey{}).(string)
	if !ok || traceID == "" {
		// 生成新的 trace_id。
		traceID = generateTraceID()
		ctx = context.WithValue(ctx, traceIDKey{}, traceID)
	}

	// 注入到请求头（在 do 方法中读取）。
	return context.WithValue(ctx, requestTraceIDKey{}, traceID)
}

// traceIDKey 是 trace_id 的 context key。
type traceIDKey struct{}
type requestTraceIDKey struct{}

// generateTraceID 生成 16 字节 hex trace_id。
func generateTraceID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// randFloat 返回 [0, 1) 随机数。
func randFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return float64(v) / float64(math.MaxUint64)
}

// httpError HTTP 错误。
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("yvonne: HTTP %d: %s", e.statusCode, e.message)
}

// asHTTPError 尝试将 error 转为 httpError。
func asHTTPError(err error, target **httpError) bool {
	if he, ok := err.(*httpError); ok {
		*target = he
		return true
	}
	// 检查是否包含 HTTP 状态码的错误消息。
	return false
}

// TraceIDFromContext 从 context 提取 trace_id。
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey{}).(string); ok {
		return v
	}
	return ""
}

// WithTraceIDContext 将 trace_id 注入 context（供调用方传入已有 trace_id）。
func WithTraceIDContext(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

// 确保 io 不再引用（已移除 import）。
