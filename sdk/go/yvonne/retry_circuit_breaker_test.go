// Package yvonne - Go SDK 重试/熔断/trace_id 测试。
package yvonne

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRetry_SuccessAfterRetry 重试后成功。
func TestRetry_SuccessAfterRetry(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&calls, 1)
		if count < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithRetry(&RetryConfig{
			MaxRetries:      3,
			InitialBackoff:  10 * time.Millisecond,
			MaxBackoff:      100 * time.Millisecond,
			RetryableStatus: map[int]bool{503: true},
		}),
	)

	err := client.healthCheck(context.Background())
	if err != nil {
		t.Fatalf("expected success after retry: %v", err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	t.Log("✅ Retry success after 2 retries")
}

// TestRetry_MaxRetriesExceeded 重试次数耗尽。
func TestRetry_MaxRetriesExceeded(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(503)
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithRetry(&RetryConfig{
			MaxRetries:      2,
			InitialBackoff:  10 * time.Millisecond,
			MaxBackoff:      50 * time.Millisecond,
			RetryableStatus: map[int]bool{503: true},
		}),
	)

	err := client.healthCheck(context.Background())
	if err == nil {
		t.Fatal("should fail after max retries")
	}
	if atomic.LoadInt32(&calls) != 3 { // 1 + 2 retries
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	t.Logf("✅ Retry max exceeded: %v", err)
}

// TestRetry_NonRetryableError 不可重试错误直接返回。
func TestRetry_NonRetryableError(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"error":"bad request"}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithRetry(&RetryConfig{
			MaxRetries:      3,
			InitialBackoff:  10 * time.Millisecond,
			MaxBackoff:      50 * time.Millisecond,
			RetryableStatus: map[int]bool{503: true},
		}),
	)

	err := client.healthCheck(context.Background())
	if err == nil {
		t.Fatal("should fail")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 call (no retry for 400), got %d", calls)
	}
	t.Log("✅ Non-retryable error: no retry")
}

// TestCircuitBreaker_OpensOnFailures 连续失败后熔断。
func TestCircuitBreaker_OpensOnFailures(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(503)
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithCircuitBreaker(&CircuitBreakerConfig{
			FailureThreshold: 3,
			ResetTimeout:     1 * time.Second,
		}),
	)

	// 前 3 次请求会调用 server。
	for i := 0; i < 3; i++ {
		client.healthCheck(context.Background())
	}

	// 第 4 次应被熔断（不调用 server）。
	beforeCalls := atomic.LoadInt32(&calls)
	err := client.healthCheck(context.Background())
	afterCalls := atomic.LoadInt32(&calls)

	if afterCalls != beforeCalls {
		t.Fatalf("circuit should be open, but server was called (calls: %d → %d)", beforeCalls, afterCalls)
	}
	if err == nil {
		t.Fatal("should fail with circuit open")
	}
	t.Logf("✅ Circuit breaker opened: %v", err)
}

// TestCircuitBreaker_ResetsAfterTimeout 超时后恢复。
func TestCircuitBreaker_ResetsAfterTimeout(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithCircuitBreaker(&CircuitBreakerConfig{
			FailureThreshold: 2,
			ResetTimeout:     100 * time.Millisecond,
		}),
	)

	// 触发熔断（模拟失败）。
	cb := client.circuitBreaker
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != "open" {
		t.Fatalf("circuit should be open, got %s", cb.State())
	}

	// 等待恢复。
	time.Sleep(150 * time.Millisecond)

	// 请求应成功（半开 → 关闭）。
	err := client.healthCheck(context.Background())
	if err != nil {
		t.Fatalf("should succeed after reset: %v", err)
	}
	t.Log("✅ Circuit breaker reset after timeout")
}

// TestTraceID_GenerateAndPropagate trace_id 生成 + 透传。
func TestTraceID_GenerateAndPropagate(t *testing.T) {
	var receivedTraceID string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedTraceID = r.Header.Get("X-Request-ID")
		mu.Unlock()
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithTraceID("X-Request-ID"),
	)

	ctx := WithTraceIDContext(context.Background(), "generated-trace-123")
	err := client.healthCheck(ctx)
	if err != nil {
		t.Fatalf("healthCheck: %v", err)
	}

	mu.Lock()
	tid := receivedTraceID
	mu.Unlock()

	if tid == "" {
		t.Fatal("trace_id should be propagated to server")
	}
	t.Logf("✅ TraceID propagated: %s", tid)
}

// TestTraceID_ContextPropagation 从 context 传入 trace_id。
func TestTraceID_ContextPropagation(t *testing.T) {
	var receivedTraceID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceID = r.Header.Get("X-Trace-ID")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "",
		WithTraceID("X-Trace-ID"),
	)

	ctx := WithTraceIDContext(context.Background(), "my-trace-123")
	err := client.healthCheck(ctx)
	if err != nil {
		t.Fatalf("healthCheck: %v", err)
	}

	if receivedTraceID != "my-trace-123" {
		t.Fatalf("expected my-trace-123, got %s", receivedTraceID)
	}
	t.Logf("✅ TraceID from context: %s", receivedTraceID)
}

// TestTraceIDFromContext 从 context 提取 trace_id。
func TestTraceIDFromContext(t *testing.T) {
	ctx := WithTraceIDContext(context.Background(), "test-trace-id")
	traceID := TraceIDFromContext(ctx)
	if traceID != "test-trace-id" {
		t.Fatalf("expected test-trace-id, got %s", traceID)
	}

	// 空 context。
	empty := TraceIDFromContext(context.Background())
	if empty != "" {
		t.Fatal("should be empty for nil context")
	}
	t.Log("✅ TraceIDFromContext")
}

// TestNewWithOpts_AllOptions 所有配置选项组合。
func TestNewWithOpts_AllOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true,"data":{}}`))
	}))
	defer server.Close()

	client := NewWithOpts(server.URL, "test-token",
		WithRetry(DefaultRetryConfig()),
		WithCircuitBreaker(DefaultCircuitBreakerConfig()),
		WithTraceID("X-Request-ID"),
		WithTimeout(10*time.Second),
	)

	if client.retryConfig == nil {
		t.Fatal("retryConfig should be set")
	}
	if client.circuitBreaker == nil {
		t.Fatal("circuitBreaker should be set")
	}
	if client.traceIDHeader != "X-Request-ID" {
		t.Fatal("traceIDHeader should be set")
	}
	t.Log("✅ All options configured")

	// 请求应成功。
	err := client.healthCheck(context.Background())
	if err != nil {
		t.Fatalf("healthCheck: %v", err)
	}
	t.Log("✅ Request with all options succeeded")
}

// TestCircuitBreaker_State 熔断器状态转换。
func TestCircuitBreaker_State(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     100 * time.Millisecond,
	})

	if cb.State() != "closed" {
		t.Fatalf("initial state should be closed, got %s", cb.State())
	}

	cb.RecordFailure()
	if cb.State() != "closed" {
		t.Fatal("should still be closed after 1 failure")
	}

	cb.RecordFailure()
	if cb.State() != "open" {
		t.Fatalf("should be open after 2 failures, got %s", cb.State())
	}

	// 等待恢复。
	time.Sleep(150 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("should allow after reset timeout (half-open)")
	}

	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Fatalf("should be closed after success, got %s", cb.State())
	}
	t.Log("✅ Circuit breaker state transitions: closed → open → half-open → closed")
}

// healthCheck 辅助方法（用于测试）。
func (c *Client) healthCheck(ctx context.Context) error {
	var resp envelope
	return c.do(ctx, http.MethodGet, "/api/v1/sys/health", nil, &resp)
}

// 确保 fmt 引用。
var _ = fmt.Sprintf
