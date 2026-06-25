//go:build integration

package api

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatusRecorder_ImplementsFlusher 验证 statusRecorder 实现 http.Flusher。
func TestStatusRecorder_ImplementsFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	if _, ok := interface{}(sr).(http.Flusher); !ok {
		t.Fatal("statusRecorder should implement http.Flusher")
	}
}

// TestStatusRecorder_ImplementsHijacker 验证 statusRecorder 实现 http.Hijacker。
func TestStatusRecorder_ImplementsHijacker(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	if _, ok := interface{}(sr).(http.Hijacker); !ok {
		t.Fatal("statusRecorder should implement http.Hijacker")
	}
}

// TestStatusRecorder_ImplementsPusher 验证 statusRecorder 实现 http.Pusher。
func TestStatusRecorder_ImplementsPusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	if _, ok := interface{}(sr).(http.Pusher); !ok {
		t.Fatal("statusRecorder should implement http.Pusher")
	}
}

// TestStatusRecorder_FlushPassthrough 验证 Flush 透传到底层 ResponseWriter。
func TestStatusRecorder_FlushPassthrough(t *testing.T) {
	// httptest.NewRecorder 实现了 http.Flusher。
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	// 不应 panic。
	sr.Flush()
}

// TestStatusRecorder_HijackNotSupported 验证底层不支持 Hijack 时返回 error。
func TestStatusRecorder_HijackNotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	// httptest.ResponseRecorder 不实现 Hijacker。
	_, _, err := sr.Hijack()
	if err == nil {
		t.Fatal("Hijack should fail when underlying doesn't support it")
	}
}

// TestStatusRecorder_PushNotSupported 验证底层不支持 Push 时返回 error。
func TestStatusRecorder_PushNotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}

	err := sr.Push("/test", nil)
	if err == nil {
		t.Fatal("Push should fail when underlying doesn't support it")
	}
}

// TestStatusRecorder_CapturesStatus 验证状态码被正确捕获。
func TestStatusRecorder_CapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 0}

	sr.WriteHeader(http.StatusTeapot)

	if sr.status != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", sr.status, http.StatusTeapot)
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("rec.Code = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// TestStatusRecorder_WriteBody 验证 Write 透传。
func TestStatusRecorder_WriteBody(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 0}

	body := []byte("test body")
	n, err := sr.Write(body)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(body) {
		t.Fatalf("wrote %d bytes, want %d", n, len(body))
	}
	if rec.Body.String() != "test body" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "test body")
	}
}

// 确保 bufio 和 net 被引用（Hijack 签名需要）。
var (
	_ *bufio.ReadWriter = nil
	_ net.Conn          = nil
)
