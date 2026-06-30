// Package observability - Alerting 测试。
package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNoopAlerter NoopAlerter 不发送。
func TestNoopAlerter(t *testing.T) {
	alerter := &NoopAlerter{}
	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "ShredKey",
		Actor:     "admin",
	})
	if err != nil {
		t.Fatalf("NoopAlerter should not error: %v", err)
	}
	t.Log("✅ NoopAlerter: no error")
}

// TestWebhookAlerter_Disabled 禁用时不发送。
func TestWebhookAlerter_Disabled(t *testing.T) {
	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:    false,
		WebhookURL: "http://example.com/webhook",
	})
	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "ShredKey",
	})
	if err != nil {
		t.Fatalf("disabled alerter should not error: %v", err)
	}
	t.Log("✅ Disabled alerter: no error")
}

// TestWebhookAlerter_NonHighRisk 非高危操作不发送。
func TestWebhookAlerter_NonHighRisk(t *testing.T) {
	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:            true,
		WebhookURL:         "http://example.com/webhook",
		HighRiskOperations: []string{"ShredKey"},
	})
	// Encrypt 不是高危操作。
	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "Encrypt",
	})
	if err != nil {
		t.Fatalf("non-high-risk should not error: %v", err)
	}
	t.Log("✅ Non-high-risk operation: no alert sent")
}

// TestWebhookAlerter_SlackFormat Slack 格式。
func TestWebhookAlerter_SlackFormat(t *testing.T) {
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读取 body 并解析。
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		// 简单验证不 panic，不深度解析 JSON。
		receivedPayload = map[string]interface{}{"body_length": n}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:            true,
		WebhookURL:         server.URL + "/hooks/slack",
		HighRiskOperations: []string{"ShredKey"},
	})

	err := alerter.Alert(context.Background(), AlertEvent{
		Operation:   "ShredKey",
		Actor:       "admin",
		Resource:    "order-key",
		Timestamp:   time.Now(),
		TraceID:     "abc123",
		Description: "test alert",
	})
	if err != nil {
		t.Fatalf("Alert: %v", err)
	}

	if receivedPayload == nil {
		t.Fatal("should have received payload")
	}
	t.Log("✅ Slack format: alert sent")
}

// TestWebhookAlerter_DingTalkFormat 钉钉格式。
func TestWebhookAlerter_DingTalkFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:            true,
		WebhookURL:         server.URL + "/oapi.dingtalk.com/robot/send",
		HighRiskOperations: []string{"EmergencySeal"},
	})

	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "EmergencySeal",
		Actor:     "admin",
	})
	if err != nil {
		t.Fatalf("Alert: %v", err)
	}
	t.Log("✅ DingTalk format: alert sent")
}

// TestWebhookAlerter_GenericFormat 通用格式。
func TestWebhookAlerter_GenericFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:            true,
		WebhookURL:         server.URL + "/webhook",
		HighRiskOperations: []string{"QuorumReject"},
	})

	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "QuorumReject",
		Actor:     "approver-1",
	})
	if err != nil {
		t.Fatalf("Alert: %v", err)
	}
	t.Log("✅ Generic format: alert sent")
}

// TestWebhookAlerter_HTTPError HTTP 错误。
func TestWebhookAlerter_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	alerter := NewWebhookAlerter(AlertConfig{
		Enabled:            true,
		WebhookURL:         server.URL,
		HighRiskOperations: []string{"ShredKey"},
	})

	err := alerter.Alert(context.Background(), AlertEvent{
		Operation: "ShredKey",
	})
	if err == nil {
		t.Fatal("should error on HTTP 500")
	}
	t.Logf("✅ HTTP error: %v", err)
}

// TestNewAlerter_Factory 根据配置创建告警器。
func TestNewAlerter_Factory(t *testing.T) {
	// 禁用 → NoopAlerter。
	a1 := NewAlerter(AlertConfig{Enabled: false})
	if _, ok := a1.(*NoopAlerter); !ok {
		t.Fatal("disabled should return NoopAlerter")
	}
	t.Log("✅ Factory: disabled → NoopAlerter")

	// 启用 → WebhookAlerter。
	a2 := NewAlerter(AlertConfig{
		Enabled:    true,
		WebhookURL: "http://example.com",
	})
	if _, ok := a2.(*WebhookAlerter); !ok {
		t.Fatal("enabled should return WebhookAlerter")
	}
	t.Log("✅ Factory: enabled → WebhookAlerter")
}
