// Package observability - Webhook 告警（钉钉/Slack/PagerDuty）。
//
// 高危操作（ShredKey/EmergencySeal/QuorumReject）触发 Webhook 告警。
// 支持 Slack/钉钉/PagerDuty 格式（自动检测 webhook URL）。
package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// AlertConfig 是告警配置。
type AlertConfig struct {
	Enabled            bool     `json:"enabled"              yaml:"enabled"`
	WebhookURL         string   `json:"webhook_url"          yaml:"webhook_url"`
	HighRiskOperations []string `json:"high_risk_operations" yaml:"high_risk_operations"`
}

// AlertEvent 是一个告警事件。
type AlertEvent struct {
	Operation   string    `json:"operation"` // ShredKey / EmergencySeal / QuorumReject
	Actor       string    `json:"actor"`     // 操作者 RoleID
	Resource    string    `json:"resource"`  // 目标资源（如 key_id）
	Timestamp   time.Time `json:"timestamp"`
	TraceID     string    `json:"trace_id"`
	Description string    `json:"description"`
}

// Alerter 是告警器接口。
type Alerter interface {
	// Alert 发送告警。
	Alert(ctx context.Context, event AlertEvent) error
}

// NoopAlerter 不发送告警（alerting 禁用时用）。
type NoopAlerter struct{}

// Alert 不发送任何告警。
func (n *NoopAlerter) Alert(ctx context.Context, event AlertEvent) error {
	return nil
}

// WebhookAlerter 是 Webhook 告警器。
type WebhookAlerter struct {
	cfg    AlertConfig
	client *http.Client
}

// NewWebhookAlerter 创建 Webhook 告警器。
func NewWebhookAlerter(cfg AlertConfig) *WebhookAlerter {
	return &WebhookAlerter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Alert 发送 Webhook 告警。
// 自动检测 webhook 类型（Slack/钉钉/PagerDuty）并格式化消息。
func (a *WebhookAlerter) Alert(ctx context.Context, event AlertEvent) error {
	if !a.cfg.Enabled {
		return nil
	}

	// 检查是否为高危操作。
	if !a.isHighRisk(event.Operation) {
		return nil
	}

	payload := a.formatPayload(event)
	if payload == nil {
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("observability: marshal alert payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("observability: create alert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req) // #nosec G107 -- webhook URL 由管理员配置
	if err != nil {
		return fmt.Errorf("observability: send alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("observability: alert webhook returned %d", resp.StatusCode)
	}

	log.Printf("alert sent: operation=%s, actor=%s, resource=%s",
		event.Operation, event.Actor, event.Resource)
	return nil
}

// isHighRisk 检查操作是否为高危。
func (a *WebhookAlerter) isHighRisk(operation string) bool {
	for _, op := range a.cfg.HighRiskOperations {
		if op == operation {
			return true
		}
	}
	return false
}

// formatPayload 根据 webhook URL 格式化消息体。
func (a *WebhookAlerter) formatPayload(event AlertEvent) map[string]interface{} {
	webhookURL := a.cfg.WebhookURL

	switch {
	case strings.Contains(webhookURL, "hooks.slack.com"):
		// Slack 格式。
		return map[string]interface{}{
			"text": fmt.Sprintf("🚨 *Yvonne KMS 高危操作告警*\n\n"+
				"*操作*: %s\n"+
				"*操作者*: %s\n"+
				"*资源*: %s\n"+
				"*时间*: %s\n"+
				"*TraceID*: %s\n"+
				"*描述*: %s",
				event.Operation, event.Actor, event.Resource,
				event.Timestamp.Format(time.RFC3339),
				event.TraceID, event.Description),
		}

	case strings.Contains(webhookURL, "oapi.dingtalk.com"):
		// 钉钉格式。
		return map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]interface{}{
				"title": "Yvonne KMS 高危操作告警",
				"text": fmt.Sprintf("## 🚨 Yvonne KMS 高危操作告警\n\n"+
					"**操作**: %s\n\n"+
					"**操作者**: %s\n\n"+
					"**资源**: %s\n\n"+
					"**时间**: %s\n\n"+
					"**TraceID**: %s\n\n"+
					"**描述**: %s",
					event.Operation, event.Actor, event.Resource,
					event.Timestamp.Format(time.RFC3339),
					event.TraceID, event.Description),
			},
		}

	case strings.Contains(webhookURL, "pagerduty.com"):
		// PagerDuty 格式。
		return map[string]interface{}{
			"routing_key":  "", // 需用户填入
			"event_action": "trigger",
			"payload": map[string]interface{}{
				"summary":  fmt.Sprintf("Yvonne KMS: %s by %s", event.Operation, event.Actor),
				"severity": "critical",
				"source":   "yvonne-kms",
				"custom_details": map[string]interface{}{
					"operation": event.Operation,
					"actor":     event.Actor,
					"resource":  event.Resource,
					"trace_id":  event.TraceID,
					"timestamp": event.Timestamp.Format(time.RFC3339),
				},
			},
		}

	default:
		// 通用 JSON 格式。
		return map[string]interface{}{
			"alert":       "yvonne-kms",
			"operation":   event.Operation,
			"actor":       event.Actor,
			"resource":    event.Resource,
			"timestamp":   event.Timestamp.Format(time.RFC3339),
			"trace_id":    event.TraceID,
			"description": event.Description,
		}
	}
}

// NewAlerter 根据配置创建告警器。
func NewAlerter(cfg AlertConfig) Alerter {
	if !cfg.Enabled {
		return &NoopAlerter{}
	}
	return NewWebhookAlerter(cfg)
}
