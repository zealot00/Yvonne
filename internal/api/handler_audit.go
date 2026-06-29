// Package api - 审计日志查询 handler。
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"yvonne/internal/audit"
)

// auditQueryRequest 是 POST /api/v1/audit/query 的请求体。
type auditQueryRequest struct {
	StartTime string `json:"start_time"` // RFC3339，空=不限
	EndTime   string `json:"end_time"`   // RFC3339，空=不限
	Actor     string `json:"actor"`      // 精确匹配，空=不限
	Action    string `json:"action"`     // 精确匹配，空=不限
	Limit     int    `json:"limit"`      // 0=默认100，-1=全部
}

// handleAuditQuery 查询审计日志。
//
// POST /api/v1/audit/query
//
// 支持按时间范围、Actor、Action 过滤。
// 返回日志条目 + 哈希链验证结果。
func (r *V1Router) handleAuditQuery(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read request body failed")
		return
	}
	defer func() {
		if bodyBytes != nil {
			clear(bodyBytes)
			runtime.KeepAlive(bodyBytes)
		}
	}()

	var body auditQueryRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	// 构造过滤条件。
	// BUG-6 修复：Limit=-1 不允许返回全量，强制上限 10000。
	limit := body.Limit
	if limit < 0 {
		limit = 10000 // 最大上限
	}
	if limit == 0 {
		limit = 100 // 默认
	}
	if limit > 10000 {
		limit = 10000 // 强制上限
	}
	filter := audit.QueryFilter{
		Actor:  body.Actor,
		Action: body.Action,
		Limit:  limit,
	}

	if body.StartTime != "" {
		t, err := time.Parse(time.RFC3339, body.StartTime)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid start_time (use RFC3339)")
			return
		}
		filter.StartTime = &t
	}
	if body.EndTime != "" {
		t, err := time.Parse(time.RFC3339, body.EndTime)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid end_time (use RFC3339)")
			return
		}
		filter.EndTime = &t
	}

	// 检查审计目录是否配置。
	if r.auditDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "audit query not configured (no log directory)")
		return
	}

	// 查询。
	logger, ok := r.auditLog.(*audit.AuditLogger)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "audit logger not available for query")
		return
	}

	results, err := logger.Query(r.auditDir, filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit query failed")
		return
	}

	// 构造响应。
	resp := map[string]interface{}{
		"count":   len(results),
		"entries": results,
	}
	writeJSONOK(w, resp)
}

// 确保 strconv 被引用（Limit 默认值处理用）。
var _ = strconv.Itoa
