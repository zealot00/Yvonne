// Package api - Quorum Approval API handler。
//
// 端点:
//
//	POST /api/v1/approvals               — 创建审批 ticket
//	GET  /api/v1/approvals/{id}          — 查询 ticket 状态
//	POST /api/v1/approvals/{id}/approve  — 审批通过
//	POST /api/v1/approvals/{id}/reject   — 审批拒绝
//	GET  /api/v1/approvals               — 列出 pending tickets
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"

	"yvonne/internal/auth"
)

// createApprovalRequest 是创建审批 ticket 的请求体。
type createApprovalRequest struct {
	Operation string `json:"operation"` // "ShredKey" / "ExportKey" / "EmergencySeal"
	KeyID     string `json:"key_id"`    // 目标密钥（如有）
	Required  int    `json:"required"`  // K（需 K 票通过）
	TTLHours  int    `json:"ttl_hours"` // TTL 小时数（默认 24）
}

// handleApprovals 处理 /api/v1/approvals（POST=创建，GET=列表，?id=xxx=查询）。
func (r *V1Router) handleApprovals(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		r.handleCreateApproval(w, req)
	case http.MethodGet:
		// 如果有 id 参数，查询单个；否则列出 pending。
		if id := req.URL.Query().Get("id"); id != "" {
			r.handleGetApproval(w, req)
		} else {
			r.handleListApprovals(w, req)
		}
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleCreateApproval 处理 POST /api/v1/approvals。
func (r *V1Router) handleCreateApproval(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read request body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body createApprovalRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Operation == "" {
		writeJSONError(w, http.StatusBadRequest, "operation is required")
		return
	}
	if body.Required < 1 {
		writeJSONError(w, http.StatusBadRequest, "required must be >= 1")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		writeJSONError(w, http.StatusForbidden, "authentication required")
		return
	}

	if r.approvalStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	// 生成 ticket ID。
	ticketID := generateUUID()
	ttlHours := body.TTLHours
	if ttlHours == 0 {
		ttlHours = 24
	}

	ticket := &auth.ApprovalTicket{
		ID:          ticketID,
		Operation:   body.Operation,
		KeyID:       body.KeyID,
		RequestedBy: policy.RoleID,
		Approvers:   []string{},
		Rejectors:   []string{},
		Required:    body.Required,
		Status:      auth.ApprovalPending,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour),
	}

	if err := r.approvalStore.CreateTicket(ticket); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, ticket)
}

// handleGetApproval 处理 GET /api/v1/approvals/{id}。
func (r *V1Router) handleGetApproval(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}

	ticketID := req.URL.Query().Get("id")
	if ticketID == "" {
		writeJSONError(w, http.StatusBadRequest, "id is required")
		return
	}

	if r.approvalStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	ticket, err := r.approvalStore.GetTicket(ticketID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSONOK(w, ticket)
}

// approveRequest 是审批的请求体。
type approveRequest struct {
	TicketID string `json:"ticket_id"`
}

// handleApprove 处理 POST /api/v1/approvals/{id}/approve。
func (r *V1Router) handleApprove(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read request body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body approveRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.TicketID == "" {
		writeJSONError(w, http.StatusBadRequest, "ticket_id is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		writeJSONError(w, http.StatusForbidden, "authentication required")
		return
	}

	if r.approvalStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	ticket, err := r.approvalStore.GetTicket(body.TicketID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	// 状态校验。
	if ticket.Status != auth.ApprovalPending {
		writeJSONError(w, http.StatusConflict, "ticket already resolved: "+string(ticket.Status))
		return
	}
	if ticket.IsExpired() {
		ticket.Status = auth.ApprovalExpired
		ticket.ResolvedAt = time.Now().UTC()
		r.approvalStore.UpdateTicket(ticket)
		writeJSONError(w, http.StatusConflict, "ticket expired")
		return
	}

	// 防自批准。
	if ticket.RequestedBy == policy.RoleID {
		writeJSONError(w, http.StatusForbidden, "cannot approve own request")
		return
	}

	// 幂等检查。
	if ticket.HasApproved(policy.RoleID) {
		writeJSONError(w, http.StatusConflict, "already approved by this role")
		return
	}

	// 添加审批者。
	ticket.Approvers = append(ticket.Approvers, policy.RoleID)

	// 检查是否达成 quorum。
	if len(ticket.Approvers) >= ticket.Required {
		ticket.Status = auth.ApprovalApproved
		ticket.ResolvedAt = time.Now().UTC()
	}

	if err := r.approvalStore.UpdateTicket(ticket); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, ticket)
}

// handleReject 处理 POST /api/v1/approvals/{id}/reject。
func (r *V1Router) handleReject(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read request body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body approveRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.TicketID == "" {
		writeJSONError(w, http.StatusBadRequest, "ticket_id is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		writeJSONError(w, http.StatusForbidden, "authentication required")
		return
	}

	if r.approvalStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	ticket, err := r.approvalStore.GetTicket(body.TicketID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	if ticket.Status != auth.ApprovalPending {
		writeJSONError(w, http.StatusConflict, "ticket already resolved: "+string(ticket.Status))
		return
	}

	// 添加拒绝者 + 标记 rejected。
	if !ticket.HasRejected(policy.RoleID) {
		ticket.Rejectors = append(ticket.Rejectors, policy.RoleID)
	}
	ticket.Status = auth.ApprovalRejected
	ticket.ResolvedAt = time.Now().UTC()

	if err := r.approvalStore.UpdateTicket(ticket); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, ticket)
}

// handleListApprovals 处理 GET /api/v1/approvals（列出 pending）。
func (r *V1Router) handleListApprovals(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}

	if r.approvalStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	tickets, err := r.approvalStore.ListPending()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"tickets": tickets,
		"count":   len(tickets),
	})
}

// generateUUID 生成简单 UUID v4（避免外部依赖）。
func generateUUID() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> uint(i*8))
	}
	// 设置 version 4 + variant 位。
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

// formatUUID 格式化 16 字节为 UUID 字符串。
func formatUUID(b []byte) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 36)
	pos := 0
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			buf[pos] = '-'
			pos++
		}
		buf[pos] = hex[v>>4]
		buf[pos+1] = hex[v&0x0f]
		pos += 2
	}
	return string(buf)
}
