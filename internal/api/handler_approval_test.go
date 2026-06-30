// Package api - Quorum Approval API 集成测试。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yvonne/internal/auth"
)

// newApprovalTestRouter 创建带 ApprovalStore 的测试 router。
func newApprovalTestRouter(t *testing.T) (*V1Router, auth.ApprovalStore) {
	t.Helper()
	router, _, _ := newV12TestRouter(t)
	approvalStore := auth.NewMemoryApprovalStore()
	router.SetApprovalStore(approvalStore)
	return router, approvalStore
}

// createApprovalViaAPI 通过 API 创建审批 ticket，返回 ticket。
func createApprovalViaAPI(t *testing.T, router *V1Router, roleID, operation string, required int) *auth.ApprovalTicket {
	t.Helper()
	body := createApprovalRequest{
		Operation: operation,
		KeyID:     "test-key",
		Required:  required,
		TTLHours:  24,
	}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: roleID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleCreateApproval(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("createApproval: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data auth.ApprovalTicket `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return &resp.Data
}

// approveViaAPI 通过 API approve ticket。
func approveViaAPI(t *testing.T, router *V1Router, roleID, ticketID string) *auth.ApprovalTicket {
	t.Helper()
	body := approveRequest{TicketID: ticketID}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: roleID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approve", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleApprove(w, req)

	var resp struct {
		Data auth.ApprovalTicket `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return &resp.Data
}

// TestApproval_Create 创建 ticket。
func TestApproval_Create(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 2)

	if ticket.ID == "" {
		t.Fatal("ticket ID should not be empty")
	}
	if ticket.Status != auth.ApprovalPending {
		t.Fatalf("status = %s, want pending", ticket.Status)
	}
	if ticket.Required != 2 {
		t.Fatalf("required = %d, want 2", ticket.Required)
	}
	t.Logf("✅ Created ticket: id=%s, required=%d", ticket.ID[:8], ticket.Required)
}

// TestApproval_Create_Invalid 缺少必填字段拒绝。
func TestApproval_Create_Invalid(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	body := createApprovalRequest{Operation: "", Required: 2}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "admin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleCreateApproval(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ Missing operation rejected")
}

// TestApproval_2of3_Approve 2-of-3 审批通过。
func TestApproval_2of3_Approve(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	// 创建 2-of-3 ticket。
	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 2)

	// approver-1 approve。
	t1 := approveViaAPI(t, router, "approver-1", ticket.ID)
	if t1.Status != auth.ApprovalPending {
		t.Fatalf("after 1st approve, status = %s, want pending", t1.Status)
	}
	t.Log("✅ 1st approve: still pending (1/2)")

	// approver-2 approve → 达成 quorum。
	t2 := approveViaAPI(t, router, "approver-2", ticket.ID)
	if t2.Status != auth.ApprovalApproved {
		t.Fatalf("after 2nd approve, status = %s, want approved", t2.Status)
	}
	t.Log("✅ 2nd approve: approved (2/2)")
}

// TestApproval_SelfApproveRejected 防自批准。
func TestApproval_SelfApproveRejected(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 1)

	// 请求者自己 approve → 拒绝。
	body := approveRequest{TicketID: ticket.ID}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "requester"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approve", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleApprove(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for self-approve, got %d", w.Code)
	}
	t.Log("✅ Self-approve rejected")
}

// TestApproval_DuplicateApproveIdempotent 重复 approve 幂等。
func TestApproval_DuplicateApproveIdempotent(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 2)

	// approver-1 approve。
	approveViaAPI(t, router, "approver-1", ticket.ID)

	// approver-1 再次 approve → 409。
	body := approveRequest{TicketID: ticket.ID}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "approver-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approve", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleApprove(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate approve, got %d", w.Code)
	}
	t.Log("✅ Duplicate approve: 409 (idempotent)")
}

// TestApproval_Reject 拒绝。
func TestApproval_Reject(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 2)

	// approver-1 reject。
	body := approveRequest{TicketID: ticket.ID}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "approver-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/reject", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleReject(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("reject: got %d, want 200", w.Code)
	}

	var resp struct {
		Data auth.ApprovalTicket `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.Status != auth.ApprovalRejected {
		t.Fatalf("status = %s, want rejected", resp.Data.Status)
	}
	t.Log("✅ Reject: ticket rejected")
}

// TestApproval_Get 查询 ticket。
func TestApproval_Get(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals?id="+ticket.ID, nil)
	req = req.WithContext(auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "admin"}))
	w := httptest.NewRecorder()
	router.handleGetApproval(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get: got %d, want 200", w.Code)
	}

	var resp struct {
		Data auth.ApprovalTicket `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.ID != ticket.ID {
		t.Fatal("ticket ID mismatch")
	}
	t.Log("✅ Get ticket: found")
}

// TestApproval_ListPending 列出 pending。
func TestApproval_ListPending(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	// 创建 2 个 pending ticket。
	createApprovalViaAPI(t, router, "requester", "ShredKey", 2)
	createApprovalViaAPI(t, router, "requester", "ExportKey", 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req = req.WithContext(auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "admin"}))
	w := httptest.NewRecorder()
	router.handleListApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			Count   int                    `json:"count"`
			Tickets []*auth.ApprovalTicket `json:"tickets"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.Count != 2 {
		t.Fatalf("pending count = %d, want 2", resp.Data.Count)
	}
	t.Logf("✅ List pending: %d tickets", resp.Data.Count)
}

// TestApproval_Expired 过期 ticket。
func TestApproval_Expired(t *testing.T) {
	router, store := newApprovalTestRouter(t)

	// 创建已过期的 ticket（直接操作 store）。
	expiredTicket := &auth.ApprovalTicket{
		ID:          "expired-001",
		Operation:   "ShredKey",
		RequestedBy: "requester",
		Approvers:   []string{},
		Rejectors:   []string{},
		Required:    1,
		Status:      auth.ApprovalPending,
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // 1 小时前过期
	}
	store.CreateTicket(expiredTicket)

	// 尝试 approve → 应返回 410 expired。
	body := approveRequest{TicketID: "expired-001"}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "approver-1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approve", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleApprove(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for expired, got %d", w.Code)
	}
	t.Log("✅ Expired ticket: rejected")
}

// TestApproval_AlreadyResolved 已完成的 ticket 拒绝再次审批。
func TestApproval_AlreadyResolved(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	// 创建 + approve 到完成。
	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 1)
	approveViaAPI(t, router, "approver-1", ticket.ID)

	// 再次 approve → 409。
	body := approveRequest{TicketID: ticket.ID}
	bodyJSON, _ := json.Marshal(body)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{RoleID: "approver-2"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approve", bytes.NewReader(bodyJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handleApprove(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for already resolved, got %d", w.Code)
	}
	t.Log("✅ Already resolved ticket: rejected")
}

// TestQuorumMiddleware_RequiresApproval Quorum 中间件拦截敏感操作。
func TestQuorumMiddleware_RequiresApproval(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:        "admin",
		RequireQuorum: 2,
		AllowedKeys:   []string{"*"},
	})

	// 敏感操作无 ticket → 202。
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/shred", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	called := false
	router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if called {
		t.Fatal("handler should NOT be called without approval ticket")
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	t.Log("✅ Quorum: sensitive op without ticket → 202 (approval required)")
}

// TestQuorumMiddleware_ApprovedTicketPasses 已批准 ticket 通过。
func TestQuorumMiddleware_ApprovedTicketPasses(t *testing.T) {
	router, store := newApprovalTestRouter(t)

	// 创建已批准的 ticket。
	ticket := &auth.ApprovalTicket{
		ID:          "approved-001",
		Operation:   "ShredKey",
		RequestedBy: "requester",
		Approvers:   []string{"approver-1", "approver-2"},
		Required:    2,
		Status:      auth.ApprovalApproved,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		ResolvedAt:  time.Now(),
	}
	store.CreateTicket(ticket)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:        "admin",
		RequireQuorum: 2,
		AllowedKeys:   []string{"*"},
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/shred", nil)
	req.Header.Set("X-Approval-Ticket-ID", "approved-001")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	called := false
	router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if !called {
		t.Fatal("handler should be called with approved ticket")
	}
	t.Log("✅ Quorum: approved ticket → handler called")
}

// TestQuorumMiddleware_PendingTicketRejected pending ticket 拒绝。
func TestQuorumMiddleware_PendingTicketRejected(t *testing.T) {
	router, _ := newApprovalTestRouter(t)

	ticket := createApprovalViaAPI(t, router, "requester", "ShredKey", 2)

	ctx := auth.WithPolicy(context.Background(), &auth.Policy{
		RoleID:        "admin",
		RequireQuorum: 2,
		AllowedKeys:   []string{"*"},
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/shred", nil)
	req.Header.Set("X-Approval-Ticket-ID", ticket.ID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	called := false
	router.mfaMiddleware("ShredKey", func(w http.ResponseWriter, r *http.Request) {
		called = true
	})(w, req)

	if called {
		t.Fatal("handler should NOT be called with pending ticket")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	t.Log("✅ Quorum: pending ticket → 403 (not completed)")
}
