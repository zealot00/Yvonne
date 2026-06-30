// Package api - MFA 中间件（敏感操作 TOTP 二次确认）。
//
// 敏感操作（ShredKey/ExportKey/EmergencySeal）在 RequireAuth 之后、
// handler 之前校验 MFA code。
//
// 流程:
//  1. RequireAuth → Policy（含 RequireMFA 标志）
//  2. MFA middleware: if Policy.RequireMFA → 校验 X-MFA-Code header
//  3. handler 执行
package api

import (
	"net/http"

	"yvonne/internal/auth"
)

// sensitiveOperations 是需要 MFA 的敏感操作集合。
var sensitiveOperations = map[string]bool{
	"ShredKey":      true,
	"EmergencySeal": true,
	"ExportKey":     true,
	"SoftDeleteKey": true,
}

// mfaMiddleware 校验敏感操作的 TOTP code + Quorum 审批。
// 从 X-MFA-Code header 读取 6 位 code，校验 against role 的 TOTP secret。
//
// 流程:
//  1. 非敏感操作放行
//  2. 如果 Policy.RequireMFA → 校验 X-MFA-Code
//  3. 如果 Policy.RequireQuorum > 0 → 返回 202 提示需 Quorum 审批
//     （实际 Quorum 流程由 handler 调用 approval API 完成）
//
// 如果 Policy.RequireMFA=false 或操作不在敏感列表，直接放行。
func (r *V1Router) mfaMiddleware(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// 非敏感操作放行。
		if !sensitiveOperations[action] {
			next(w, req)
			return
		}

		policy := auth.PolicyFromContext(req.Context())
		if policy == nil {
			// Dev 模式无 Policy 放行（测试友好）。
			next(w, req)
			return
		}

		// Quorum 检查：如果需要 K-of-N 审批，返回 202 提示。
		if policy.RequireQuorum > 0 && r.approvalStore != nil {
			// 检查是否有已 approved 的 ticket。
			ticketID := req.Header.Get("X-Approval-Ticket-ID")
			if ticketID == "" {
				// 无 ticket ID → 返回 202 提示需创建审批。
				writeJSONError(w, http.StatusAccepted, "quorum approval required: create approval ticket first")
				return
			}

			ticket, err := r.approvalStore.GetTicket(ticketID)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "approval ticket not found: "+err.Error())
				return
			}

			if ticket.Status != auth.ApprovalApproved {
				writeJSONError(w, http.StatusForbidden, "approval not completed, current status: "+string(ticket.Status))
				return
			}

			if ticket.Operation != action {
				writeJSONError(w, http.StatusForbidden, "ticket operation mismatch")
				return
			}

			// Quorum 审批通过，继续 MFA 检查。
		}

		// 不需要 MFA 的角色放行。
		if !policy.RequireMFA {
			next(w, req)
			return
		}

		// 需要 MFA：校验 X-MFA-Code header。
		if r.mfaStore == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "mfa store not configured")
			return
		}

		state, err := r.mfaStore.GetMFAState(policy.RoleID)
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "mfa not setup for role")
			return
		}
		if !state.Enabled {
			writeJSONError(w, http.StatusForbidden, "mfa not enabled, call verify first")
			return
		}

		code := req.Header.Get("X-MFA-Code")
		if code == "" {
			writeJSONError(w, http.StatusUnauthorized, "mfa code required in X-MFA-Code header")
			return
		}

		if err := auth.ValidateTOTP(state.Secret, code, nil); err != nil {
			writeJSONError(w, http.StatusForbidden, "invalid mfa code")
			return
		}

		// MFA 验证通过，继续执行。
		next(w, req)
	}
}
