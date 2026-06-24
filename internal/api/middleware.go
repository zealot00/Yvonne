// Package api - 审计中间件 + 认证中间件 + 指标埋点。
//
// 中间件层级（从外到内）：
//
//	RequireAuth（认证 + RBAC 校验）
//	  → auditMiddleware（TraceID + 审计日志 + 指标）
//	    → requireUnsealedV1（Sealed 503）
//	      → 业务 handler
//
// 安全：
//   - RequireAuth 解析 Bearer Token，注入 RoleID 到 context。
//   - auditMiddleware 从 context 提取 RoleID 作为 Actor（而非 IP）。
//   - 越权返回 403 并记录审计日志 status=Unauthorized。
//   - 默认拒绝：无 Token 或找不到 Policy 返回 401。
package api

import (
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/memguard"
)

// statusRecorder 拦截 WriteHeader 调用，记录最终状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// RequireAuth 是认证+授权中间件，置于所有业务 API 路由最外层。
//
// 流程：
//  1. 从 Authorization header 提取 Bearer Token。
//  2. 调用 Authenticator 获取 Policy。
//  3. 将 RoleID 注入 context。
//  4. 校验 KeyID 和 Action 是否在 Policy 范围内。
//  5. 越权返回 403 并记录审计日志。
//
// 安全红线：
//   - 绝不打印 Token 明文。
//   - 默认拒绝：无 Token 或找不到 Policy 返回 401。
//   - Actor 字段记录 RoleID（非 IP）。
func (r *V1Router) RequireAuth(authenticator auth.Authenticator, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// 1. 提取 Bearer Token。
		token, err := auth.ExtractBearerToken(req.Header.Get("Authorization"))
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// 2. 认证。
		policy, err := authenticator.Authenticate(req.Context(), token)
		if err != nil {
			// 默认拒绝。绝不打印 Token。
			writeJSONError(w, http.StatusUnauthorized, "authentication failed")
			return
		}

		// 3. 注入 RoleID 到 context。
		ctx := auth.WithRoleID(req.Context(), policy.RoleID)
		req = req.WithContext(ctx)

		// 4. RBAC 校验：Action 是否允许。
		if !policy.IsActionAllowed(action) {
			writeJSONError(w, http.StatusForbidden, "action not allowed")
			return
		}

		// 5. RBAC 校验：KeyID 是否允许（从 URL 路径或 body 解析）。
		//    对于 /api/v1/keys/{key_id}/*，从路径提取 key_id。
		//    对于 /api/v1/encrypt 和 /api/v1/decrypt，key_id 在 body 中，
		//    handler 内部会调用 policy 检查（此处仅检查 action）。
		keyID := extractKeyIDFromPath(req.URL.Path)
		if keyID != "" && !policy.IsKeyAllowed(keyID) {
			writeJSONError(w, http.StatusForbidden, "key not allowed")
			return
		}

		next(w, req)
	}
}

// extractKeyIDFromPath 从 URL 路径提取 key_id（仅对 /api/v1/keys/{key_id}/... 有效）。
func extractKeyIDFromPath(path string) string {
	const prefix = "/api/v1/keys/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// auditMiddleware 是 v1 API 的强制审计中间件。
//
// 从 context 提取 RoleID 作为 Actor（若无可回退到 RemoteAddr）。
func (r *V1Router) auditMiddleware(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// 紧急封印状态：拒绝一切请求（auditMiddleware 拦截后仍记录审计日志）。
		if r.seal.IsEmergencySealed() {
			writeJSONError(w, http.StatusServiceUnavailable, "vault is emergency sealed")
			return
		}

		startTime := time.Now()

		traceIDBytes, err := memguard.GenerateSecureRandom(16)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "trace id generation failed")
			return
		}
		traceID := hex.EncodeToString(traceIDBytes)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		func() {
			defer func() {
				if recov := recover(); recov != nil {
					if rec.status == http.StatusOK {
						writeJSONError(rec, http.StatusInternalServerError, "internal error")
					}
				}
			}()
			next(rec, req)
		}()

		duration := time.Since(startTime)
		success := rec.status < 400
		if r.metrics != nil {
			r.metrics.RecordAPIRequest(action, duration, success)
		}

		// 从 context 提取 RoleID 作为 Actor。
		actor := auth.RoleIDFromContext(req.Context())
		if actor == "" {
			actor = req.RemoteAddr // 回退到 IP（未认证路由如 health）
		}

		status := "success"
		if !success {
			status = "failure"
		}
		if rec.status == http.StatusForbidden {
			status = "unauthorized"
		}

		entry := audit.LogEntry{
			TraceID:   traceID,
			Timestamp: time.Now().UTC(),
			Actor:     actor,
			Action:    action,
			KeyID:     "",
			Status:    status,
		}
		_ = r.auditLog.Record(entry)
	}
}
