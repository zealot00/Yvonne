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
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/memguard"
)

// statusRecorder 拦截 WriteHeader 调用，记录最终状态码。
// 同时保留 http.Flusher / http.Hijacker / http.Pusher 接口透传。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush 实现 http.Flusher，透传给底层 ResponseWriter（流式响应支持）。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 实现 http.Hijacker，透传给底层 ResponseWriter（WebSocket 支持）。
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("api: ResponseWriter does not support Hijack")
}

// Push 实现 http.Pusher，透传给底层 ResponseWriter（HTTP/2 Server Push）。
func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// RequireAuth 是认证+授权中间件，置于所有业务 API 路由最外层。
//
// 流程：
//  1. 从 Authorization header 提取 Bearer Token。
//  2. 调用 Authenticator 获取 Policy。
//  3. 将 RoleID + 完整 Policy 注入 context（供 handler 内做 body.KeyID 资源级校验）。
//  4. 校验 Action 是否在 Policy 范围内。
//  5. 校验 URL path 中的 KeyID（如 /keys/{id}/rotate），body 中的 KeyID 由 handler 校验。
//  6. 越权返回 403。
//
// 安全红线：
//   - 绝不打印 Token 明文。
//   - 默认拒绝：无 Token 或找不到 Policy 返回 401。
//   - body 中的 KeyID 资源级校验由 handler 调用 PolicyFromContext + IsKeyAllowed 完成。
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

		// 3. 注入 RoleID + 完整 Policy + TenantID 到 context。
		ctx := auth.WithRoleID(req.Context(), policy.RoleID)
		ctx = auth.WithPolicy(ctx, policy)
		if policy.TenantID != "" {
			ctx = auth.WithTenant(ctx, policy.TenantID)
		}
		req = req.WithContext(ctx)

		// 4. RBAC 校验：Action 是否允许。
		if !policy.IsActionAllowed(action) {
			writeJSONError(w, http.StatusForbidden, fmt.Sprintf(
				"access denied: role %q does not have action %q (allowed: %v)",
				policy.RoleID, action, policy.AllowedActions))
			return
		}

		// 5. RBAC 校验：URL path 中的 KeyID（如 /keys/{id}/rotate）。
		//    body 中的 KeyID（如 /encrypt /decrypt）由 handler 内部校验。
		keyID := extractKeyIDFromPath(req.URL.Path)
		if keyID != "" && !policy.IsKeyAllowed(keyID) {
			writeJSONError(w, http.StatusForbidden, "key not allowed")
			return
		}

		next(w, req)
	}
}

// authorizeBodyKeyID 从 context 提取 Policy，校验 body 中的 KeyID 是否被授权。
// 返回 true=允许，false=拒绝。
// 无 Policy（Dev 模式无认证器）时默认允许，保持向后兼容。
func authorizeBodyKeyID(req *http.Request, keyID string) bool {
	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		return true // Dev 模式无认证器，允许所有
	}
	return policy.IsKeyAllowed(keyID)
}

// authorizeBodyKeyIDWithDetail 同 authorizeBodyKeyID，但返回详细 error。
func authorizeBodyKeyIDWithDetail(req *http.Request, keyID string) error {
	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		return nil // Dev 模式
	}
	if !policy.IsKeyAllowed(keyID) {
		return fmt.Errorf("access denied: role %q cannot access key %q (allowed keys: %v)",
			policy.RoleID, keyID, policy.AllowedKeys)
	}
	return nil
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

// bufferedAuditResponseRecorder 缓冲业务 handler 的响应头、状态码与响应体，
// 确保审计日志落盘成功后再向客户端发送响应（防止审计写入失败时仍泄露明文 DEK 或操作结果）。
type bufferedAuditResponseRecorder struct {
	header      http.Header
	body        []byte
	status      int
	wroteHeader bool
}

func newBufferedAuditResponseRecorder() *bufferedAuditResponseRecorder {
	return &bufferedAuditResponseRecorder{
		header: make(http.Header),
		status: http.StatusOK,
	}
}

func (r *bufferedAuditResponseRecorder) Header() http.Header {
	return r.header
}

func (r *bufferedAuditResponseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
}

func (r *bufferedAuditResponseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, p...)
	return len(p), nil
}

func (r *bufferedAuditResponseRecorder) wipe() {
	clear(r.body)
	runtime.KeepAlive(r.body)
	r.body = nil
}

func (r *bufferedAuditResponseRecorder) flushTo(w http.ResponseWriter) {
	dst := w.Header()
	for k, vals := range r.header {
		dst[k] = append([]string(nil), vals...)
	}
	w.WriteHeader(r.status)
	if len(r.body) > 0 {
		_, _ = w.Write(r.body)
	}
	r.wipe()
}

// auditMiddleware 是 v1 API 的强制审计中间件。
//
// 从 context 提取 RoleID 作为 Actor（若无可回退到 RemoteAddr）。
//
// 安全保证（Fail-Closed Audit）：
//   - 业务响应先缓冲在内存中，待 r.auditLog.Record(entry) 写入成功后再刷写给客户端。
//   - 若审计写入失败，立即擦除缓冲中的响应体（含潜在明文 DEK），记录 CRITICAL 告警并返回 500。
func (r *V1Router) auditMiddleware(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// v1.3: TraceID 优先用 OTel span context，无 OTel 时用随机生成。
		traceID := traceIDFromContext(req.Context())
		if traceID == "" {
			traceIDBytes, err := memguard.GenerateSecureRandom(16)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "trace id generation failed")
				return
			}
			traceID = hex.EncodeToString(traceIDBytes)
		}

		// 从 context 提取 RoleID 作为 Actor。
		actor := auth.RoleIDFromContext(req.Context())
		if actor == "" {
			actor = req.RemoteAddr // 回退到 IP（未认证路由如 health）
		}

		// 紧急封印状态：拒绝一切请求（记录审计日志后返回 503）。
		if r.seal.IsEmergencySealed() {
			if r.auditLog != nil {
				entry := audit.LogEntry{
					TraceID:   traceID,
					Timestamp: time.Now().UTC(),
					Actor:     actor,
					Action:    action,
					KeyID:     "",
					Status:    "failure",
					Result:    "vault is emergency sealed",
				}
				if err := r.auditLog.Record(entry); err != nil {
					log.Printf("CRITICAL: audit log write failed on emergency-sealed request action=%s actor=%s trace=%s: %v",
						action, actor, traceID, err)
					writeJSONError(w, http.StatusInternalServerError, "audit log write failed")
					return
				}
			}
			writeJSONError(w, http.StatusServiceUnavailable, "vault is emergency sealed")
			return
		}

		startTime := time.Now()
		rec := newBufferedAuditResponseRecorder()

		func() {
			defer func() {
				if recov := recover(); recov != nil {
					// 记录完整堆栈到日志（防静默吞异常）。
					log.Printf("PANIC in handler %s: %v\n%s", req.URL.Path, recov, debug.Stack())
					rec.wipe()
					rec.header = make(http.Header)
					rec.wroteHeader = false
					writeJSONError(rec, http.StatusInternalServerError, "internal error")
					// 不 re-panic：http.Server 已接管连接，re-panic 会导致连接强制关闭
					// 而无错误响应。记录堆栈 + 返回 500 已是最安全处理。
				}
			}()
			next(rec, req)
		}()

		duration := time.Since(startTime)
		success := rec.status < 400
		if r.metrics != nil {
			r.metrics.RecordAPIRequest(action, duration, success)
		}

		// 若内层中间件（如 RequireAuth）更新了 context，优先尝试重新提取 RoleID。
		if roleAfter := auth.RoleIDFromContext(req.Context()); roleAfter != "" {
			actor = roleAfter
		}

		status := "success"
		if !success {
			status = "failure"
		}
		if rec.status == http.StatusForbidden {
			status = "unauthorized"
		}

		if r.auditLog != nil {
			entry := audit.LogEntry{
				TraceID:   traceID,
				Timestamp: time.Now().UTC(),
				Actor:     actor,
				Action:    action,
				KeyID:     "",
				Status:    status,
			}
			if err := r.auditLog.Record(entry); err != nil {
				rec.wipe()
				log.Printf("CRITICAL: audit log write failed for action=%s actor=%s trace=%s: %v",
					action, actor, traceID, err)
				writeJSONError(w, http.StatusInternalServerError, "audit log write failed")
				return
			}
		}

		rec.flushTo(w)
	}
}

// traceIDFromContext 从 OTel span context 提取 TraceID。
// 无 OTel span 时返回空字符串（调用方需 fallback 到随机生成）。
func traceIDFromContext(ctx context.Context) string {
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.HasTraceID() {
		return spanCtx.TraceID().String()
	}
	return ""
}
