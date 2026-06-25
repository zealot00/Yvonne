// Package api - 系统管理 handler（health + unseal）。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"runtime"

	"yvonne/internal/memguard"
)

// handleHealth 健康检查端点。Sealed 状态也算存活。
func (r *V1Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"status": "alive",
		"sealed": r.seal.IsSealed(),
		"state":  r.seal.State().String(),
	})
}

// sysUnsealRequest 是 /api/v1/sys/unseal 的请求体。
type sysUnsealRequest struct {
	Share []byte `json:"share"`
}

// handleSysUnseal 提交单份 Shamir Share 推进解封。
func (r *V1Router) handleSysUnseal(w http.ResponseWriter, req *http.Request) {
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

	var body sysUnsealRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 提交 Share。ProvideShare 内部会拷贝 share，此处可安全清理。
	unsealed, err := r.seal.ProvideShare(body.Share)
	clear(body.Share)
	runtime.KeepAlive(body.Share)

	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if err != nil {
		if unsealed {
			writeJSONOK(w, map[string]interface{}{"unsealed": true, "note": "already unsealed, extra share rejected"})
			return
		}
		writeJSONError(w, http.StatusBadRequest, "unseal failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{"unsealed": unsealed})
}

// 确保 memguard 包被引用（未来可能用于 share 的 SecureBuffer 封装）。
var _ = memguard.NewSecureBuffer

// panicRequest 是 POST /api/v1/sys/panic 的请求体。
type panicRequest struct {
	AdminToken string `json:"admin_token"`
	Confirm    bool   `json:"confirm"` // 必须为 true，防止误触发
}

// handleEmergencySeal 紧急封印接口。
//
// 需要极高的权限验证（独立验证 Admin Token）。
// 调用后触发 EmergencySeal，强制落盘 FATAL 审计日志。
//
// 安全：
//   - 必须传 confirm=true 防止误触发。
//   - Admin Token 通过 subtle.ConstantTimeCompare 校验。
//   - 调用后系统进入深度冰冻，拒绝一切 API 请求。
func (r *V1Router) handleEmergencySeal(w http.ResponseWriter, req *http.Request) {
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

	var body panicRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	// 1. 必须传 confirm=true。
	if !body.Confirm {
		writeJSONError(w, http.StatusBadRequest, "confirm must be true to trigger emergency seal")
		return
	}

	// 2. 验证 Admin Token。
	if r.adminToken == "" {
		writeJSONError(w, http.StatusForbidden, "emergency seal not configured (no admin token set)")
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.AdminToken), []byte(r.adminToken)) != 1 {
		writeJSONError(w, http.StatusForbidden, "invalid admin token")
		return
	}

	// 3. 清理请求中的 token 明文（string 不可 clear，覆盖为空串）。
	body.AdminToken = ""

	// 4. 触发紧急封印。
	r.seal.EmergencySeal(req.Context())

	// 4b. 清空 DEK 缓存——紧急封印后缓存中的明文 DEK 不可继续使用。
	if r.manager != nil {
		r.manager.ClearCache()
	}

	// 5. 返回响应（审计日志由 auditMiddleware 自动记录，Action=EmergencySeal, Status=success）。
	writeJSONOK(w, map[string]interface{}{
		"emergency_sealed": true,
		"message":          "vault is now emergency sealed. all operations refused until process restart + shamir unseal.",
	})
}
