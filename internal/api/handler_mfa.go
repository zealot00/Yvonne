// Package api - MFA（TOTP）API handler。
//
// 端点:
//
//	POST /api/v1/auth/mfa/setup   — 注册 TOTP（返回 secret + QR code URI）
//	POST /api/v1/auth/mfa/verify  — 验证 TOTP code（绑定 MFA）
//	POST /api/v1/auth/mfa/disable — 禁用 MFA
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"

	"yvonne/internal/auth"
)

// mfaSetupRequest 是 /api/v1/auth/mfa/setup 的请求体。
type mfaSetupRequest struct {
	RoleID string `json:"role_id"` // 目标角色（管理员为其他角色设置，或自己设置）
}

// mfaSetupResponse 是 setup 的响应。
type mfaSetupResponse struct {
	Secret  string `json:"secret"`  // base32 TOTP secret
	URI     string `json:"uri"`     // otpauth:// URI（生成 QR code）
	Issuer  string `json:"issuer"`  // 发行方
	Account string `json:"account"` // 账户标识
}

// handleMFASetup 处理 POST /api/v1/auth/mfa/setup。
// 生成 TOTP secret，返回 QR code URI 供用户扫描。
// 此时 MFA 尚未启用，需 verify 后才生效。
func (r *V1Router) handleMFASetup(w http.ResponseWriter, req *http.Request) {
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

	var body mfaSetupRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.RoleID == "" {
		writeJSONError(w, http.StatusBadRequest, "role_id is required")
		return
	}

	// 从 context 获取 Policy（权限校验：管理员或自己）。
	policy := auth.PolicyFromContext(req.Context())
	if policy == nil {
		writeJSONError(w, http.StatusForbidden, "authentication required")
		return
	}
	// 仅允许为自己设置 MFA（或管理员，后续可扩展）。
	if policy.RoleID != body.RoleID {
		writeJSONError(w, http.StatusForbidden, "can only setup MFA for yourself")
		return
	}

	// 生成 TOTP secret。
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 保存 MFA 状态（未启用，待 verify）。
	state := &auth.MFAState{
		RoleID:    body.RoleID,
		Secret:    secret,
		Enabled:   false,
		CreatedAt: time.Now().UTC(),
	}
	if err := r.mfaStore.SaveMFAState(state); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	issuer := "Yvonne KMS"
	uri := auth.BuildTOTPURI(issuer, body.RoleID, secret)

	writeJSONOK(w, mfaSetupResponse{
		Secret:  secret,
		URI:     uri,
		Issuer:  issuer,
		Account: body.RoleID,
	})
}

// mfaVerifyRequest 是 /api/v1/auth/mfa/verify 的请求体。
type mfaVerifyRequest struct {
	RoleID string `json:"role_id"`
	Code   string `json:"code"` // 6 位 TOTP code
}

// handleMFAVerify 处理 POST /api/v1/auth/mfa/verify。
// 验证 TOTP code，验证通过后启用 MFA。
func (r *V1Router) handleMFAVerify(w http.ResponseWriter, req *http.Request) {
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

	var body mfaVerifyRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.RoleID == "" || body.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "role_id and code are required")
		return
	}

	// 获取 MFA 状态。
	state, err := r.mfaStore.GetMFAState(body.RoleID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "mfa not setup, call setup first")
		return
	}

	// 验证 TOTP code。
	if err := auth.ValidateTOTP(state.Secret, body.Code, nil); err != nil {
		writeJSONError(w, http.StatusForbidden, "invalid TOTP code")
		return
	}

	// 启用 MFA。
	state.Enabled = true
	state.VerifiedAt = time.Now().UTC()
	if err := r.mfaStore.SaveMFAState(state); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"role_id": body.RoleID,
		"enabled": true,
	})
}

// mfaDisableRequest 是 /api/v1/auth/mfa/disable 的请求体。
type mfaDisableRequest struct {
	RoleID string `json:"role_id"`
	Code   string `json:"code"` // 需验证当前 TOTP code 才能禁用
}

// handleMFADisable 处理 POST /api/v1/auth/mfa/disable。
// 禁用 MFA（需验证当前 TOTP code 防误操作）。
func (r *V1Router) handleMFADisable(w http.ResponseWriter, req *http.Request) {
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

	var body mfaDisableRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.RoleID == "" || body.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "role_id and code are required")
		return
	}

	// 获取 MFA 状态。
	state, err := r.mfaStore.GetMFAState(body.RoleID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "mfa not setup")
		return
	}

	// 验证 TOTP code（防误操作）。
	if err := auth.ValidateTOTP(state.Secret, body.Code, nil); err != nil {
		writeJSONError(w, http.StatusForbidden, "invalid TOTP code")
		return
	}

	// 删除 MFA 绑定。
	if err := r.mfaStore.DeleteMFAState(body.RoleID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"role_id": body.RoleID,
		"enabled": false,
	})
}
