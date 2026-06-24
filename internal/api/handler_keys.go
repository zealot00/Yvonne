// Package api - 密钥生命周期 handler（Create / Rotate / Shred）。
//
// 路由：
//
//	POST   /api/v1/keys              → handleCreateKey
//	POST   /api/v1/keys/{id}/rotate  → handleKeyOps（路径解析）
//	DELETE /api/v1/keys/{id}/shred   → handleKeyOps（路径解析）
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
)

// createKeyRequest 是 POST /api/v1/keys 的请求体。
type createKeyRequest struct {
	KeyID string `json:"key_id"`
}

// createKeyResponse 返回新创建的密钥信息。
// PlaintextDEK 是 base64 编码的明文 DEK，业务方用完需自行擦除。
type createKeyResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	PlaintextDEK []byte `json:"plaintext_dek"`
}

// handleCreateKey 创建新业务密钥（DEK）。
func (r *V1Router) handleCreateKey(w http.ResponseWriter, req *http.Request) {
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

	var body createKeyRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// 通过 MasterKeyRef 获取 Master Key，调用 lifecycle.CreateKey。
	var plaintextDEK *memguard.SecureBuffer
	var meta *struct {
		KeyID   string
		Version int
	}

	err = r.seal.MasterKeyRef(func(mk *memguard.SecureBuffer) error {
		m, pdek, e := r.manager.CreateKey(context.Background(), body.KeyID, mk)
		if e != nil {
			return e
		}
		plaintextDEK = pdek
		meta = &struct {
			KeyID   string
			Version int
		}{m.KeyID, m.Version}
		return nil
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create key failed")
		return
	}
	defer plaintextDEK.Wipe()

	// 取出明文 DEK 用于响应（base64 编码）。
	var dekBytes []byte
	_ = plaintextDEK.WithKey(func(secret []byte) error {
		dekBytes = append(dekBytes, secret...)
		return nil
	})
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	writeJSONOK(w, createKeyResponse{
		KeyID:        meta.KeyID,
		Version:      meta.Version,
		PlaintextDEK: dekBytes,
	})
}

// shredRequest 是 DELETE /api/v1/keys/{id}/shred 的请求体。
type shredRequest struct {
	Version int `json:"version"`
}

// handleKeyOps 处理 /api/v1/keys/{key_id}/rotate 和 /api/v1/keys/{key_id}/shred。
//
// 路径解析：Go 1.21 ServeMux 不支持路径参数，手动从 req.URL.Path 解析。
// /api/v1/keys/{key_id}/rotate → POST
// /api/v1/keys/{key_id}/shred  → DELETE
func (r *V1Router) handleKeyOps(w http.ResponseWriter, req *http.Request) {
	// 解析路径：/api/v1/keys/{key_id}/{action}
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/keys/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSONError(w, http.StatusNotFound, "invalid key path")
		return
	}
	keyID := parts[0]
	action := parts[1]

	if keyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	switch action {
	case "rotate":
		if !requireMethod(w, req, http.MethodPost) {
			return
		}
		r.handleRotateKey(w, req, keyID)
	case "shred":
		if !requireMethod(w, req, http.MethodDelete) {
			return
		}
		r.handleShredKey(w, req, keyID)
	case "soft-delete":
		if !requireMethod(w, req, http.MethodPatch) {
			return
		}
		r.handleSoftDeleteKey(w, req, keyID)
	case "restore":
		if !requireMethod(w, req, http.MethodPost) {
			return
		}
		r.handleRestoreKey(w, req, keyID)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown key operation: "+action)
	}
}

// handleRotateKey 轮转密钥。
func (r *V1Router) handleRotateKey(w http.ResponseWriter, req *http.Request, keyID string) {
	var plaintextDEK *memguard.SecureBuffer
	var newVersion int

	err := r.seal.MasterKeyRef(func(mk *memguard.SecureBuffer) error {
		m, pdek, e := r.manager.RotateKey(context.Background(), keyID, mk)
		if e != nil {
			return e
		}
		plaintextDEK = pdek
		newVersion = m.Version
		return nil
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "rotate key failed")
		return
	}
	defer plaintextDEK.Wipe()

	var dekBytes []byte
	_ = plaintextDEK.WithKey(func(secret []byte) error {
		dekBytes = append(dekBytes, secret...)
		return nil
	})
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	writeJSONOK(w, map[string]interface{}{
		"key_id":        keyID,
		"version":       newVersion,
		"plaintext_dek": dekBytes,
	})
}

// handleShredKey 物理粉碎密钥。
func (r *V1Router) handleShredKey(w http.ResponseWriter, req *http.Request, keyID string) {
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

	var body shredRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if body.Version < 1 {
		writeJSONError(w, http.StatusBadRequest, "version is required and must be >= 1")
		return
	}

	if err := r.manager.ShredKey(context.Background(), keyID, body.Version); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "shred key failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":  keyID,
		"version": body.Version,
		"shred":   true,
	})
}

// handleSoftDeleteKey 软删除（移入回收站）。
//
// PATCH /api/v1/keys/{key_id}/soft-delete
// Body: {"version": N}
//
// 软删除后：
//   - 数据保留在 DB（EncryptedMaterial 不变）
//   - 仍可解密历史密文
//   - 不可加密
//   - TTL 过期后自动物理粉碎
//   - 可通过 POST /keys/{key_id}/restore 恢复
func (r *V1Router) handleSoftDeleteKey(w http.ResponseWriter, req *http.Request, keyID string) {
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

	var body shredRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if body.Version < 1 {
		writeJSONError(w, http.StatusBadRequest, "version is required and must be >= 1")
		return
	}

	if err := r.manager.SoftDeleteKey(context.Background(), keyID, body.Version); err != nil {
		if err == lifecycle.ErrKeyDestroyed {
			writeJSONError(w, http.StatusBadRequest, "key is already destroyed")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "soft-delete failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":       keyID,
		"version":      body.Version,
		"soft_deleted": true,
		"restorable":   true,
	})
}

// handleRestoreKey 从回收站恢复。
//
// POST /api/v1/keys/{key_id}/restore
// Body: {"version": N}
//
// 恢复后状态为 Deactivated（非 Active），如需加密应 RotateKey。
func (r *V1Router) handleRestoreKey(w http.ResponseWriter, req *http.Request, keyID string) {
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

	var body shredRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if body.Version < 1 {
		writeJSONError(w, http.StatusBadRequest, "version is required and must be >= 1")
		return
	}

	if err := r.manager.RestoreKey(context.Background(), keyID, body.Version); err != nil {
		if err == lifecycle.ErrKeyDestroyed {
			writeJSONError(w, http.StatusBadRequest, "key is destroyed, cannot restore")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "restore failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":   keyID,
		"version":  body.Version,
		"restored": true,
		"state":    "Deactivated",
		"note":     "restored as Deactivated; rotate to make Active for encryption",
	})
}
