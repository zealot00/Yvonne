// Package api - 密钥生命周期 handler（Create / Rotate / Shred）。
//
// 路由：
//
//	POST   /api/v1/keys              → handleCreateKey
//	POST   /api/v1/keys/{id}/rotate  → handleKeyOps（路径解析）
//	DELETE /api/v1/keys/{id}/shred   → handleKeyOps（路径解析）
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// createKeyRequest 是 POST /api/v1/keys 的请求体。
type createKeyRequest struct {
	KeyID     string `json:"key_id"`
	ReturnDEK *bool  `json:"return_dek,omitempty"` // 可选，默认 true；false 时不返回明文 DEK
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

	err = r.seal.KEKRef(func(kek seal.KEK) error {
		m, pdek, e := r.manager.CreateKey(req.Context(), body.KeyID, kek, 0)
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

	// 判断是否需要返回明文 DEK（默认 true）。
	returnDEK := true
	if body.ReturnDEK != nil {
		returnDEK = *body.ReturnDEK
	}

	// 响应：强制 no-store 防止明文 DEK 被缓存。
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")

	if !returnDEK {
		// 不返回明文 DEK（客户端只能通过 GDK 获取）。
		writeJSONOK(w, createKeyResponse{
			KeyID:        meta.KeyID,
			Version:      meta.Version,
			PlaintextDEK: nil, // 明文 DEK 已在 defer 中 Wipe
		})
		return
	}

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
	case "generate-data-key":
		if !requireMethod(w, req, http.MethodPost) {
			return
		}
		r.handleGenerateDataKey(w, req, keyID)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown key operation: "+action)
	}
}

// handleRotateKey 轮转密钥。
func (r *V1Router) handleRotateKey(w http.ResponseWriter, req *http.Request, keyID string) {
	var plaintextDEK *memguard.SecureBuffer
	var newVersion int

	err := r.seal.KEKRef(func(kek seal.KEK) error {
		m, pdek, e := r.manager.RotateKey(req.Context(), keyID, kek)
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

	if err := r.manager.ShredKey(req.Context(), keyID, body.Version); err != nil {
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

	if err := r.manager.SoftDeleteKey(req.Context(), keyID, body.Version); err != nil {
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

	if err := r.manager.RestoreKey(req.Context(), keyID, body.Version); err != nil {
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

// gdkResponse 是 GenerateDataKey 的响应结构。
// PlaintextDEK 是 []byte，JSON 编码时自动 base64。
// CiphertextDEK 是版本化密文 []byte，JSON 编码时自动 base64。
type gdkResponse struct {
	OK   bool `json:"ok"`
	Data struct {
		KeyID         string `json:"key_id"`
		PlaintextDEK  []byte `json:"plaintext_dek"`
		CiphertextDEK []byte `json:"ciphertext_dek"`
	} `json:"data"`
}

// handleGenerateDataKey 生成临时 DEK 并返回明文+密文。
//
// POST /api/v1/keys/{key_id}/generate-data-key
//
// 致命内存流转约束：
//   - 明文 DEK 从 SecureBuffer 提取后装入 []byte 用于 JSON 编码。
//   - JSON 写入 ResponseWriter 后，立即 clear() 擦除明文 []byte。
//   - SecureBuffer 本身由 defer Wipe 擦除。
//
// 审计防泄漏：
//   - 审计日志记录 Action=GenerateDataKey，但绝不记录明文/密文 DEK。
func (r *V1Router) handleGenerateDataKey(w http.ResponseWriter, req *http.Request, keyID string) {
	// 1. 调用 lifecycle 生成临时 DEK + 密文。
	var plainDEK *memguard.SecureBuffer
	var ciphertext []byte

	err := r.seal.KEKRef(func(kek seal.KEK) error {
		var e error
		plainDEK, ciphertext, e = r.manager.GenerateDataKey(req.Context(), keyID, kek)
		return e
	})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "generate data key failed")
		return
	}
	defer plainDEK.Wipe()

	// 2. 从 SecureBuffer 提取明文 DEK 副本用于 JSON 响应。
	var rawDEK []byte
	_ = plainDEK.WithKey(func(dek []byte) error {
		rawDEK = make([]byte, len(dek))
		copy(rawDEK, dek)
		return nil
	})
	// 致命约束：响应发送后立即 clear 明文 DEK 副本。
	defer func() {
		clear(rawDEK)
		runtime.KeepAlive(rawDEK)
	}()

	// 3. 手动构造 JSON（不走 writeJSONOK，因为需要精确控制 clear 时机）。
	resp := gdkResponse{OK: true}
	resp.Data.KeyID = keyID
	resp.Data.PlaintextDEK = rawDEK
	resp.Data.CiphertextDEK = ciphertext

	out, err := json.Marshal(resp)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "marshal response failed")
		return
	}

	// 4. 写入 HTTP 响应（强制 no-store 防止明文 DEK 被缓存）。
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)

	// 5. 立即擦除 JSON 序列化缓冲（含 base64 编码的明文 DEK）。
	clear(out)
	runtime.KeepAlive(out)

	// 6. rawDEK 由 defer clear 擦除（函数返回时执行）。
	// plainDEK 由 defer Wipe 擦除。
}

// createAsymmetricKeyRequest 是 /api/v1/keys/asymmetric 的请求体。
type createAsymmetricKeyRequest struct {
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type"` // rsa | ecdsa | sm2
}

// handleCreateAsymmetricKey 处理 POST /api/v1/keys/asymmetric。
// 创建非对称密钥（RSA-4096 / ECDSA P-256 / SM2），公钥返回给客户端。
func (r *V1Router) handleCreateAsymmetricKey(w http.ResponseWriter, req *http.Request) {
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

	var body createAsymmetricKeyRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// 校验 key_type。
	switch body.KeyType {
	case "rsa", "ecdsa", "sm2":
		// 合法值。
	default:
		writeJSONError(w, http.StatusBadRequest, "key_type must be rsa, ecdsa, or sm2")
		return
	}

	// 通过 KEKRef 获取 KEK，调用 lifecycle.CreateAsymmetricKey。
	var meta *lifecycle.KeyMetadata
	err = r.seal.KEKRef(func(kek seal.KEK) error {
		m, e := r.manager.CreateAsymmetricKey(req.Context(), body.KeyID, body.KeyType, kek)
		if e != nil {
			return e
		}
		meta = m
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":     meta.KeyID,
		"version":    meta.Version,
		"key_type":   meta.KeyType,
		"public_key": meta.PublicKey,
	})
}
