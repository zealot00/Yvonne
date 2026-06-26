// Package api - BYOK 传输密钥与导入 handler。
package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"runtime"

	"yvonne/internal/seal"
)

// handleTransitPub 生成临时传输公钥。
//
// GET /api/v1/keys/transit-pub
//
// 返回 RSA-4096 公钥 PEM + keyID + 过期时间。
// 客户端用此公钥离线加密外部 DEK，然后通过 /keys/import 导入。
func (r *V1Router) handleTransitPub(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}

	pub, err := r.transitMgr.GenerateTransitKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "generate transit key failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":     pub.KeyID,
		"public_key": pub.PublicKey,
		"expires_at": pub.ExpiresAt,
	})
}

// importRequest 是 POST /api/v1/keys/import 的请求体。
type importRequest struct {
	KeyID           string `json:"key_id"`           // 导入后的 Yvonne 密钥标识
	TransitKeyID    string `json:"transit_key_id"`   // 传输密钥 ID（从 transit-pub 获取）
	WrappedMaterial string `json:"wrapped_material"` // 用 Transit 公钥加密的外部 DEK（Base64）
}

// handleImportKey 导入外部密钥（BYOK）。
//
// POST /api/v1/keys/import
//
// 流程：
//  1. 解析请求体
//  2. 用传输私钥 RSA-OAEP 解密 WrappedMaterial → 明文 DEK
//  3. 立即用 CMK 信封加密 → Yvonne 标准密文
//  4. 存入 DB（V1 Active）
//  5. 阅后即焚：传输私钥 Wipe + 明文 DEK Wipe
func (r *V1Router) handleImportKey(w http.ResponseWriter, req *http.Request) {
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

	var body importRequest
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
	if body.TransitKeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "transit_key_id is required")
		return
	}
	if body.WrappedMaterial == "" {
		writeJSONError(w, http.StatusBadRequest, "wrapped_material is required")
		return
	}

	// 解码 WrappedMaterial（Base64）。
	wrapped, err := base64.StdEncoding.DecodeString(body.WrappedMaterial)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid wrapped_material base64")
		return
	}

	// 调用 lifecycle.ImportKey 完成解包 + 加密 + 存储。
	var version int
	err = r.seal.KEKRef(func(kek seal.KEK) error {
		meta, e := r.manager.ImportKey(
			req.Context(),
			body.KeyID,
			body.TransitKeyID,
			wrapped,
			r.transitMgr,
			kek,
		)
		if e != nil {
			return e
		}
		version = meta.Version
		return nil
	})

	// 清理 wrapped 密文。
	clear(wrapped)
	runtime.KeepAlive(wrapped)

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "import failed")
		return
	}

	writeJSONOK(w, map[string]interface{}{
		"key_id":   body.KeyID,
		"version":  version,
		"state":    "Active",
		"imported": true,
	})
}
