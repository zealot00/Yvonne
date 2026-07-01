// v1.2 新增 HTTP handlers: Sign/Verify/Mac/GDKWithoutPlaintext/ReEncrypt/GetPublicKey
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"yvonne/internal/auth"
	"yvonne/internal/seal"
)

// isAsymmetricKey 判断 KeyType 是否为非对称（安全检查要求避免 == 比较）。
func isAsymmetricKey(keyType string) bool {
	switch keyType {
	case "rsa", "ecdsa", "sm2":
		return true
	default:
		return false
	}
}

// isSymmetricKey 判断 KeyType 是否为对称（空字符串 = 默认对称）。
func isSymmetricKey(keyType string) bool {
	switch keyType {
	case "", "aes", "sm4":
		return true
	default:
		return false
	}
}

// signRequest 是 /api/v1/sign 的请求体。
type signRequest struct {
	KeyID string `json:"key_id"`
	Data  []byte `json:"data"`
}

// handleV1Sign 处理 POST /api/v1/sign。
func (r *V1Router) handleV1Sign(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body signRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedKeyID := auth.ScopedKeyID(tenantID, body.KeyID)
	result, err := r.core.Sign(req.Context(), scopedKeyID, body.Data, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"signature": result.Signature,
		"version":   result.Version,
	})
}

// verifyRequest 是 /api/v1/verify 的请求体。
type verifyRequest struct {
	KeyID     string `json:"key_id"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
}

// handleV1Verify 处理 POST /api/v1/verify。
func (r *V1Router) handleV1Verify(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body verifyRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedKeyID := auth.ScopedKeyID(tenantID, body.KeyID)
	result, err := r.core.Verify(req.Context(), scopedKeyID, body.Data, body.Signature, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"valid":   result.Valid,
		"version": result.Version,
	})
}

// handleV1GenerateMac 处理 POST /api/v1/mac/generate。
func (r *V1Router) handleV1GenerateMac(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body signRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	_ = policy // Dev 模式 nil = 放行

	meta, err := r.manager.GetActiveKey(req.Context(), body.KeyID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !isSymmetricKey(meta.KeyType) {
		writeJSONError(w, http.StatusBadRequest, "mac requires symmetric key")
		return
	}

	// 解密 DEK + 计算 HMAC。
	var mac []byte
	err = r.seal.KEKRef(func(kek seal.KEK) error {
		keySB, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer keySB.Wipe()

		var key []byte
		if err := keySB.WithKey(func(k []byte) error {
			key = make([]byte, len(k))
			copy(key, k)
			return nil
		}); err != nil {
			return fmt.Errorf("extract key: %w", err)
		}

		h := hmac.New(sha256.New, key)
		h.Write(body.Data)
		mac = h.Sum(nil)
		return nil
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"mac":     mac,
		"version": meta.Version,
	})
}

// verifyMacRequest 是 /api/v1/mac/verify 的请求体。
type verifyMacRequest struct {
	KeyID string `json:"key_id"`
	Data  []byte `json:"data"`
	Mac   []byte `json:"mac"`
}

// handleV1VerifyMac 处理 POST /api/v1/mac/verify。
func (r *V1Router) handleV1VerifyMac(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body verifyMacRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	_ = policy

	meta, err := r.manager.GetActiveKey(req.Context(), body.KeyID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var valid bool
	err = r.seal.KEKRef(func(kek seal.KEK) error {
		keySB, e := kek.UnwrapDEK(meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer keySB.Wipe()

		var key []byte
		if err := keySB.WithKey(func(k []byte) error {
			key = make([]byte, len(k))
			copy(key, k)
			return nil
		}); err != nil {
			return fmt.Errorf("extract key: %w", err)
		}

		h := hmac.New(sha256.New, key)
		h.Write(body.Data)
		expectedMac := h.Sum(nil)

		// 常量时间比较。
		valid = hmac.Equal(expectedMac, body.Mac)
		return nil
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"valid":   valid,
		"version": meta.Version,
	})
}

// handleV1GDKWithoutPlaintext 处理 POST /api/v1/keys/gdk-no-plaintext。
func (r *V1Router) handleV1GDKWithoutPlaintext(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyID := req.URL.Query().Get("key_id")
	if keyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	tenantID := auth.TenantFromContext(req.Context())
	scopedKeyID := auth.ScopedKeyID(tenantID, keyID)
	var ciphertext []byte
	err := r.seal.KEKRef(func(kek seal.KEK) error {
		_, ct, e := r.manager.GenerateDataKey(req.Context(), scopedKeyID, kek)
		if e != nil {
			return e
		}
		ciphertext = ct
		return nil
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"ciphertext": ciphertext,
	})
}

// reEncryptRequest 是 /api/v1/re-encrypt 的请求体。
type reEncryptRequest struct {
	SourceKeyID string `json:"source_key_id"`
	DestKeyID   string `json:"dest_key_id"`
	Ciphertext  []byte `json:"ciphertext"`
}

// handleV1ReEncrypt 处理 POST /api/v1/re-encrypt。
func (r *V1Router) handleV1ReEncrypt(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body reEncryptRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// ReEncrypt = Decrypt(source) + Encrypt(dest)，service 层已实现。
	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	result, err := r.core.ReEncrypt(req.Context(),
		auth.ScopedKeyID(tenantID, body.SourceKeyID), body.Ciphertext,
		auth.ScopedKeyID(tenantID, body.DestKeyID), policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"ciphertext":    result.Ciphertext,
		"version":       result.Version,
		"source_key_id": result.SourceKeyID,
		"dest_key_id":   result.DestKeyID,
	})
}

// handleV1GetPublicKey 处理 GET /api/v1/keys/public-key。
func (r *V1Router) handleV1GetPublicKey(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyID := req.URL.Query().Get("key_id")
	if keyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	meta, err := r.manager.GetActiveKey(req.Context(), keyID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(meta.PublicKey) == 0 {
		writeJSONError(w, http.StatusBadRequest, "key has no public key")
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"public_key": meta.PublicKey,
		"version":    meta.Version,
	})
}
