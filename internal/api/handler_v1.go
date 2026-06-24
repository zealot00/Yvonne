// Package api - v1 加解密 handler（终极蓝图对齐版：自路由密文 + 状态机强制）。
//
// 密文格式（Self-Routing Ciphertext）：
//
//	[Version (uint32, 4 bytes, BigEndian)] [Nonce (12 bytes)] [Ciphertext + AuthTag]
//
// encrypt：强制向 lifecycle 请求 Active 版本的 DEK。
// decrypt：从密文头部解析 KeyVersion，精准请求对应版本；
//
//	Active/Deactivated 允许解密，Destroyed 返回 400。
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"

	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
)

// encryptRequest 是 /api/v1/encrypt 的请求体。
type encryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"` // base64 自动解码
}

// encryptResponse 返回密文与 DEK 版本。
type encryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Version    int    `json:"version"`
}

// handleV1Encrypt 加密业务数据。
//
// 流程：
//  1. 读取 body → clear+KeepAlive
//  2. 向 lifecycle 请求 Active 版本（GetActiveKey）
//  3. 用 MasterKey 解密 DEK 密文 → 明文 DEK（SecureBuffer）
//  4. 用明文 DEK 加密业务明文
//  5. 组装自路由密文：[Version uint32 BE][Nonce][Ciphertext+AuthTag]
//  6. Wipe 明文 DEK
func (r *V1Router) handleV1Encrypt(w http.ResponseWriter, req *http.Request) {
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

	var body encryptRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 明文立刻装入 SecureBuffer。
	plaintextSB := memguard.NewSecureBuffer(body.Plaintext)
	clear(body.Plaintext)
	runtime.KeepAlive(body.Plaintext)
	defer plaintextSB.Wipe()

	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)
	bodyBytes = nil

	if body.KeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	ctx := context.Background()

	// 强制请求 Active 版本（状态机硬编码：只有 Active 能加密）。
	meta, err := r.manager.GetActiveKey(ctx, body.KeyID)
	if err != nil {
		if err == lifecycle.ErrKeyNotActive {
			writeJSONError(w, http.StatusForbidden, "key is not active, encrypt refused")
			return
		}
		writeJSONError(w, http.StatusNotFound, "active key not found")
		return
	}

	// 用 MasterKey 解密 DEK，然后用 DEK 加密业务明文（优化：单次分配）。
	var ciphertext []byte
	err = r.seal.MasterKeyRef(func(mk *memguard.SecureBuffer) error {
		// 解密 DEK。
		plaintextDEK, e := crypto.DecryptGCM(mk, meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer plaintextDEK.Wipe()

		// 用 DEK 加密业务明文（EncryptVersioned 直接输出自路由格式，零中间拷贝）。
		var encErr error
		_ = plaintextSB.WithKey(func(plain []byte) error {
			ciphertext, encErr = crypto.EncryptVersioned(plaintextDEK, uint32(meta.Version), plain)
			return nil
		})
		return encErr
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "encrypt failed")
		return
	}

	writeJSONOK(w, encryptResponse{
		Ciphertext: ciphertext,
		Version:    meta.Version,
	})
}

// decryptRequest 是 /api/v1/decrypt 的请求体。
type decryptRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
}

// decryptResponse 返回明文与 DEK 版本。
type decryptResponse struct {
	Plaintext []byte `json:"plaintext"`
	Version   int    `json:"version"`
}

// handleV1Decrypt 解密业务数据。
//
// 流程：
//  1. 从密文头部解析 KeyVersion（4 字节 uint32 BigEndian）
//  2. 向 lifecycle 请求 (KeyID, KeyVersion) — GetKeyForDecrypt
//     - Active/Deactivated：允许解密
//     - Destroyed：返回 400
//  3. 用 MasterKey 解密 DEK → 用 DEK 解密业务密文
//  4. Wipe 明文 DEK
func (r *V1Router) handleV1Decrypt(w http.ResponseWriter, req *http.Request) {
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

	var body decryptRequest
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
	if len(body.Ciphertext) < crypto.MinCiphertextSize {
		writeJSONError(w, http.StatusBadRequest, "ciphertext too short")
		return
	}

	// 1. 从密文头部解析版本号（自路由）。
	version, _, _, err := crypto.DecodeVersionedCiphertext(body.Ciphertext)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid ciphertext format")
		return
	}

	ctx := context.Background()

	// 2. 精准请求对应版本（状态机强制：Destroyed 拒绝）。
	meta, err := r.manager.GetKeyForDecrypt(ctx, body.KeyID, int(version))
	if err != nil {
		if err == lifecycle.ErrKeyDestroyed {
			writeJSONError(w, http.StatusBadRequest, "key version is destroyed, decrypt refused")
			return
		}
		writeJSONError(w, http.StatusNotFound, "key version not found")
		return
	}

	// 3. 用 MasterKey 解密 DEK，然后用 DEK 解密业务密文（优化：零中间拷贝）。
	var plaintextSB *memguard.SecureBuffer
	err = r.seal.MasterKeyRef(func(mk *memguard.SecureBuffer) error {
		// 解密 DEK。
		plaintextDEK, e := crypto.DecryptGCM(mk, meta.EncryptedMaterial)
		if e != nil {
			return e
		}
		defer plaintextDEK.Wipe()

		// 用 DEK 解密业务密文（DecryptVersioned 直接解析自路由格式）。
		plaintextSB, _, e = crypto.DecryptVersioned(plaintextDEK, body.Ciphertext)
		return e
	})

	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	defer plaintextSB.Wipe()

	// 取出明文用于响应。
	var plaintextCopy []byte
	_ = plaintextSB.WithKey(func(secret []byte) error {
		plaintextCopy = append(plaintextCopy, secret...)
		return nil
	})
	defer func() {
		for i := range plaintextCopy {
			plaintextCopy[i] = 0
		}
	}()

	writeJSONOK(w, decryptResponse{
		Plaintext: plaintextCopy,
		Version:   int(version),
	})
}

// findLatestActiveVersion 已废弃，由 lifecycle.GetActiveKey 替代。
// 保留空函数避免外部引用断裂。
func (r *V1Router) findLatestActiveVersion(ctx context.Context, keyID string) (int, error) {
	return 0, lifecycle.ErrKeyNotActive
}

// 确保 lifecycle 包被引用。
var _ = lifecycle.StateActive
