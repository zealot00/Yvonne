// v1.2 新增 API 单元测试。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newV12TestRouter 创建 v1.2 测试 router。
// 返回 router + manager + vault 的 master key（用于创建 KEK）。
func newV12TestRouter(t *testing.T) (*V1Router, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	var auditBuf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(auditLog.Close)

	router := NewV1Router(vault, auditLog, mgr, nil, nil)
	return router, mgr, mk
}

// TestV12_GenerateMacGenerateMac HMAC 生成。
func TestV12_GenerateMacGenerateMac(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()

	// 创建对称密钥。
	mgr.CreateKey(ctx, "mac-key", seal.NewSoftwareKEK(mk), 0)

	// 生成 MAC。
	body := signRequest{KeyID: "mac-key", Data: []byte("hello mac")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mac/generate", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1GenerateMac(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GenerateMac: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			Mac     []byte `json:"mac"`
			Version int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data.Mac) == 0 {
		t.Fatal("mac should not be empty")
	}
	t.Logf("✅ Generated MAC: %d bytes, v%d", len(resp.Data.Mac), resp.Data.Version)
}

// TestV12_GenerateMacVerifyMac HMAC 生成 + 验证往返。
func TestV12_GenerateMacVerifyMac(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)
	mgr.CreateKey(ctx, "mac-verify-key", kek, 0)

	// 1. 生成 MAC。
	genBody := signRequest{KeyID: "mac-verify-key", Data: []byte("test data")}
	genJSON, _ := json.Marshal(genBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mac/generate", bytes.NewReader(genJSON))
	w := httptest.NewRecorder()
	router.handleV1GenerateMac(w, req)

	var genResp struct {
		Data struct {
			Mac []byte `json:"mac"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &genResp)
	t.Logf("GenerateMac response: %s", w.Body.String())
	t.Logf("Generated MAC: %x", genResp.Data.Mac)

	// 2. 验证 MAC（正确）。
	verifyBody := verifyMacRequest{KeyID: "mac-verify-key", Data: []byte("test data"), Mac: genResp.Data.Mac}
	verifyJSON, _ := json.Marshal(verifyBody)

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/mac/verify", bytes.NewReader(verifyJSON))
	w2 := httptest.NewRecorder()
	router.handleV1VerifyMac(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("VerifyMac: got %d, want 200", w2.Code)
	}

	var verifyResp struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &verifyResp)
	if !verifyResp.Data.Valid {
		t.Fatalf("MAC should be valid, response: %s", w2.Body.String())
	}
	t.Log("✅ MAC verify (correct) passed")

	// 3. 验证 MAC（错误数据）。
	verifyBody2 := verifyMacRequest{KeyID: "mac-verify-key", Data: []byte("wrong data"), Mac: genResp.Data.Mac}
	verifyJSON2, _ := json.Marshal(verifyBody2)

	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/mac/verify", bytes.NewReader(verifyJSON2))
	w3 := httptest.NewRecorder()
	router.handleV1VerifyMac(w3, req3)

	var verifyResp2 struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w3.Body.Bytes(), &verifyResp2)
	if verifyResp2.Data.Valid {
		t.Fatal("MAC should be invalid for wrong data")
	}
	t.Log("✅ MAC verify (wrong data) correctly rejected")
}

// TestV12_GenerateMacWrongKeyType 非对称密钥拒绝 MAC。
func TestV12_GenerateMacWrongKeyType(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()

	// 创建非对称密钥。
	mgr.CreateAsymmetricKey(ctx, "rsa-key", "rsa", seal.NewSoftwareKEK(mk))

	body := signRequest{KeyID: "rsa-key", Data: []byte("test")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mac/generate", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1GenerateMac(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for asymmetric key, got %d", w.Code)
	}
	t.Log("✅ MAC with asymmetric key correctly rejected")
}

// TestV12_GetPublicKey 获取公钥。
func TestV12_GetPublicKey(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()

	// 创建非对称密钥。
	mgr.CreateAsymmetricKey(ctx, "asym-key", "rsa", seal.NewSoftwareKEK(mk))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key?key_id=asym-key", nil)
	w := httptest.NewRecorder()
	router.handleV1GetPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetPublicKey: got %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			PublicKey []byte `json:"public_key"`
			Version   int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data.PublicKey) == 0 {
		t.Fatal("public key should not be empty")
	}
	t.Logf("✅ GetPublicKey: %d bytes, v%d", len(resp.Data.PublicKey), resp.Data.Version)
}

// TestV12_GetPublicKeySymmetric 对称密钥无公钥。
func TestV12_GetPublicKeySymmetric(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "sym-key", seal.NewSoftwareKEK(mk), 0)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key?key_id=sym-key", nil)
	w := httptest.NewRecorder()
	router.handleV1GetPublicKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for symmetric key, got %d", w.Code)
	}
	t.Log("✅ GetPublicKey with symmetric key correctly rejected")
}

// TestV12_GDKWithoutPlaintext 生成无明文 DEK。
func TestV12_GDKWithoutPlaintext(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "gdk-key", seal.NewSoftwareKEK(mk), 0)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/gdk-no-plaintext?key_id=gdk-key", nil)
	w := httptest.NewRecorder()
	router.handleV1GDKWithoutPlaintext(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GDKWithoutPlaintext: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Ciphertext []byte `json:"ciphertext"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data.Ciphertext) == 0 {
		t.Fatal("ciphertext should not be empty")
	}
	t.Logf("✅ GDKWithoutPlaintext: %d bytes ciphertext", len(resp.Data.Ciphertext))
}

// TestV12_SignKeyNotFound 不存在的密钥。
func TestV12_SignKeyNotFound(t *testing.T) {
	router, _, _ := newV12TestRouter(t)

	body := signRequest{KeyID: "nonexistent", Data: []byte("test")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Sign(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for nonexistent key, got %d", w.Code)
	}
	t.Log("✅ Sign with nonexistent key correctly failed")
}

// TestV12_SignSymmetricKey 对称密钥拒绝签名。
func TestV12_SignSymmetricKey(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "sym-key", seal.NewSoftwareKEK(mk), 0)

	body := signRequest{KeyID: "sym-key", Data: []byte("test")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Sign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for symmetric key sign, got %d", w.Code)
	}
	t.Log("✅ Sign with symmetric key correctly rejected")
}

// TestV12_EmptyKeyID 空key_id 拒绝。
func TestV12_EmptyKeyID(t *testing.T) {
	router, _, _ := newV12TestRouter(t)

	body := signRequest{KeyID: "", Data: []byte("test")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Sign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty key_id, got %d", w.Code)
	}
	t.Log("✅ Empty key_id correctly rejected")
}

// getTestMK 获取测试用 Master Key。
func getTestMK(t *testing.T) *memguard.SecureBuffer {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	return mk
}
