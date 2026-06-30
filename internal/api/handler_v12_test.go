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

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent key, got %d", w.Code)
	}
	t.Log("✅ Sign with nonexistent key correctly failed (404)")
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

// === Day 4: Sign/Verify/ReEncrypt/AsymmetricKey 测试 ===

// createAsymKeyViaAPI 通过 API 创建非对称密钥。
func createAsymKeyViaAPI(t *testing.T, router *V1Router, keyID, keyType string) []byte {
	t.Helper()
	body := createAsymmetricKeyRequest{KeyID: keyID, KeyType: keyType}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asymmetric", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleCreateAsymmetricKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("createAsymmetricKey %s: got %d, want 200, body=%s", keyType, w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			PublicKey []byte `json:"public_key"`
			Version   int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Data.PublicKey
}

// signViaAPI 通过 API 签名。
func signViaAPI(t *testing.T, router *V1Router, keyID string, data []byte) []byte {
	t.Helper()
	body := signRequest{KeyID: keyID, Data: data}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Sign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Sign: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Signature []byte `json:"signature"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Data.Signature
}

// verifyViaAPI 通过 API 验签，返回 valid。
func verifyViaAPI(t *testing.T, router *V1Router, keyID string, data, sig []byte) bool {
	t.Helper()
	body := verifyRequest{KeyID: keyID, Data: data, Signature: sig}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/verify", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Verify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Verify: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Data.Valid
}

// TestV12_CreateAsymmetricKey_RSA 创建 RSA 密钥。
func TestV12_CreateAsymmetricKey_RSA(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	pubPEM := createAsymKeyViaAPI(t, router, "rsa-key", "rsa")
	if len(pubPEM) == 0 {
		t.Fatal("RSA public key should not be empty")
	}
	t.Logf("✅ CreateAsymmetricKey RSA: %d bytes public key", len(pubPEM))
}

// TestV12_CreateAsymmetricKey_ECDSA 创建 ECDSA 密钥。
func TestV12_CreateAsymmetricKey_ECDSA(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	pubPEM := createAsymKeyViaAPI(t, router, "ecdsa-key", "ecdsa")
	if len(pubPEM) == 0 {
		t.Fatal("ECDSA public key should not be empty")
	}
	t.Logf("✅ CreateAsymmetricKey ECDSA: %d bytes public key", len(pubPEM))
}

// TestV12_CreateAsymmetricKey_InvalidKeyType 非法 key_type 拒绝。
func TestV12_CreateAsymmetricKey_InvalidKeyType(t *testing.T) {
	router, _, _ := newV12TestRouter(t)

	body := createAsymmetricKeyRequest{KeyID: "bad-key", KeyType: "aes"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asymmetric", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleCreateAsymmetricKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid key_type, got %d", w.Code)
	}
	t.Log("✅ Invalid key_type correctly rejected")
}

// TestV12_CreateAsymmetricKey_EmptyKeyID 空 key_id 拒绝。
func TestV12_CreateAsymmetricKey_EmptyKeyID(t *testing.T) {
	router, _, _ := newV12TestRouter(t)

	body := createAsymmetricKeyRequest{KeyID: "", KeyType: "rsa"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asymmetric", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleCreateAsymmetricKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty key_id, got %d", w.Code)
	}
	t.Log("✅ Empty key_id correctly rejected")
}

// TestV12_SignVerify_RSA RSA 签名 + 验签往返。
func TestV12_SignVerify_RSA(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	createAsymKeyViaAPI(t, router, "rsa-sign", "rsa")

	data := []byte("hello RSA")
	sig := signViaAPI(t, router, "rsa-sign", data)

	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}
	t.Logf("✅ RSA Sign: %d bytes", len(sig))

	// 验签（正确）。
	valid := verifyViaAPI(t, router, "rsa-sign", data, sig)
	if !valid {
		t.Fatal("RSA verify should be valid")
	}
	t.Log("✅ RSA Verify: valid=true")

	// 验签（篡改数据）。
	valid = verifyViaAPI(t, router, "rsa-sign", []byte("tampered"), sig)
	if valid {
		t.Fatal("RSA verify should reject tampered data")
	}
	t.Log("✅ RSA Verify (tampered): valid=false")
}

// TestV12_SignVerify_ECDSA ECDSA 签名 + 验签往返。
func TestV12_SignVerify_ECDSA(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	createAsymKeyViaAPI(t, router, "ecdsa-sign", "ecdsa")

	data := []byte("hello ECDSA")
	sig := signViaAPI(t, router, "ecdsa-sign", data)
	t.Logf("✅ ECDSA Sign: %d bytes", len(sig))

	// 验签（正确）。
	valid := verifyViaAPI(t, router, "ecdsa-sign", data, sig)
	if !valid {
		t.Fatal("ECDSA verify should be valid")
	}
	t.Log("✅ ECDSA Verify: valid=true")

	// 验签（假签名）。
	fakeSig := make([]byte, 64)
	valid = verifyViaAPI(t, router, "ecdsa-sign", data, fakeSig)
	if valid {
		t.Fatal("ECDSA should reject fake signature")
	}
	t.Log("✅ ECDSA Verify (fake sig): valid=false")
}

// TestV12_Sign_SymmetricKeyRejected 对称密钥签名被拒绝。
func TestV12_Sign_SymmetricKeyRejected(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	// 创建对称密钥。
	mgr.CreateKey(context.Background(), "sym-key", seal.NewSoftwareKEK(mk), 0)

	body := signRequest{KeyID: "sym-key", Data: []byte("test")}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sign", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1Sign(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for symmetric key sign, got %d", w.Code)
	}
	t.Log("✅ Symmetric key sign correctly rejected")
}

// TestV12_Verify_EmptySignature 空签名验签。
func TestV12_Verify_EmptySignature(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	createAsymKeyViaAPI(t, router, "verify-empty", "ecdsa")

	valid := verifyViaAPI(t, router, "verify-empty", []byte("data"), []byte{})
	if valid {
		t.Fatal("empty signature should be invalid")
	}
	t.Log("✅ Empty signature verify: valid=false")
}

// TestV12_ReEncrypt 跨密钥重加密。
func TestV12_ReEncrypt(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	ctx := context.Background()

	// 创建两个对称密钥。
	mgr.CreateKey(ctx, "src-key", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "dst-key", seal.NewSoftwareKEK(mk), 0)

	// 加密 src-key。
	encResp := struct {
		Data struct {
			Ciphertext []byte `json:"ciphertext"`
		} `json:"data"`
	}{}
	encBody := map[string]interface{}{"key_id": "src-key", "plaintext": "aGVsbG8="}
	encJSON, _ := json.Marshal(encBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", bytes.NewReader(encJSON))
	w := httptest.NewRecorder()
	router.handleV1Encrypt(w, req)
	json.Unmarshal(w.Body.Bytes(), &encResp)

	if len(encResp.Data.Ciphertext) == 0 {
		t.Fatal("encrypt failed")
	}

	// ReEncrypt: src-key → dst-key。
	reBody := reEncryptRequest{
		SourceKeyID: "src-key",
		DestKeyID:   "dst-key",
		Ciphertext:  encResp.Data.Ciphertext,
	}
	reJSON, _ := json.Marshal(reBody)

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/re-encrypt", bytes.NewReader(reJSON))
	w2 := httptest.NewRecorder()
	router.handleV1ReEncrypt(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("ReEncrypt: got %d, want 200, body=%s", w2.Code, w2.Body.String())
	}

	var reResp struct {
		Data struct {
			Ciphertext []byte `json:"ciphertext"`
			Version    int    `json:"version"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &reResp)
	if len(reResp.Data.Ciphertext) == 0 {
		t.Fatal("re-encrypted ciphertext should not be empty")
	}
	t.Logf("✅ ReEncrypt: %d bytes, v%d", len(reResp.Data.Ciphertext), reResp.Data.Version)

	// 用 dst-key 解密重加密后的密文，验证数据一致。
	decBody := map[string]interface{}{"key_id": "dst-key", "ciphertext": reResp.Data.Ciphertext}
	decJSON, _ := json.Marshal(decBody)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader(decJSON))
	w3 := httptest.NewRecorder()
	router.handleV1Decrypt(w3, req3)

	var decResp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	json.Unmarshal(w3.Body.Bytes(), &decResp)
	if decResp.Data.Plaintext != "aGVsbG8=" {
		t.Fatalf("decrypt after re-encrypt: got %q, want %q", decResp.Data.Plaintext, "aGVsbG8=")
	}
	t.Log("✅ Decrypt after ReEncrypt: plaintext matches original")
}

// TestV12_ReEncrypt_NonexistentSource 源密钥不存在。
func TestV12_ReEncrypt_NonexistentSource(t *testing.T) {
	router, mgr, mk := newV12TestRouter(t)
	mgr.CreateKey(context.Background(), "dst-key", seal.NewSoftwareKEK(mk), 0)

	body := reEncryptRequest{
		SourceKeyID: "nonexistent",
		DestKeyID:   "dst-key",
		Ciphertext:  []byte("dummy"),
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/re-encrypt", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handleV1ReEncrypt(w, req)

	if w.Code != http.StatusNotFound && w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 404 or 500 for nonexistent source, got %d", w.Code)
	}
	t.Logf("✅ ReEncrypt nonexistent source: %d", w.Code)
}

// TestV12_GetPublicKey_AfterAsymmetricCreate 创建后获取公钥。
func TestV12_GetPublicKey_AfterAsymmetricCreate(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	pubPEM := createAsymKeyViaAPI(t, router, "getpub-key", "ecdsa")

	// 通过 GetPublicKey API 再次获取。
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key?key_id=getpub-key", nil)
	w := httptest.NewRecorder()
	router.handleV1GetPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetPublicKey: got %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			PublicKey []byte `json:"public_key"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	// 公钥应与创建时返回的一致。
	if string(resp.Data.PublicKey) != string(pubPEM) {
		t.Fatal("GetPublicKey mismatch with creation")
	}
	t.Log("✅ GetPublicKey matches creation")
}
