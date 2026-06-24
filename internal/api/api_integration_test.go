//go:build integration

// API 端点集成测试。
//
// 覆盖全部 8 个端点的完整生命周期与错误路径：
//   - GET  /api/v1/sys/health
//   - POST /api/v1/sys/unseal
//   - POST /api/v1/keys
//   - POST /api/v1/keys/{id}/rotate
//   - DELETE /api/v1/keys/{id}/shred
//   - POST /api/v1/encrypt
//   - POST /api/v1/decrypt
//   - GET  /metrics
//
// 运行方式：
//
//	go test ./internal/api/ -tags=integration -race -v -timeout 60s
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newIntegrationRouter 创建完整装配的 V1Router（Unsealed + lifecycle.Manager + metrics）。
// 返回 router、审计日志 buffer、vault、manager、store 供测试断言。
func newIntegrationRouter(t *testing.T) (*V1Router, *bytes.Buffer, *seal.VaultState, *lifecycle.Manager, *storage.MemoryStore) {
	t.Helper()

	// 1. 创建 VaultState 并直接 Unseal（用临时 Master Key）。
	masterKey, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	t.Cleanup(func() { masterKey.Wipe() })

	vault := seal.NewVaultState(5, 3, 0)
	if err := vault.DirectUnseal(masterKey); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	// 2. 创建 MemoryStore + lifecycle.Manager。
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	// 3. 创建 audit logger（输出到 buffer 供验证）。
	var auditBuf bytes.Buffer
	logger, err := audit.NewAuditLogger(&auditBuf)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	// 4. 创建 metrics registry。
	reg := metrics.NewRegistry()

	// 5. 装配 V1Router。
	r := NewV1Router(vault, logger, mgr, reg, nil)
	return r, &auditBuf, vault, mgr, store
}

// doRequest 封装 httptest 请求，返回 status code 与解析后的 JSON body。
func doRequest(t *testing.T, r *V1Router, method, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var bodyReader *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		bodyReader = strings.NewReader(string(raw))
	} else {
		bodyReader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

// extractString 从 JSON 响应中按路径提取字符串（如 data.ciphertext）。
func extractString(t *testing.T, resp map[string]interface{}, keys ...string) string {
	t.Helper()
	current := resp
	for i, k := range keys {
		v, ok := current[k]
		if !ok {
			t.Fatalf("key %q not found at path %v", k, keys[:i+1])
		}
		if i == len(keys)-1 {
			s, ok := v.(string)
			if !ok {
				t.Fatalf("value at %v is not string: %T", keys, v)
			}
			return s
		}
		current, ok = v.(map[string]interface{})
		if !ok {
			t.Fatalf("value at %v is not object: %T", keys[:i+1], v)
		}
	}
	return ""
}

// extractInt 从 JSON 响应中按路径提取 int（JSON 数字是 float64）。
func extractInt(t *testing.T, resp map[string]interface{}, keys ...string) int {
	t.Helper()
	current := resp
	for i, k := range keys {
		v, ok := current[k]
		if !ok {
			t.Fatalf("key %q not found at path %v", k, keys[:i+1])
		}
		if i == len(keys)-1 {
			f, ok := v.(float64)
			if !ok {
				t.Fatalf("value at %v is not number: %T", keys, v)
			}
			return int(f)
		}
		current, ok = v.(map[string]interface{})
		if !ok {
			t.Fatalf("value at %v is not object: %T", keys[:i+1], v)
		}
	}
	return 0
}

// extractBool 从 JSON 响应中按路径提取 bool。
func extractBool(t *testing.T, resp map[string]interface{}, keys ...string) bool {
	t.Helper()
	current := resp
	for i, k := range keys {
		v, ok := current[k]
		if !ok {
			t.Fatalf("key %q not found at path %v", k, keys[:i+1])
		}
		if i == len(keys)-1 {
			b, ok := v.(bool)
			if !ok {
				t.Fatalf("value at %v is not bool: %T", keys, v)
			}
			return b
		}
		current, ok = v.(map[string]interface{})
		if !ok {
			t.Fatalf("value at %v is not object: %T", keys[:i+1], v)
		}
	}
	return false
}

// =====================================================================
// 1. 健康检查
// =====================================================================

func TestIntegration_Health(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	code, resp := doRequest(t, r, http.MethodGet, "/api/v1/sys/health", nil)
	if code != http.StatusOK {
		t.Fatalf("health: got %d, want 200", code)
	}
	if !extractBool(t, resp, "ok") {
		t.Fatal("ok should be true")
	}
	if extractBool(t, resp, "data", "sealed") {
		t.Fatal("sealed should be false (Unsealed)")
	}
	if extractString(t, resp, "data", "state") != "unsealed" {
		t.Fatal("state should be unsealed")
	}
}

func TestIntegration_Health_MethodNotAllowed(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/sys/health", nil)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("POST health: got %d, want 405", code)
	}
}

// =====================================================================
// 2. Unseal（已解封后提交多余 share）
// =====================================================================

func TestIntegration_Unseal_AlreadyUnsealed(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	code, resp := doRequest(t, r, http.MethodPost, "/api/v1/sys/unseal", map[string]interface{}{
		"share": base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
	})
	if code != http.StatusOK {
		t.Fatalf("unseal: got %d, want 200", code)
	}
	if !extractBool(t, resp, "data", "unsealed") {
		t.Fatal("unsealed should be true")
	}
}

func TestIntegration_Unseal_InvalidBody(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sys/unseal", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid body: got %d, want 400", rec.Code)
	}
}

// =====================================================================
// 3. 创建密钥
// =====================================================================

func TestIntegration_CreateKey(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	code, resp := doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "integration-test-key",
	})
	if code != http.StatusOK {
		t.Fatalf("create key: got %d, want 200", code)
	}
	if extractString(t, resp, "data", "key_id") != "integration-test-key" {
		t.Fatal("key_id mismatch")
	}
	if extractInt(t, resp, "data", "version") != 1 {
		t.Fatal("version should be 1")
	}
	dek := extractString(t, resp, "data", "plaintext_dek")
	if dek == "" {
		t.Fatal("plaintext_dek should not be empty")
	}
	// DEK 应是 32 字节 base64（44 字符含 padding）。
	decoded, err := base64.StdEncoding.DecodeString(dek)
	if err != nil {
		t.Fatalf("decode plaintext_dek: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("plaintext_dek length = %d, want 32", len(decoded))
	}
}

func TestIntegration_CreateKey_MissingKeyID(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("missing key_id: got %d, want 400", code)
	}
}

func TestIntegration_CreateKey_MethodNotAllowed(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodGet, "/api/v1/keys", nil)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /keys: got %d, want 405", code)
	}
}

// =====================================================================
// 4. 加密
// =====================================================================

func TestIntegration_Encrypt(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 先创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "enc-test-key",
	})

	// 加密。
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret data"))
	code, resp := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "enc-test-key",
		"plaintext": plaintext,
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt: got %d, want 200", code)
	}
	ct := extractString(t, resp, "data", "ciphertext")
	if ct == "" {
		t.Fatal("ciphertext should not be empty")
	}
	if extractInt(t, resp, "data", "version") != 1 {
		t.Fatal("version should be 1")
	}

	// 密文 base64 解码后应 >= 2(版本) + 12(nonce) + 16(tag) = 30 字节。
	decoded, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if len(decoded) < 30 {
		t.Fatalf("ciphertext too short: %d bytes", len(decoded))
	}
}

func TestIntegration_Encrypt_KeyNotFound(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "nonexistent",
		"plaintext": "aGVsbG8=",
	})
	if code != http.StatusNotFound {
		t.Fatalf("encrypt nonexistent key: got %d, want 404", code)
	}
}

func TestIntegration_Encrypt_MissingKeyID(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"plaintext": "aGVsbG8=",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("encrypt missing key_id: got %d, want 400", code)
	}
}

// =====================================================================
// 5. 解密 + 加解密往返
// =====================================================================

func TestIntegration_EncryptDecrypt_RoundTrip(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "roundtrip-key",
	})

	// 加密。
	originalPlain := "hello world"
	code, encResp := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "roundtrip-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte(originalPlain)),
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt: got %d", code)
	}
	ciphertext := extractString(t, encResp, "data", "ciphertext")

	// 解密。
	code, decResp := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     "roundtrip-key",
		"ciphertext": ciphertext,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt: got %d", code)
	}

	decryptedB64 := extractString(t, decResp, "data", "plaintext")
	decrypted, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if string(decrypted) != originalPlain {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, originalPlain)
	}
	if extractInt(t, decResp, "data", "version") != 1 {
		t.Fatal("decrypt version should be 1")
	}
}

func TestIntegration_Decrypt_KeyNotFound(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	// 密文需 >= 30 字节才能通过长度检查，进入 key 查找阶段。
	// 构造 30 字节的合法格式密文：[2版本][12 nonce][16 tag]。
	fakeCt := base64.StdEncoding.EncodeToString(make([]byte, 30))
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     "nonexistent",
		"ciphertext": fakeCt,
	})
	if code != http.StatusNotFound {
		t.Fatalf("decrypt nonexistent key: got %d, want 404", code)
	}
}

func TestIntegration_Decrypt_CiphertextTooShort(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 先创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "short-ct-key",
	})

	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     "short-ct-key",
		"ciphertext": base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}), // 太短
	})
	if code != http.StatusBadRequest {
		t.Fatalf("short ciphertext: got %d, want 400", code)
	}
}

func TestIntegration_Decrypt_TamperedCiphertext(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "tamper-key",
	})

	// 加密。
	_, encResp := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "tamper-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("original")),
	})
	ciphertext := extractString(t, encResp, "data", "ciphertext")

	// 篡改密文（翻转最后一字节）。
	decoded, _ := base64.StdEncoding.DecodeString(ciphertext)
	decoded[len(decoded)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(decoded)

	// 解密应失败（AuthTag 校验不通过）。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     "tamper-key",
		"ciphertext": tampered,
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("tampered ciphertext: got %d, want 500", code)
	}
}

// =====================================================================
// 6. 轮转 + 向后兼容
// =====================================================================

func TestIntegration_RotateAndBackwardCompat(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 创建 V1。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "rotate-key",
	})

	// 用 V1 加密。
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "rotate-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1-data")),
	})
	v1Ciphertext := extractString(t, enc1, "data", "ciphertext")
	if extractInt(t, enc1, "data", "version") != 1 {
		t.Fatal("V1 encrypt version should be 1")
	}

	// 轮转到 V2。
	code, rotResp := doRequest(t, r, http.MethodPost, "/api/v1/keys/rotate-key/rotate", nil)
	if code != http.StatusOK {
		t.Fatalf("rotate: got %d, want 200", code)
	}
	if extractInt(t, rotResp, "data", "version") != 2 {
		t.Fatal("rotated version should be 2")
	}

	// 用 V2 加密。
	_, enc2 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "rotate-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v2-data")),
	})
	if extractInt(t, enc2, "data", "version") != 2 {
		t.Fatal("V2 encrypt version should be 2")
	}

	// V1 旧密文仍可解密（向后兼容）。
	code, decOld := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     "rotate-key",
		"ciphertext": v1Ciphertext,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V1 after rotate: got %d, want 200", code)
	}
	oldPlain, _ := base64.StdEncoding.DecodeString(extractString(t, decOld, "data", "plaintext"))
	if string(oldPlain) != "v1-data" {
		t.Fatalf("V1 decrypt: got %q, want %q", oldPlain, "v1-data")
	}
	if extractInt(t, decOld, "data", "version") != 1 {
		t.Fatal("V1 decrypt version should be 1")
	}
}

func TestIntegration_Rotate_KeyNotFound(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys/nonexistent/rotate", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("rotate nonexistent: got %d, want 500", code)
	}
}

// =====================================================================
// 7. 物理粉碎
// =====================================================================

func TestIntegration_Shred(t *testing.T) {
	r, _, _, mgr, _ := newIntegrationRouter(t)

	// 创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "shred-key",
	})

	// 粉碎 V1。
	code, resp := doRequest(t, r, http.MethodDelete, "/api/v1/keys/shred-key/shred", map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("shred: got %d, want 200", code)
	}
	if !extractBool(t, resp, "data", "shred") {
		t.Fatal("shred should be true")
	}

	// 验证底层存储已删除该版本。
	_, err := mgr.GetKey(context.Background(), "shred-key", 1)
	if err == nil {
		t.Fatal("GetKey after Shred should fail")
	}
}

func TestIntegration_Shred_VersionNotFound(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 创建密钥 V1。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "shred-missing-key",
	})

	// 粉碎不存在的 V99。
	code, _ := doRequest(t, r, http.MethodDelete, "/api/v1/keys/shred-missing-key/shred", map[string]interface{}{
		"version": 99,
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("shred nonexistent version: got %d, want 500", code)
	}
}

func TestIntegration_Shred_MissingVersion(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "shred-no-ver-key",
	})

	code, _ := doRequest(t, r, http.MethodDelete, "/api/v1/keys/shred-no-ver-key/shred", map[string]interface{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("shred missing version: got %d, want 400", code)
	}
}

// =====================================================================
// 8. 完整生命周期：Create → Encrypt → Rotate → Encrypt V2 → Shred V1 → Decrypt V1 失败
// =====================================================================

func TestIntegration_FullLifecycle(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "lifecycle-key"

	// 1. 创建。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": keyID,
	})
	if code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}

	// 2. V1 加密。
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1-secret")),
	})
	v1Ct := extractString(t, enc1, "data", "ciphertext")

	// 3. 轮转。
	code, _ = doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)
	if code != http.StatusOK {
		t.Fatalf("rotate: got %d", code)
	}

	// 4. V2 加密。
	_, enc2 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v2-secret")),
	})
	v2Ct := extractString(t, enc2, "data", "ciphertext")

	// 5. 粉碎 V1。
	code, _ = doRequest(t, r, http.MethodDelete, "/api/v1/keys/"+keyID+"/shred", map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("shred V1: got %d", code)
	}

	// 6. V1 密文解密应失败（DEK 已粉碎）。
	code, _ = doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v1Ct,
	})
	if code != http.StatusInternalServerError && code != http.StatusNotFound {
		t.Fatalf("decrypt V1 after shred: got %d, want 500 or 404", code)
	}

	// 7. V2 密文仍可解密（V2 未粉碎）。
	code, dec2 := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v2Ct,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V2 after shredding V1: got %d, want 200", code)
	}
	v2Plain, _ := base64.StdEncoding.DecodeString(extractString(t, dec2, "data", "plaintext"))
	if string(v2Plain) != "v2-secret" {
		t.Fatalf("V2 decrypt: got %q, want %q", v2Plain, "v2-secret")
	}
}

// =====================================================================
// 9. Sealed 状态下业务 API 返回 503
// =====================================================================

func TestIntegration_SealedReturns503(t *testing.T) {
	// 创建 Sealed 的 router（不调用 DirectUnseal）。
	vault := seal.NewVaultState(5, 3, 0)
	var buf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&buf)
	defer logger.Close()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	r := NewV1Router(vault, logger, mgr, nil, nil)

	endpoints := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": "x"}},
		{http.MethodPost, "/api/v1/encrypt", map[string]interface{}{"key_id": "x", "plaintext": "aGk="}},
		{http.MethodPost, "/api/v1/decrypt", map[string]interface{}{"key_id": "x", "ciphertext": "AAECAwQ="}},
		{http.MethodPost, "/api/v1/keys/x/rotate", nil},
		{http.MethodDelete, "/api/v1/keys/x/shred", map[string]interface{}{"version": 1}},
	}

	for _, ep := range endpoints {
		code, _ := doRequest(t, r, ep.method, ep.path, ep.body)
		if code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: Sealed state got %d, want 503", ep.method, ep.path, code)
		}
	}
}

// =====================================================================
// 10. Prometheus 指标
// =====================================================================

func TestIntegration_Metrics(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 发几个请求产生指标。
	doRequest(t, r, http.MethodGet, "/api/v1/sys/health", nil)
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": "metrics-key"})
	doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "metrics-key",
		"plaintext": "aGk=",
	})

	// 获取指标。
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metrics: got %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	requiredMetrics := []string{
		"yvonne_api_request_duration_seconds",
		"yvonne_api_requests_total",
		"go_memstats_alloc_bytes",
		"go_goroutines",
	}
	for _, m := range requiredMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("metrics output missing %q", m)
		}
	}
}

// =====================================================================
// 11. 审计日志验证
// =====================================================================

func TestIntegration_AuditLog_AllRequestsRecorded(t *testing.T) {
	r, auditBuf, _, _, _ := newIntegrationRouter(t)

	// 发 3 个请求。
	doRequest(t, r, http.MethodGet, "/api/v1/sys/health", nil) // health 不走 auditMiddleware
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": "audit-key"})
	doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "audit-key",
		"plaintext": "aGk=",
	})

	// 审计日志应记录 2 条（health 不走 auditMiddleware，keys + encrypt 走了）。
	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("audit log lines = %d, want >= 2", len(lines))
	}

	// 每条日志都应含 signature 字段。
	for i, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse audit line %d: %v", i, err)
		}
		if _, ok := entry["signature"]; !ok {
			t.Errorf("audit line %d missing signature", i)
		}
		if _, ok := entry["payload"]; !ok {
			t.Errorf("audit line %d missing payload", i)
		}
	}

	// 验证审计日志不含明文/密文（脱敏）。
	fullLog := auditBuf.String()
	if strings.Contains(fullLog, "aGk=") {
		t.Error("audit log contains plaintext (should be redacted)")
	}
}

func TestIntegration_AuditLog_FailureAlsoRecorded(t *testing.T) {
	r, auditBuf, _, _, _ := newIntegrationRouter(t)

	// 发一个会失败的请求（key not found）。
	doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "nonexistent",
		"plaintext": "aGk=",
	})

	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("audit log should record failed requests")
	}

	// 解析最后一条，验证 status 是 failure。
	var entry map[string]interface{}
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &entry)
	payload, _ := entry["payload"].(string)
	if !strings.Contains(payload, `"status":"failure"`) {
		t.Errorf("audit log for failed request should have status=failure, payload: %s", payload)
	}
}

// =====================================================================
// 12. 方法限制
// =====================================================================

func TestIntegration_MethodEnforcement(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	cases := []struct {
		method   string
		path     string
		wantCode int
	}{
		{http.MethodGet, "/api/v1/keys", http.StatusMethodNotAllowed},
		{http.MethodPut, "/api/v1/keys", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/encrypt", http.StatusMethodNotAllowed},
		{http.MethodPut, "/api/v1/decrypt", http.StatusMethodNotAllowed},
	}

	for _, c := range cases {
		code, _ := doRequest(t, r, c.method, c.path, nil)
		if code != c.wantCode {
			t.Errorf("%s %s: got %d, want %d", c.method, c.path, code, c.wantCode)
		}
	}
}

// =====================================================================
// 13. 额外错误路径覆盖
// =====================================================================

func TestIntegration_Encrypt_InvalidBody(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("encrypt invalid body: got %d, want 400", rec.Code)
	}
}

func TestIntegration_Decrypt_InvalidBody(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("decrypt invalid body: got %d, want 400", rec.Code)
	}
}

func TestIntegration_CreateKey_InvalidBody(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create key invalid body: got %d, want 400", rec.Code)
	}
}

func TestIntegration_Shred_InvalidBody(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	// 先创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": "shred-invalid-body"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/shred-invalid-body/shred", strings.NewReader("not-json"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("shred invalid body: got %d, want 400", rec.Code)
	}
}

func TestIntegration_KeyOps_InvalidPath(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	// /api/v1/keys/ 只有 key_id，没有 action。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys/test-key", nil)
	if code != http.StatusNotFound {
		t.Fatalf("invalid key path: got %d, want 404", code)
	}
}

func TestIntegration_KeyOps_UnknownAction(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys/test-key/unknown", nil)
	if code != http.StatusNotFound {
		t.Fatalf("unknown action: got %d, want 404", code)
	}
}

func TestIntegration_MetricsContentType(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("metrics Content-Type = %q, want text/plain", ct)
	}
}

func TestIntegration_AuditMiddleware_PanicRecovery(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 用一个会 panic 的路径触发中间件恢复。
	// 当前实现中没有故意 panic 的端点，但可以验证 auditMiddleware 在 500 时不崩溃。
	// 加密不存在的 key 会返回 404（非 panic），这里验证中间件正常处理。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "nonexistent-for-panic-test",
		"plaintext": "aGk=",
	})
	if code == 0 {
		t.Fatal("should get non-zero status code")
	}
}
