//go:build gmsm

// v1.2.2 SM2 API 集成测试（gmsm 构建标签）。
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestV12_SignVerify_SM2 SM2 签名 + 验签往返。
func TestV12_SignVerify_SM2(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	pubPEM := createAsymKeyViaAPI(t, router, "sm2-sign", "sm2")
	if len(pubPEM) == 0 {
		t.Fatal("SM2 public key should not be empty")
	}
	t.Logf("✅ CreateAsymmetricKey SM2: %d bytes public key", len(pubPEM))

	data := []byte("hello SM2")
	sig := signViaAPI(t, router, "sm2-sign", data)
	t.Logf("✅ SM2 Sign: %d bytes", len(sig))

	// 验签（正确）。
	valid := verifyViaAPI(t, router, "sm2-sign", data, sig)
	if !valid {
		t.Fatal("SM2 verify should be valid")
	}
	t.Log("✅ SM2 Verify: valid=true")

	// 验签（篡改数据）。
	valid = verifyViaAPI(t, router, "sm2-sign", []byte("tampered"), sig)
	if valid {
		t.Fatal("SM2 should reject tampered data")
	}
	t.Log("✅ SM2 Verify (tampered): valid=false")
}

// TestV12_GetPublicKey_SM2 SM2 公钥获取。
func TestV12_GetPublicKey_SM2(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	createAsymKeyViaAPI(t, router, "sm2-getpub", "sm2")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/public-key?key_id=sm2-getpub", nil)
	w := httptest.NewRecorder()
	router.handleV1GetPublicKey(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetPublicKey SM2: got %d, want 200", w.Code)
	}

	var resp struct {
		Data struct {
			PublicKey []byte `json:"public_key"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data.PublicKey) == 0 {
		t.Fatal("SM2 public key should not be empty")
	}
	t.Logf("✅ GetPublicKey SM2: %d bytes", len(resp.Data.PublicKey))
}

// TestV12_SM2_EncryptDecrypt SM2 加解密（验证密钥可用性）。
func TestV12_SM2_KeyPairValid(t *testing.T) {
	router, _, _ := newV12TestRouter(t)
	createAsymKeyViaAPI(t, router, "sm2-valid", "sm2")

	// 签名 + 验签验证密钥对完整性。
	data := []byte("validity check")
	sig := signViaAPI(t, router, "sm2-valid", data)

	if !verifyViaAPI(t, router, "sm2-valid", data, sig) {
		t.Fatal("SM2 key pair invalid: sign+verify failed")
	}
	t.Log("✅ SM2 key pair valid: sign+verify roundtrip")
}

// 确保 bytes/json/http/httptest 被引用（辅助函数在非 gmsm 文件中）。
var _ = bytes.NewBuffer
var _ = json.Marshal
var _ = http.MethodPost
var _ = httptest.NewRecorder
