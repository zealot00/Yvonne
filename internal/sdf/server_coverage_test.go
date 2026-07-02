//go:build gmsm

// SDF HTTP handler 覆盖率补充测试。
package sdf

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSDFServer_Random POST /api/v1/sdf/random。
func TestSDFServer_Random(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	server := NewServer(dev, "test-token")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/random", strings.NewReader(`{"length":32}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "random") {
		t.Fatalf("response should contain random, got: %s", rec.Body.String())
	}
	t.Logf("✅ SDF HTTP Random: %d", rec.Code)
}

// TestSDFServer_Random_InvalidLength 无效长度。
func TestSDFServer_Random_InvalidLength(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/random", strings.NewReader(`{"length":0}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("should reject length=0")
	}
	t.Logf("✅ SDF HTTP Random invalid length: %d", rec.Code)
}

// TestSDFServer_SM2Generate POST /api/v1/sdf/sm2/generate。
func TestSDFServer_SM2Generate(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/generate", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "public_key") || !strings.Contains(body, "private_key") {
		t.Fatalf("response should contain keys, got: %s", body)
	}
	t.Logf("✅ SDF HTTP SM2Generate: %d", rec.Code)
}

// TestSDFServer_SM2SignAndVerify SM2 签名 + 验签 HTTP 往返。
func TestSDFServer_SM2SignAndVerify(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	// 1. 生成密钥对。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/generate", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200, got %d", rec.Code)
	}
	// 提取公私钥（简单字符串解析）。
	body := rec.Body.String()
	pubIdx := strings.Index(body, `"public_key":"`) + len(`"public_key":"`)
	pubEnd := strings.Index(body[pubIdx:], `"`)
	pubKey := body[pubIdx : pubIdx+pubEnd]
	privIdx := strings.Index(body, `"private_key":"`) + len(`"private_key":"`)
	privEnd := strings.Index(body[privIdx:], `"`)
	privKey := body[privIdx : privIdx+privEnd]

	// 2. 签名。
	dataHex := hex.EncodeToString([]byte("test sign data"))
	signBody := `{"private_key":` + jsonString(privKey) + `,"data":` + jsonString(dataHex) + `}`
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/sign", strings.NewReader(signBody))
	req2.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("sign: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	sigIdx := strings.Index(rec2.Body.String(), `"signature":"`) + len(`"signature":"`)
	sigEnd := strings.Index(rec2.Body.String()[sigIdx:], `"`)
	sig := rec2.Body.String()[sigIdx : sigIdx+sigEnd]

	// 3. 验签。
	verifyBody := `{"public_key":` + jsonString(pubKey) + `,"data":` + jsonString(dataHex) + `,"signature":` + jsonString(sig) + `}`
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/verify", strings.NewReader(verifyBody))
	req3.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}
	if !strings.Contains(rec3.Body.String(), `"valid":true`) {
		t.Fatalf("verify should return valid=true, got: %s", rec3.Body.String())
	}
	t.Logf("✅ SDF HTTP SM2 Sign+Verify round-trip")
}

// TestSDFServer_SM2EncryptDecrypt SM2 加密 + 解密 HTTP 往返。
func TestSDFServer_SM2EncryptDecrypt(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	// 生成密钥对。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/generate", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)
	body := rec.Body.String()
	pubIdx := strings.Index(body, `"public_key":"`) + len(`"public_key":"`)
	pubEnd := strings.Index(body[pubIdx:], `"`)
	pubKey := body[pubIdx : pubIdx+pubEnd]
	privIdx := strings.Index(body, `"private_key":"`) + len(`"private_key":"`)
	privEnd := strings.Index(body[privIdx:], `"`)
	privKey := body[privIdx : privIdx+privEnd]

	// 加密。
	dataHex := hex.EncodeToString([]byte("secret"))
	encBody := `{"public_key":` + jsonString(pubKey) + `,"data":` + jsonString(dataHex) + `}`
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/encrypt", strings.NewReader(encBody))
	req2.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("encrypt: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	ctIdx := strings.Index(rec2.Body.String(), `"ciphertext":"`) + len(`"ciphertext":"`)
	ctEnd := strings.Index(rec2.Body.String()[ctIdx:], `"`)
	ct := rec2.Body.String()[ctIdx : ctIdx+ctEnd]

	// 解密。
	decBody := `{"private_key":` + jsonString(privKey) + `,"ciphertext":` + jsonString(ct) + `}`
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm2/decrypt", strings.NewReader(decBody))
	req3.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("decrypt: expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}
	t.Logf("✅ SDF HTTP SM2 Encrypt+Decrypt round-trip")
}

// TestSDFServer_SM4Decrypt SM4 解密 HTTP。
func TestSDFServer_SM4Decrypt(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	// 先加密获得密文。
	keyHex := hex.EncodeToString([]byte("0123456789abcdef"))
	plainHex := hex.EncodeToString([]byte("Hello SM4!"))
	encBody := `{"key":` + jsonString(keyHex) + `,"data":` + jsonString(plainHex) + `}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm4/encrypt", strings.NewReader(encBody))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt: expected 200, got %d", rec.Code)
	}
	ctIdx := strings.Index(rec.Body.String(), `"ciphertext":"`) + len(`"ciphertext":"`)
	ctEnd := strings.Index(rec.Body.String()[ctIdx:], `"`)
	ct := rec.Body.String()[ctIdx : ctIdx+ctEnd]

	// 解密。
	decBody := `{"key":` + jsonString(keyHex) + `,"ciphertext":` + jsonString(ct) + `}`
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm4/decrypt", strings.NewReader(decBody))
	req2.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("decrypt: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	t.Logf("✅ SDF HTTP SM4 Decrypt: %d", rec2.Code)
}

// TestSDFServer_InvalidJSON 无效 JSON。
func TestSDFServer_InvalidJSON(t *testing.T) {
	dev, _ := NewSoftwareDevice()
	defer dev.Close()
	server := NewServer(dev, "test-token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/random", strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("should reject invalid JSON")
	}
	t.Logf("✅ SDF HTTP invalid JSON rejected: %d", rec.Code)
}

// jsonString 将字符串包装为 JSON 字符串字面量。
func jsonString(s string) string {
	return `"` + s + `"`
}
