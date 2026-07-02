//go:build gmsm

package sdf

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSDFServer_DeviceInfo HTTP 端到端：POST /api/v1/sdf/device/info。
func TestSDFServer_DeviceInfo(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	server := NewServer(dev, "test-token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/device/info", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "GM/T 0018") {
		t.Fatalf("response should contain GM/T 0018, got: %s", body)
	}
	t.Logf("✅ SDF HTTP DeviceInfo: %d", rec.Code)
}

// TestSDFServer_SM3Hash HTTP 端到端：POST /api/v1/sdf/sm3/hash。
func TestSDFServer_SM3Hash(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	server := NewServer(dev, "test-token")

	// data hex = "abc"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm3/hash", strings.NewReader(`{"data":"616263"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "hash") {
		t.Fatalf("response should contain hash, got: %s", body)
	}
	t.Logf("✅ SDF HTTP SM3Hash: %d", rec.Code)
}

// TestSDFServer_SM4Encrypt HTTP 端到端：SM4 加密。
func TestSDFServer_SM4Encrypt(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	server := NewServer(dev, "test-token")

	keyHex := hex.EncodeToString([]byte("0123456789abcdef"))
	plainHex := hex.EncodeToString([]byte("Hello SM4!"))

	rec := httptest.NewRecorder()
	reqBody := `{"key":"` + keyHex + `","data":"` + plainHex + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/sm4/encrypt", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer test-token")
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("encrypt expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	t.Logf("✅ SDF HTTP SM4Encrypt: %d", rec.Code)
}

// TestSDFServer_Unauthorized 无 token 应被拒绝。
func TestSDFServer_Unauthorized(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	server := NewServer(dev, "secret")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdf/device/info", strings.NewReader(`{}`))
	// 不设 Authorization header
	server.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("should reject without token")
	}
	t.Logf("✅ SDF HTTP unauthorized correctly rejected: %d", rec.Code)
}

// TestSDF_WrapKey 密钥包装往返。
func TestSDF_WrapKey(t *testing.T) {
	dev, err := NewSoftwareDevice()
	if err != nil {
		t.Fatalf("NewSoftwareDevice: %v", err)
	}
	defer dev.Close()

	kek := []byte("0123456789abcdef")          // 16 字节 SM4 KEK
	target := []byte("target-key-data-16byte") // 待包装的密钥

	wrapped, err := dev.WrapKey(kek, target)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped key should not be empty")
	}

	unwrapped, err := dev.UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if string(unwrapped) != string(target) {
		t.Fatalf("unwrapped = %q, want %q", string(unwrapped), string(target))
	}
	t.Log("✅ SDF WrapKey + UnwrapKey round-trip")
}
