package yvonne

import (
	"context"
	"testing"
)

// TestClient_Struct 验证 Client 结构体字段可访问。
func TestClient_Struct(t *testing.T) {
	c := New("http://127.0.0.1:8400", "test-token")
	if c.baseURL != "http://127.0.0.1:8400" {
		t.Fatalf("baseURL = %q", c.baseURL)
	}
	if c.token != "test-token" {
		t.Fatalf("token = %q", c.token)
	}
	if c.http == nil {
		t.Fatal("http client should not be nil")
	}
}

// TestClient_NewWithHTTP 验证自定义 HTTP client。
func TestClient_NewWithHTTP(t *testing.T) {
	c := NewWithHTTP("http://localhost", "token", nil)
	if c.http != nil {
		t.Fatal("http should be nil when passed nil")
	}
}

// TestClient_RequestTypes 验证请求/响应类型可构造。
func TestClient_RequestTypes(t *testing.T) {
	req := &EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("hello"),
	}
	if req.KeyID != "test-key" {
		t.Fatal("KeyID mismatch")
	}

	resp := &DecryptResponse{
		Plaintext: []byte("decrypted"),
		Version:   2,
	}
	if resp.Version != 2 {
		t.Fatal("Version mismatch")
	}
}

// 确保 context 被引用。
var _ = context.Background
