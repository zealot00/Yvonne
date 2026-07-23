package yvonne

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sdfMockServer 返回 SDF mock server。
func sdfMockServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/sdf/device/info":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"name":    "Yvonne SDF Software Device",
					"version": "GM/T 0018-2023",
				},
			})
		case "/api/v1/sdf/random":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"random": hex.EncodeToString([]byte("random-bytes-32-bytes-padding!"))},
			})
		case "/api/v1/sdf/sm3/hash":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"hash": "66c7f7d6e3b5b3a83d6b2e8a3d6b2e8a3d6b2e8a3d6b2e8a3d6b2e8a3d6b2e8a"},
			})
		case "/api/v1/sdf/sm4/encrypt":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"ciphertext": hex.EncodeToString([]byte("encrypted-data-16byt"))},
			})
		case "/api/v1/sdf/sm4/decrypt":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"plaintext": hex.EncodeToString([]byte("Hello SM4!"))},
			})
		case "/api/v1/sdf/sm2/generate":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]string{
					"public_key":  "-----BEGIN PUBLIC KEY-----\nMOCKPUB\n-----END PUBLIC KEY-----\n",
					"private_key": "-----BEGIN PRIVATE KEY-----\nMOCKPRIV\n-----END PRIVATE KEY-----\n",
				},
			})
		case "/api/v1/sdf/sm2/sign":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"signature": hex.EncodeToString([]byte("mock-signature-32-bytes-pad!!"))},
			})
		case "/api/v1/sdf/sm2/verify":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]bool{"valid": true},
			})
		case "/api/v1/sdf/sm2/encrypt":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"ciphertext": hex.EncodeToString([]byte("sm2-encrypted-data"))},
			})
		case "/api/v1/sdf/sm2/decrypt":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]string{"plaintext": hex.EncodeToString([]byte("Hello SM2!"))},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "not found"})
		}
	}))
}

func TestClient_SDFDeviceInfo(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	resp, err := c.SDFDeviceInfo(context.Background())
	if err != nil {
		t.Fatalf("SDFDeviceInfo: %v", err)
	}
	if resp.Version != "GM/T 0018-2023" {
		t.Fatalf("Version = %q", resp.Version)
	}
	t.Logf("✅ SDFDeviceInfo: %s v%s", resp.Name, resp.Version)
}

func TestClient_SDFRandom(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	rnd, err := c.SDFRandom(context.Background(), 32)
	if err != nil {
		t.Fatalf("SDFRandom: %v", err)
	}
	if len(rnd) == 0 {
		t.Fatal("random should not be empty")
	}
	t.Logf("✅ SDFRandom: %d bytes", len(rnd))
}

func TestClient_SDFSM3Hash(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	hash, err := c.SDFSM3Hash(context.Background(), []byte("abc"))
	if err != nil {
		t.Fatalf("SDFSM3Hash: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash length = %d, want 32", len(hash))
	}
	t.Logf("✅ SDFSM3Hash: %s", hex.EncodeToString(hash))
}

func TestClient_SDFSM4RoundTrip(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	key := []byte("0123456789abcdef")

	// 加密
	ct, err := c.SDFSM4Encrypt(context.Background(), key, []byte("Hello SM4!"))
	if err != nil {
		t.Fatalf("SDFSM4Encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	// 解密
	pt, err := c.SDFSM4Decrypt(context.Background(), key, ct)
	if err != nil {
		t.Fatalf("SDFSM4Decrypt: %v", err)
	}
	if string(pt) != "Hello SM4!" {
		t.Fatalf("plaintext = %q", string(pt))
	}
	t.Log("✅ SDFSM4 encrypt+decrypt round-trip")
}

func TestClient_SDFSM2KeyPair(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	pub, priv, err := c.SDFSM2GenerateKeyPair(context.Background())
	if err != nil {
		t.Fatalf("SDFSM2GenerateKeyPair: %v", err)
	}
	if pub == "" || priv == "" {
		t.Fatal("pub/priv should not be empty")
	}
	t.Log("✅ SDFSM2GenerateKeyPair")
}

func TestClient_SDFSM2SignVerify(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")

	// 签名
	sig, err := c.SDFSM2Sign(context.Background(), "priv-pem", []byte("data"))
	if err != nil {
		t.Fatalf("SDFSM2Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// 验签
	valid, err := c.SDFSM2Verify(context.Background(), "pub-pem", []byte("data"), sig)
	if err != nil {
		t.Fatalf("SDFSM2Verify: %v", err)
	}
	if !valid {
		t.Fatal("verify should be valid")
	}
	t.Log("✅ SDFSM2 sign+verify round-trip")
}

func TestClient_SDFSM2EncryptDecrypt(t *testing.T) {
	srv := sdfMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")

	ct, err := c.SDFSM2Encrypt(context.Background(), "pub-pem", []byte("Hello SM2!"))
	if err != nil {
		t.Fatalf("SDFSM2Encrypt: %v", err)
	}

	pt, err := c.SDFSM2Decrypt(context.Background(), "priv-pem", ct)
	if err != nil {
		t.Fatalf("SDFSM2Decrypt: %v", err)
	}
	if string(pt) != "Hello SM2!" {
		t.Fatalf("plaintext = %q", string(pt))
	}
	t.Log("✅ SDFSM2 encrypt+decrypt round-trip")
}
