//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestGDK_GenerateAndDecrypt 验证 GDK 生成的临时 DEK 可用于本地加密 + KMS 解密往返。
func TestGDK_GenerateAndDecrypt(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "gdk-roundtrip-test"

	// 1. 创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": keyID,
	})

	// 2. 调用 GDK 获取临时 DEK。
	code, resp := doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/generate-data-key", nil)
	if code != http.StatusOK {
		t.Fatalf("GDK: got %d, want 200", code)
	}

	plainDEKB64 := extractString(t, resp, "data", "plaintext_dek")
	cipherDEKB64 := extractString(t, resp, "data", "ciphertext_dek")

	if plainDEKB64 == "" {
		t.Fatal("plaintext_dek should not be empty")
	}
	if cipherDEKB64 == "" {
		t.Fatal("ciphertext_dek should not be empty")
	}

	// 3. 验证明文 DEK 是 32 字节。
	plainDEK, err := base64.StdEncoding.DecodeString(plainDEKB64)
	if err != nil {
		t.Fatalf("decode plaintext_dek: %v", err)
	}
	if len(plainDEK) != 32 {
		t.Fatalf("plaintext_dek length = %d, want 32", len(plainDEK))
	}

	// 4. 验证密文 DEK 含版本前缀（uint32 BigEndian = 1）。
	cipherDEK, _ := base64.StdEncoding.DecodeString(cipherDEKB64)
	if len(cipherDEK) < 32 {
		t.Fatalf("ciphertext_dek too short: %d", len(cipherDEK))
	}
	version := uint32(cipherDEK[0])<<24 | uint32(cipherDEK[1])<<16 | uint32(cipherDEK[2])<<8 | uint32(cipherDEK[3])
	if version != 1 {
		t.Fatalf("ciphertext_dek version = %d, want 1", version)
	}

	// 5. 用密文 DEK 调用 /decrypt 验证往返（密文 DEK 本身就是版本化密文）。
	decCode, decResp := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": cipherDEKB64,
	})
	if decCode != http.StatusOK {
		t.Fatalf("decrypt GDK ciphertext: got %d, want 200", decCode)
	}
	decryptedB64 := extractString(t, decResp, "data", "plaintext")
	decrypted, _ := base64.StdEncoding.DecodeString(decryptedB64)
	if string(decrypted) != string(plainDEK) {
		t.Fatal("GDK round-trip: decrypted DEK != original plaintext DEK")
	}
}

// TestGDK_KeyNotFound 验证不存在的 key 返回 404。
func TestGDK_KeyNotFound(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/keys/nonexistent/generate-data-key", nil)
	if code != http.StatusNotFound {
		t.Fatalf("GDK nonexistent key: got %d, want 404", code)
	}
}

// TestGDK_DifferentEachCall 验证每次调用生成不同的临时 DEK。
func TestGDK_DifferentEachCall(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "gdk-uniqueness-test"

	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": keyID,
	})

	_, resp1 := doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/generate-data-key", nil)
	_, resp2 := doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/generate-data-key", nil)

	dek1 := extractString(t, resp1, "data", "plaintext_dek")
	dek2 := extractString(t, resp2, "data", "plaintext_dek")

	if dek1 == dek2 {
		t.Fatal("two GDK calls should produce different plaintext DEKs (CSPRNG)")
	}
}

// TestGDK_AfterRotate 验证轮转后 GDK 用新版本加密。
func TestGDK_AfterRotate(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "gdk-rotate-test"

	// 创建 V1。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})

	// V1 GDK。
	_, resp1 := doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/generate-data-key", nil)
	cipherDEK1B64 := extractString(t, resp1, "data", "ciphertext_dek")
	cipherDEK1, _ := base64.StdEncoding.DecodeString(cipherDEK1B64)
	v1 := uint32(cipherDEK1[0])<<24 | uint32(cipherDEK1[1])<<16 | uint32(cipherDEK1[2])<<8 | uint32(cipherDEK1[3])
	if v1 != 1 {
		t.Fatalf("GDK V1 ciphertext version = %d, want 1", v1)
	}

	// 轮转到 V2。
	doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)

	// V2 GDK。
	_, resp2 := doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/generate-data-key", nil)
	cipherDEK2B64 := extractString(t, resp2, "data", "ciphertext_dek")
	cipherDEK2, _ := base64.StdEncoding.DecodeString(cipherDEK2B64)
	v2 := uint32(cipherDEK2[0])<<24 | uint32(cipherDEK2[1])<<16 | uint32(cipherDEK2[2])<<8 | uint32(cipherDEK2[3])
	if v2 != 2 {
		t.Fatalf("GDK V2 ciphertext version = %d, want 2", v2)
	}

	// V1 密文 DEK 仍可解密（Deactivated 允许解密）。
	decCode, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": cipherDEK1B64,
	})
	if decCode != http.StatusOK {
		t.Fatalf("decrypt V1 GDK after rotate: got %d, want 200", decCode)
	}
}
