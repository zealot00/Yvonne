//go:build integration

// 版本化密文 + 状态机强制集成测试。
package api

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestVersionedCiphertext_Format 验证密文格式为 [4字节版本][12字节Nonce][密文+Tag]。
func TestVersionedCiphertext_Format(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)

	// 创建密钥。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{
		"key_id": "format-test-key",
	})

	// 加密。
	code, resp := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    "format-test-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("format check")),
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt: got %d", code)
	}

	ctB64 := extractString(t, resp, "data", "ciphertext")
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	// 最小长度：4(version) + 12(nonce) + 16(GCM tag) = 32 字节。
	if len(ct) < 32 {
		t.Fatalf("ciphertext too short: %d bytes, need at least 32", len(ct))
	}

	// 版本号应为 1（uint32 BigEndian）。
	version := uint32(ct[0])<<24 | uint32(ct[1])<<16 | uint32(ct[2])<<8 | uint32(ct[3])
	if version != 1 {
		t.Fatalf("ciphertext version = %d, want 1", version)
	}
}

// TestStateMechanism_DestroyedRefusesDecrypt 验证 Shred 后该版本拒绝解密。
func TestStateMechanism_DestroyedRefusesDecrypt(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "destroyed-decrypt-test"

	// 创建 + 加密。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})
	_, encResp := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("will be destroyed")),
	})
	ciphertext := extractString(t, encResp, "data", "ciphertext")

	// 粉碎 V1。
	code, _ := doRequest(t, r, http.MethodDelete, "/api/v1/keys/"+keyID+"/shred", map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("shred: got %d", code)
	}

	// 解密应返回 404（Shred 物理删除了行，版本不存在）。
	code, _ = doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": ciphertext,
	})
	if code != http.StatusNotFound {
		t.Fatalf("decrypt destroyed key: got %d, want 404", code)
	}
}

// TestStateMechanism_DeactivatedAllowsDecrypt 验证轮转后旧版本（Deactivated）仍可解密。
func TestStateMechanism_DeactivatedAllowsDecrypt(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "deactivated-decrypt-test"

	// 创建 V1 + 加密。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1 data")),
	})
	v1Ciphertext := extractString(t, enc1, "data", "ciphertext")

	// 轮转到 V2（V1 变 Deactivated）。
	doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)

	// V1 密文仍可解密（Deactivated 允许解密）。
	code, decResp := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v1Ciphertext,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V1 after rotate: got %d, want 200", code)
	}
	plain, _ := base64.StdEncoding.DecodeString(extractString(t, decResp, "data", "plaintext"))
	if string(plain) != "v1 data" {
		t.Fatalf("V1 decrypt: got %q, want %q", plain, "v1 data")
	}
}

// TestStateMechanism_EncryptUsesActiveOnly 验证加密总是用最新 Active 版本。
func TestStateMechanism_EncryptUsesActiveOnly(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "active-only-test"

	// 创建 V1。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})

	// V1 加密 → version=1。
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1")),
	})
	if extractInt(t, enc1, "data", "version") != 1 {
		t.Fatal("V1 encrypt should report version 1")
	}

	// 轮转到 V2。
	doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)

	// V2 加密 → version=2。
	_, enc2 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v2")),
	})
	if extractInt(t, enc2, "data", "version") != 2 {
		t.Fatal("V2 encrypt should report version 2")
	}
}

// TestVersionedCiphertext_CrossVersionDecrypt 验证 V1 和 V2 密文都能正确解密。
func TestVersionedCiphertext_CrossVersionDecrypt(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "cross-version-test"

	// 创建 V1 + 加密。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1 secret")),
	})
	v1Ct := extractString(t, enc1, "data", "ciphertext")

	// 轮转 V2 + 加密。
	doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)
	_, enc2 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v2 secret")),
	})
	v2Ct := extractString(t, enc2, "data", "ciphertext")

	// 解密 V1。
	code, dec1 := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v1Ct,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V1: got %d", code)
	}
	p1, _ := base64.StdEncoding.DecodeString(extractString(t, dec1, "data", "plaintext"))
	if string(p1) != "v1 secret" {
		t.Fatalf("V1: got %q", p1)
	}
	if extractInt(t, dec1, "data", "version") != 1 {
		t.Fatal("V1 decrypt version should be 1")
	}

	// 解密 V2。
	code, dec2 := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v2Ct,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V2: got %d", code)
	}
	p2, _ := base64.StdEncoding.DecodeString(extractString(t, dec2, "data", "plaintext"))
	if string(p2) != "v2 secret" {
		t.Fatalf("V2: got %q", p2)
	}
	if extractInt(t, dec2, "data", "version") != 2 {
		t.Fatal("V2 decrypt version should be 2")
	}
}

// TestVersionedCiphertext_TamperedVersion 验证篡改版本号导致解密失败。
func TestVersionedCiphertext_TamperedVersion(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "tamper-version-test"

	// 创建 V1 + 加密。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})
	_, enc := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("original")),
	})
	ctB64 := extractString(t, enc, "data", "ciphertext")
	ct, _ := base64.StdEncoding.DecodeString(ctB64)

	// 篡改版本号为 99（不存在的版本）。
	ct[0] = 0
	ct[1] = 0
	ct[2] = 0
	ct[3] = 99
	tampered := base64.StdEncoding.EncodeToString(ct)

	// 解密应返回 404（版本不存在）。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": tampered,
	})
	if code != http.StatusNotFound {
		t.Fatalf("tampered version: got %d, want 404", code)
	}
}

// TestStateMechanism_FullLifecycleWithVersionedCiphertext 完整生命周期验证。
func TestStateMechanism_FullLifecycleWithVersionedCiphertext(t *testing.T) {
	r, _, _, _, _ := newIntegrationRouter(t)
	keyID := "lifecycle-versioned-test"

	// 1. 创建 V1。
	doRequest(t, r, http.MethodPost, "/api/v1/keys", map[string]interface{}{"key_id": keyID})

	// 2. V1 加密。
	_, enc1 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1-data")),
	})
	v1Ct := extractString(t, enc1, "data", "ciphertext")

	// 3. 轮转 V2。
	doRequest(t, r, http.MethodPost, "/api/v1/keys/"+keyID+"/rotate", nil)

	// 4. V2 加密。
	_, enc2 := doRequest(t, r, http.MethodPost, "/api/v1/encrypt", map[string]interface{}{
		"key_id":    keyID,
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v2-data")),
	})
	v2Ct := extractString(t, enc2, "data", "ciphertext")

	// 5. 粉碎 V1。
	doRequest(t, r, http.MethodDelete, "/api/v1/keys/"+keyID+"/shred", map[string]interface{}{
		"version": 1,
	})

	// 6. V1 密文解密 → 404（Shred 物理删除了行）。
	code, _ := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v1Ct,
	})
	if code != http.StatusNotFound {
		t.Fatalf("decrypt V1 after shred: got %d, want 404", code)
	}

	// 7. V2 密文解密 → 200（Active）。
	code, dec2 := doRequest(t, r, http.MethodPost, "/api/v1/decrypt", map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": v2Ct,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt V2 after shredding V1: got %d, want 200", code)
	}
	p2, _ := base64.StdEncoding.DecodeString(extractString(t, dec2, "data", "plaintext"))
	if string(p2) != "v2-data" {
		t.Fatalf("V2 decrypt: got %q, want %q", p2, "v2-data")
	}
}
