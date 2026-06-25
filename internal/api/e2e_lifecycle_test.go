//go:build integration

// 时空穿越 E2E 测试：验证"加密永远用最新，解密永远向后兼容"的核心架构承诺。
//
// 全链路流程：
//  1. 建 Key → V1 Active
//  2. 首次加密 → Ciphertext_V1
//  3. 轮转 → V1 Deactivated + V2 Active
//  4. 二次加密 → Ciphertext_V2
//  5. 向后兼容：解密 Ciphertext_V1 成功（自动路由到 Deactivated V1）
//  6. 解密 Ciphertext_V2 成功
//  7. 数字火化：ShredKey V1
//  8. 历史粉碎：解密 Ciphertext_V1 失败（400），Ciphertext_V2 仍成功
package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"yvonne/internal/lifecycle"
	"yvonne/internal/seal"
)

// TestE2E_TimeTravel_KeyLifecycle 时空穿越 E2E 测试。
//
// 这是 KMS 的灵魂测试：验证版本化自路由密文 + 状态机强制 + 向后兼容 + 物理粉碎。
func TestE2E_TimeTravel_KeyLifecycle(t *testing.T) {
	// === 装配 ===
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{
			RoleID:         "trade-service",
			Token:          "trade-token",
			AllowedKeys:    []string{"trade-key"},
			AllowedActions: []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp"},
		},
	})

	token := "trade-token"
	ctx := context.Background()
	kek := seal.NewSoftwareKEK(mk)

	// === Step 1: 建 Key ===
	t.Log("Step 1: 创建 trade-key，期望 V1 Active")

	code, resp := doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys", token, map[string]interface{}{
		"key_id": "trade-key",
	})
	if code != http.StatusOK {
		t.Fatalf("Step 1 CreateKey: got %d, want 200 (resp=%v)", code, resp)
	}

	// 验证 V1 Active。
	meta, err := mgr.GetKey(ctx, "trade-key", 1)
	if err != nil {
		t.Fatalf("Step 1 GetKey V1: %v", err)
	}
	if meta.State != lifecycle.StateActive {
		t.Fatalf("Step 1: V1 State = %v, want Active", meta.State)
	}
	if meta.Version != 1 {
		t.Fatalf("Step 1: V1 Version = %d, want 1", meta.Version)
	}
	t.Log("  ✓ V1 Active 确认")

	// === Step 2: 首次加密 ===
	t.Log("Step 2: 首次加密 'SecretData' → Ciphertext_V1")

	plaintext := "SecretData"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(plaintext))

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", token, map[string]interface{}{
		"key_id":    "trade-key",
		"plaintext": plaintextB64,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 2 Encrypt V1: got %d, want 200 (resp=%v)", code, resp)
	}

	ciphertextV1 := extractString(t, resp, "data", "ciphertext")
	if ciphertextV1 == "" {
		t.Fatal("Step 2: Ciphertext_V1 should not be empty")
	}

	// 验证密文版本前缀 = 1（V1 加密）。
	ctBytes, _ := base64.StdEncoding.DecodeString(ciphertextV1)
	ctVersion := uint32(ctBytes[0])<<24 | uint32(ctBytes[1])<<16 | uint32(ctBytes[2])<<8 | uint32(ctBytes[3])
	if ctVersion != 1 {
		t.Fatalf("Step 2: Ciphertext_V1 version prefix = %d, want 1", ctVersion)
	}
	t.Log("  ✓ Ciphertext_V1 生成，版本前缀=1")

	// === Step 3: 轮转 ===
	t.Log("Step 3: 轮转 trade-key，期望 V1→Deactivated, V2→Active")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys/trade-key/rotate", token, map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 3 Rotate: got %d, want 200 (resp=%v)", code, resp)
	}

	// 验证 V1 Deactivated。
	v1, _ := mgr.GetKey(ctx, "trade-key", 1)
	if v1.State != lifecycle.StateDeactivated {
		t.Fatalf("Step 3: V1 State = %v, want Deactivated", v1.State)
	}

	// 验证 V2 Active。
	v2, _ := mgr.GetKey(ctx, "trade-key", 2)
	if v2.State != lifecycle.StateActive {
		t.Fatalf("Step 3: V2 State = %v, want Active", v2.State)
	}
	if v2.Version != 2 {
		t.Fatalf("Step 3: V2 Version = %d, want 2", v2.Version)
	}
	t.Log("  ✓ V1 Deactivated, V2 Active 确认")

	// === Step 4: 二次加密 ===
	t.Log("Step 4: 二次加密相同明文 → Ciphertext_V2")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", token, map[string]interface{}{
		"key_id":    "trade-key",
		"plaintext": plaintextB64,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 4 Encrypt V2: got %d, want 200 (resp=%v)", code, resp)
	}

	ciphertextV2 := extractString(t, resp, "data", "ciphertext")
	if ciphertextV2 == "" {
		t.Fatal("Step 4: Ciphertext_V2 should not be empty")
	}

	// 验证密文版本前缀 = 2（V2 加密）。
	ctBytes2, _ := base64.StdEncoding.DecodeString(ciphertextV2)
	ctVersion2 := uint32(ctBytes2[0])<<24 | uint32(ctBytes2[1])<<16 | uint32(ctBytes2[2])<<8 | uint32(ctBytes2[3])
	if ctVersion2 != 2 {
		t.Fatalf("Step 4: Ciphertext_V2 version prefix = %d, want 2", ctVersion2)
	}

	// 验证两次密文不同（不同 Nonce + 不同版本号）。
	if ciphertextV1 == ciphertextV2 {
		t.Fatal("Step 4: Ciphertext_V1 and V2 should differ (nonce + version)")
	}
	t.Log("  ✓ Ciphertext_V2 生成，版本前缀=2")

	// === Step 5: 向后兼容验证（核心）===
	t.Log("Step 5: 【核心】向后兼容 — 解密 Ciphertext_V1（路由到 Deactivated V1）")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", token, map[string]interface{}{
		"key_id":     "trade-key",
		"ciphertext": ciphertextV1,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 5 Decrypt V1 (backward compat): got %d, want 200 — "+
			"解密旧密文必须成功！这是向后兼容的核心承诺 (resp=%v)", code, resp)
	}

	decryptedV1 := extractString(t, resp, "data", "plaintext")
	decV1Bytes, _ := base64.StdEncoding.DecodeString(decryptedV1)
	if string(decV1Bytes) != plaintext {
		t.Fatalf("Step 5: decrypted V1 = %q, want %q", string(decV1Bytes), plaintext)
	}
	t.Logf("  ✓ Ciphertext_V1 解密成功，明文一致：%q", plaintext)

	// === Step 6: 解密 V2 ===
	t.Log("Step 6: 解密 Ciphertext_V2（当前 Active V2）")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", token, map[string]interface{}{
		"key_id":     "trade-key",
		"ciphertext": ciphertextV2,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 6 Decrypt V2: got %d, want 200 (resp=%v)", code, resp)
	}

	decryptedV2 := extractString(t, resp, "data", "plaintext")
	decV2Bytes, _ := base64.StdEncoding.DecodeString(decryptedV2)
	if string(decV2Bytes) != plaintext {
		t.Fatalf("Step 6: decrypted V2 = %q, want %q", string(decV2Bytes), plaintext)
	}
	t.Logf("  ✓ Ciphertext_V2 解密成功，明文一致：%q", plaintext)

	// === Step 7: 数字火化 ===
	t.Log("Step 7: 数字火化 — ShredKey V1（模拟 180 天后硬删除）")

	code, _ = doRequestWithToken(t, r, http.MethodDelete, "/api/v1/keys/trade-key/shred", token, map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 7 ShredKey V1: got %d, want 200", code)
	}

	// 验证 V1 已物理删除（GetKey 返回 not found）。
	_, err = mgr.GetKey(ctx, "trade-key", 1)
	if err == nil {
		t.Fatal("Step 7: V1 should be physically destroyed (GetKey should fail)")
	}

	// 验证 V2 仍存在且 Active。
	v2After, _ := mgr.GetKey(ctx, "trade-key", 2)
	if v2After.State != lifecycle.StateActive {
		t.Fatalf("Step 7: V2 State after shred V1 = %v, want Active", v2After.State)
	}
	t.Log("  ✓ V1 物理删除，V2 仍 Active")

	// === Step 8: 历史粉碎验证 ===
	t.Log("Step 8: 【关键】历史粉碎 — Ciphertext_V1 解密必须失败（400）")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", token, map[string]interface{}{
		"key_id":     "trade-key",
		"ciphertext": ciphertextV1,
	})
	// 物理粉碎后版本不存在 → 404 或 400 均可（关键是不是 200）。
	if code == http.StatusOK {
		t.Fatalf("Step 8 Decrypt V1 after shred: got %d, want 4xx — "+
			"已粉碎的版本必须无法解密！(resp=%v)", code, resp)
	}
	if code < 400 || code >= 500 {
		t.Fatalf("Step 8 Decrypt V1 after shred: got %d, want 4xx (resp=%v)", code, resp)
	}
	t.Logf("  ✓ Ciphertext_V1 解密失败（HTTP %d），历史密文已永久不可读", code)

	// V2 密文仍可解密。
	t.Log("Step 8b: Ciphertext_V2 解密仍成功（V2 未受影响）")

	code, resp = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", token, map[string]interface{}{
		"key_id":     "trade-key",
		"ciphertext": ciphertextV2,
	})
	if code != http.StatusOK {
		t.Fatalf("Step 8b Decrypt V2 after shred V1: got %d, want 200 (resp=%v)", code, resp)
	}

	decryptedV2Final := extractString(t, resp, "data", "plaintext")
	decV2FinalBytes, _ := base64.StdEncoding.DecodeString(decryptedV2Final)
	if string(decV2FinalBytes) != plaintext {
		t.Fatalf("Step 8b: decrypted V2 = %q, want %q", string(decV2FinalBytes), plaintext)
	}
	t.Logf("  ✓ Ciphertext_V2 解密成功，明文一致：%q", plaintext)

	// === 终态总结 ===
	t.Log("")
	t.Log("=== E2E 时空穿越测试通过 ===")
	t.Log("  加密永远用最新版本（V2 Active）")
	t.Log("  解密永远向后兼容（V1 Deactivated 可解）")
	t.Log("  物理粉碎后历史密文永久不可读（V1 Shredded → 400）")
	t.Log("  现役密文不受影响（V2 仍可解）")

	// 避免 unused 警告。
	_ = kek
	_ = ctx
}
