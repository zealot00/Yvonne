//go:build integration

// P0 安全修复：资源级越权拦截测试。
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/metrics"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

type testRole struct {
	RoleID         string
	Token          string
	AllowedKeys    []string
	AllowedActions []string
}

// newAuthRouter 创建带认证的 V1Router，返回 router、manager、store、masterKey。
func newAuthRouter(t *testing.T, roles []testRole) (*V1Router, *lifecycle.Manager, *storage.MemoryStore, *memguard.SecureBuffer) {
	t.Helper()

	masterKey, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(func() { masterKey.Wipe() })

	vault := seal.NewVaultState(5, 3, 0)
	if err := vault.DirectUnseal(masterKey); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	var auditBuf bytes.Buffer
	logger, _ := audit.NewAuditLogger(&auditBuf)
	t.Cleanup(func() { logger.Close() })

	reg := metrics.NewRegistry()

	authenticator := auth.NewAppRoleAuthenticator()
	for _, r := range roles {
		authenticator.RegisterPolicy(r.RoleID, r.Token, &auth.Policy{
			RoleID:         r.RoleID,
			AllowedKeys:    r.AllowedKeys,
			AllowedActions: r.AllowedActions,
		})
	}

	r := NewV1Router(vault, logger, mgr, reg, authenticator)
	return r, mgr, store, masterKey
}

func doRequestWithToken(t *testing.T, r *V1Router, method, path, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(raw)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

// createKey 辅助：用 masterKey 创建密钥。
func createKey(t *testing.T, mgr *lifecycle.Manager, mk *memguard.SecureBuffer, keyID string) {
	t.Helper()
	if _, _, err := mgr.CreateKey(context.Background(), keyID, mk, 0); err != nil {
		t.Fatalf("CreateKey %s: %v", keyID, err)
	}
}

// TestRBAC_EncryptAllowedKey 验证有权限的 Token 可以加密。
func TestRBAC_EncryptAllowedKey(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token-xxx", []string{"order-*"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
	})
	createKey(t, mgr, mk, "order-key")

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "order-token-xxx", map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt with allowed key: got %d, want 200", code)
	}
}

// TestRBAC_EncryptForbiddenKey 验证越权访问返回 403。
// order-service Token 尝试加密 user-key → 必须返回 403。
func TestRBAC_EncryptForbiddenKey(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token-xxx", []string{"order-*"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
	})
	createKey(t, mgr, mk, "user-key")

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "order-token-xxx", map[string]interface{}{
		"key_id":    "user-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusForbidden {
		t.Fatalf("encrypt forbidden key: got %d, want 403", code)
	}
}

// TestRBAC_DecryptForbiddenKey 验证越权解密返回 403。
func TestRBAC_DecryptForbiddenKey(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token-xxx", []string{"order-*"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
		{"user-service", "user-token-yyy", []string{"user-*"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
	})
	createKey(t, mgr, mk, "user-key")

	// 用 user-service token 加密 user-key。
	code, resp := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "user-token-yyy", map[string]interface{}{
		"key_id":    "user-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt user-key: got %d, want 200", code)
	}
	ciphertext := extractString(t, resp, "data", "ciphertext")

	// order-service token 尝试解密 user-key 的密文 → 403。
	code, _ = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", "order-token-xxx", map[string]interface{}{
		"key_id":     "user-key",
		"ciphertext": ciphertext,
	})
	if code != http.StatusForbidden {
		t.Fatalf("decrypt forbidden key: got %d, want 403", code)
	}
}

// TestRBAC_WildcardKeyAccess 验证 "*" 通配符允许所有 key。
func TestRBAC_WildcardKeyAccess(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"admin", "admin-token-zzz", []string{"*"}, []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp"}},
	})
	createKey(t, mgr, mk, "any-key")

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "admin-token-zzz", map[string]interface{}{
		"key_id":    "any-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusOK {
		t.Fatalf("admin encrypt with wildcard: got %d, want 200", code)
	}
}

// TestRBAC_NoToken 验证无 Token 返回 401。
func TestRBAC_NoToken(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token-xxx", []string{"order-*"}, []string{"Encrypt", "Decrypt"}},
	})
	createKey(t, mgr, mk, "order-key")

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "", map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", code)
	}
}

// TestRBAC_InvalidToken 验证无效 Token 返回 401。
func TestRBAC_InvalidToken(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token-xxx", []string{"order-*"}, []string{"Encrypt", "Decrypt"}},
	})
	createKey(t, mgr, mk, "order-key")

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "invalid-token", map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("invalid token: got %d, want 401", code)
	}
}

// TestRBAC_ActionForbidden 验证 Action 越权返回 403。
func TestRBAC_ActionForbidden(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"encrypt-only", "enc-only-token", []string{"order-*"}, []string{"Encrypt"}},
	})
	createKey(t, mgr, mk, "order-key")

	code, resp := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "enc-only-token", map[string]interface{}{
		"key_id":    "order-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt with allowed action: got %d, want 200", code)
	}
	ciphertext := extractString(t, resp, "data", "ciphertext")

	code, _ = doRequestWithToken(t, r, http.MethodPost, "/api/v1/decrypt", "enc-only-token", map[string]interface{}{
		"key_id":     "order-key",
		"ciphertext": ciphertext,
	})
	if code != http.StatusForbidden {
		t.Fatalf("decrypt without action permission: got %d, want 403", code)
	}
}

// TestRBAC_PrefixMatch 验证前缀通配符匹配。
func TestRBAC_PrefixMatch(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token", []string{"order-*"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
	})

	createKey(t, mgr, mk, "order-001")
	createKey(t, mgr, mk, "order-002")
	createKey(t, mgr, mk, "payment-001")

	// order-001 允许。
	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "order-token", map[string]interface{}{
		"key_id":    "order-001",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusOK {
		t.Fatalf("order-001 should be allowed: got %d", code)
	}

	// payment-001 不允许。
	code, _ = doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "order-token", map[string]interface{}{
		"key_id":    "payment-001",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusForbidden {
		t.Fatalf("payment-001 should be forbidden: got %d, want 403", code)
	}
}

// TestRBAC_ExactMatch 验证精确匹配（无通配符）。
func TestRBAC_ExactMatch(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"exact-role", "exact-token", []string{"exact-key"}, []string{"Encrypt", "Decrypt", "CreateKey"}},
	})

	createKey(t, mgr, mk, "exact-key")
	createKey(t, mgr, mk, "exact-key-2")

	// exact-key 允许。
	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "exact-token", map[string]interface{}{
		"key_id":    "exact-key",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusOK {
		t.Fatalf("exact-key should be allowed: got %d", code)
	}

	// exact-key-2 不允许（精确匹配不前缀）。
	code, _ = doRequestWithToken(t, r, http.MethodPost, "/api/v1/encrypt", "exact-token", map[string]interface{}{
		"key_id":    "exact-key-2",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != http.StatusForbidden {
		t.Fatalf("exact-key-2 should be forbidden: got %d, want 403", code)
	}
}

// TestRBAC_KeyOpPathAuthorization 验证 /keys/{id}/rotate 路径中的 key_id 授权。
func TestRBAC_KeyOpPathAuthorization(t *testing.T) {
	r, mgr, _, mk := newAuthRouter(t, []testRole{
		{"order-service", "order-token", []string{"order-*"}, []string{"Encrypt", "Decrypt", "CreateKey", "KeyOp"}},
	})

	createKey(t, mgr, mk, "order-key")
	createKey(t, mgr, mk, "user-key")

	// 轮转 order-key 允许。
	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys/order-key/rotate", "order-token", map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("rotate order-key: got %d, want 200", code)
	}

	// 轮转 user-key 不允许 → 403。
	code, _ = doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys/user-key/rotate", "order-token", map[string]interface{}{
		"version": 1,
	})
	if code != http.StatusForbidden {
		t.Fatalf("rotate user-key: got %d, want 403", code)
	}
}

// TestRBAC_CreateKeyAuthorization 验证 CreateKey 的授权。
func TestRBAC_CreateKeyAuthorization(t *testing.T) {
	r, _, _, _ := newAuthRouter(t, []testRole{
		{"no-create-role", "no-create-token", []string{"*"}, []string{"Encrypt", "Decrypt"}},
	})

	code, _ := doRequestWithToken(t, r, http.MethodPost, "/api/v1/keys", "no-create-token", map[string]interface{}{
		"key_id": "new-key",
	})
	if code != http.StatusForbidden {
		t.Fatalf("create key without permission: got %d, want 403", code)
	}
}
