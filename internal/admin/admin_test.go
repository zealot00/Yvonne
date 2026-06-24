package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// newTestAdminServer 创建测试用 admin Server（Unsealed 状态）。
func newTestAdminServer(t *testing.T) *Server {
	t.Helper()
	mk, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	t.Cleanup(func() { mk.Wipe() })

	v := seal.NewVaultState(3, 2, 0)
	if err := v.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}
	return NewServer(v)
}

// doRequest 发送请求并返回 status code + 解析后的 JSON body。
func doRequest(t *testing.T, s *Server, method, path string, body string) (int, map[string]interface{}) {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

// =====================================================================
// seal-status
// =====================================================================

func TestHandleSealStatus_Unsealed(t *testing.T) {
	s := newTestAdminServer(t)

	code, resp := doRequest(t, s, http.MethodGet, "/admin/api/seal-status", "")
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
	if resp["sealed"] != false {
		t.Fatal("sealed should be false")
	}
	if resp["state"] != "unsealed" {
		t.Fatalf("state = %v, want unsealed", resp["state"])
	}
}

func TestHandleSealStatus_Sealed(t *testing.T) {
	s := newTestAdminServer(t)
	s.seal.Seal(context.Background())

	code, resp := doRequest(t, s, http.MethodGet, "/admin/api/seal-status", "")
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
	if resp["sealed"] != true {
		t.Fatal("sealed should be true")
	}
	if resp["state"] != "sealed" {
		t.Fatalf("state = %v, want sealed", resp["state"])
	}
}

func TestHandleSealStatus_MethodNotAllowed(t *testing.T) {
	s := newTestAdminServer(t)
	code, _ := doRequest(t, s, http.MethodPost, "/admin/api/seal-status", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("POST seal-status: got %d, want 405", code)
	}
}

// =====================================================================
// seal
// =====================================================================

func TestHandleSeal_Success(t *testing.T) {
	s := newTestAdminServer(t)

	if !s.seal.IsUnsealed() {
		t.Fatal("should start unsealed")
	}

	code, resp := doRequest(t, s, http.MethodPost, "/admin/api/seal", "")
	if code != http.StatusOK {
		t.Fatalf("seal: got %d, want 200", code)
	}
	if resp["sealed"] != true {
		t.Fatal("response sealed should be true")
	}
	if !s.seal.IsSealed() {
		t.Fatal("vault should be sealed after API call")
	}
}

func TestHandleSeal_AlreadySealed(t *testing.T) {
	s := newTestAdminServer(t)
	s.seal.Seal(context.Background())

	// 再次 Seal 应幂等成功。
	code, resp := doRequest(t, s, http.MethodPost, "/admin/api/seal", "")
	if code != http.StatusOK {
		t.Fatalf("seal twice: got %d, want 200", code)
	}
	if resp["sealed"] != true {
		t.Fatal("sealed should be true")
	}
}

func TestHandleSeal_MethodNotAllowed(t *testing.T) {
	s := newTestAdminServer(t)
	code, _ := doRequest(t, s, http.MethodGet, "/admin/api/seal", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET seal: got %d, want 405", code)
	}
}

// =====================================================================
// unseal
// =====================================================================

func TestHandleUnseal_MethodNotAllowed(t *testing.T) {
	s := newTestAdminServer(t)
	code, _ := doRequest(t, s, http.MethodGet, "/admin/api/unseal", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET unseal: got %d, want 405", code)
	}
}

func TestHandleUnseal_InvalidJSON(t *testing.T) {
	s := newTestAdminServer(t)
	s.seal.Seal(context.Background())

	code, _ := doRequest(t, s, http.MethodPost, "/admin/api/unseal", "not-json")
	if code != http.StatusBadRequest {
		t.Fatalf("invalid JSON: got %d, want 400", code)
	}
}

func TestHandleUnseal_InvalidShare(t *testing.T) {
	s := newTestAdminServer(t)
	s.seal.Seal(context.Background())

	// 提交空 share 应返回 400。
	code, _ := doRequest(t, s, http.MethodPost, "/admin/api/unseal", `{"share":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty share: got %d, want 400", code)
	}
}

func TestHandleUnseal_ValidShareAccepted(t *testing.T) {
	s := newTestAdminServer(t)
	s.seal.Seal(context.Background())

	// 提交一份 base64 share（未达 threshold=2，应返回 200 + unsealed=false）。
	code, resp := doRequest(t, s, http.MethodPost, "/admin/api/unseal", `{"share":"AAAA"}`)
	if code != http.StatusOK {
		t.Fatalf("valid share: got %d, want 200", code)
	}
	if resp["unsealed"] != false {
		t.Fatal("unsealed should be false (not enough shares yet)")
	}
}

func TestHandleUnseal_AlreadyUnsealed(t *testing.T) {
	s := newTestAdminServer(t)

	// 已 Unsealed 状态下提交 share 应返回错误。
	code, resp := doRequest(t, s, http.MethodPost, "/admin/api/unseal", `{"share":"AAAA"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("already unsealed: got %d, want 400", code)
	}
	if _, ok := resp["error"]; !ok {
		t.Fatal("should contain error")
	}
}

// =====================================================================
// 静态资源与首页
// =====================================================================

func TestHandleIndex_Success(t *testing.T) {
	s := newTestAdminServer(t)
	code, resp := doRequest(t, s, http.MethodGet, "/", "")
	if code != http.StatusOK {
		t.Fatalf("index: got %d, want 200", code)
	}
	// HTML 不解析为 JSON，resp 应为 nil 或空。
	_ = resp
}

func TestHandleIndex_MethodNotAllowed(t *testing.T) {
	s := newTestAdminServer(t)
	code, _ := doRequest(t, s, http.MethodPost, "/", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /: got %d, want 405", code)
	}
}

func TestStaticAssets(t *testing.T) {
	s := newTestAdminServer(t)

	assets := []string{"/static/app.js", "/static/style.css"}
	for _, path := range assets {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: empty body", path)
		}
	}
}

// =====================================================================
// 安全响应头
// =====================================================================

func TestSecurityHeaders(t *testing.T) {
	s := newTestAdminServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, want := range checks {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header missing")
	}
}

// =====================================================================
// 完整 Seal → Unseal 流程
// =====================================================================

func TestSealUnseal_FullFlow(t *testing.T) {
	s := newTestAdminServer(t)

	// 1. 初始 Unsealed。
	code, resp := doRequest(t, s, http.MethodGet, "/admin/api/seal-status", "")
	if resp["sealed"] != false {
		t.Fatal("should start unsealed")
	}

	// 2. Seal。
	code, _ = doRequest(t, s, http.MethodPost, "/admin/api/seal", "")
	if code != http.StatusOK {
		t.Fatalf("seal: got %d", code)
	}

	// 3. 确认 Sealed。
	code, resp = doRequest(t, s, http.MethodGet, "/admin/api/seal-status", "")
	if resp["sealed"] != true {
		t.Fatal("should be sealed after seal API")
	}

	// 4. Unseal 提交一份 share（未达 threshold=2，应返回 200 + unsealed=false）。
	code, _ = doRequest(t, s, http.MethodPost, "/admin/api/unseal", `{"share":"AAAA"}`)
	if code != http.StatusOK {
		t.Fatalf("share submit: got %d, want 200", code)
	}

	// 5. 仍应 Sealed。
	code, resp = doRequest(t, s, http.MethodGet, "/admin/api/seal-status", "")
	if resp["sealed"] != true {
		t.Fatal("should still be sealed after partial unseal")
	}
}

// =====================================================================
// 404 路径回退到 index.html
// =====================================================================

func TestUnknownPath_FallbackToIndex(t *testing.T) {
	s := newTestAdminServer(t)
	req := httptest.NewRequest(http.MethodGet, "/some/unknown/route", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	// SPA 回退：应返回 index.html（200）。
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown route: got %d, want 200 (SPA fallback)", rec.Code)
	}
}
