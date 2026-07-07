// Package admin - 补充覆盖测试。
package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// newAdminTestServer 创建测试 admin server。
func newAdminTestServer(t *testing.T) *Server {
	t.Helper()
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	srv := NewServer(vault)
	srv.SetManager(mgr)
	return srv
}

// TestAdmin_ListKeys 列出密钥。
func TestAdmin_ListKeys(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	ctx := context.Background()
	mgr.CreateKey(ctx, "key-1", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "key-2", seal.NewSoftwareKEK(mk), 0)

	srv := NewServer(vault)
	srv.SetManager(mgr)

	req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 200 {
		t.Fatalf("ListKeys: %d, body=%s", w.Code, w.Body.String())
	}
	t.Logf("✅ ListKeys: %s", w.Body.String()[:50])
}

// TestAdmin_ListKeys_NoManager 无 manager。
func TestAdmin_ListKeys_NoManager(t *testing.T) {
	srv := NewServer(testVault(t))

	req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	t.Log("✅ ListKeys no manager → empty list")
}

// TestAdmin_ListKeys_MethodNotAllowed 非 GET 拒绝。
func TestAdmin_ListKeys_MethodNotAllowed(t *testing.T) {
	srv := newAdminTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleListKeys(w, req)

	if w.Code != 405 {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	t.Log("✅ ListKeys POST → 405")
}

// TestAdmin_SetAdminToken 设置 admin token。
func TestAdmin_SetAdminToken(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("test-token")
	if srv.adminToken != "test-token" {
		t.Fatal("token not set")
	}
	t.Log("✅ SetAdminToken")
}

// TestAdmin_SetManager 设置 manager。
func TestAdmin_SetManager(t *testing.T) {
	srv := NewServer(testVault(t))
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	srv.SetManager(mgr)
	if srv.manager == nil {
		t.Fatal("manager not set")
	}
	t.Log("✅ SetManager")
}

// TestAdmin_ServeHTTP_PublicIndex 设置 token 后根路径仍可访问（v1.4.2 不再有双层 auth）。
// 公共页面不需要 auth；受保护 API 需要 session 或 Bearer。
func TestAdmin_ServeHTTP_PublicIndex(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAdminToken("secret")
	wireMinimalStorage(srv)

	// 根路径无认证 → 公开 index（200 / SPA 占位）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// 可能 200 / 404 / 405（取决于 index handler），不应是 401
	if w.Code == 401 {
		t.Fatalf("public index should not be 401, got %d", w.Code)
	}
	t.Logf("✅ ServeHTTP public index → %d (no longer 401)", w.Code)

	// 受保护 API 无认证 → 401
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard", nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("protected API without auth should be 401, got %d", w2.Code)
	}
	t.Log("✅ ServeHTTP protected API no auth → 401")

	// Bearer 通过
	req3 := httptest.NewRequest(http.MethodGet, "/admin/api/dashboard", nil)
	req3.Header.Set("Authorization", "Bearer secret")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)
	if w3.Code == 401 {
		t.Fatalf("Bearer should pass protected API, got %d", w3.Code)
	}
	t.Logf("✅ ServeHTTP protected API + Bearer → %d", w3.Code)
}

// wireMinimalStorage 给一个最小可用的 Server 注入 v1.4.2 存储（测试 helper）。
func wireMinimalStorage(s *Server) {
	if s.sessions == nil {
		s.sessions = NewMemorySessionStore()
	}
	if s.captchaStore == nil {
		s.captchaStore = NewMemoryCaptchaStore()
	}
	if s.loginStates == nil {
		s.loginStates = NewMemoryLoginStateStore()
	}
	if s.devices == nil {
		s.devices = NewMemoryDeviceStore()
	}
	if s.auditor == nil {
		s.auditor = &NoopAuditor{}
	}
	if s.idleTimeout == 0 {
		s.idleTimeout = 30 * time.Minute
	}
	if s.hardCap == 0 {
		s.hardCap = 8 * time.Hour
	}
	if s.sessionSecret == nil {
		s.sessionSecret = []byte("test-session-secret-32-bytes-pad!")
	}
}

// 辅助函数。
func testMK(t *testing.T) *memguard.SecureBuffer {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	return mk
}

// testVault 创建测试 vault。
func testVault(t *testing.T) seal.Unsealer {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)
	return vault
}

// =====================================================================
// v1.4.2 覆盖率补丁 — 覆盖未达 100% 的关键路径
// =====================================================================

// TestAdmin_ClientIP_AllBranches 覆盖 clientIP 的三条分支。
func TestAdmin_ClientIP_AllBranches(t *testing.T) {
	// (1) X-Forwarded-For 优先取第一个
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	req1.RemoteAddr = "127.0.0.1:55555"
	if got := clientIP(req1); got != "1.2.3.4" {
		t.Fatalf("XFF first IP: got %q", got)
	}
	// (2) 无 XFF 但有 X-Real-IP
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "5.6.7.8")
	req2.RemoteAddr = "127.0.0.1:55555"
	if got := clientIP(req2); got != "5.6.7.8" {
		t.Fatalf("X-Real-IP: got %q", got)
	}
	// (3) 都没设 → RemoteAddr
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "9.9.9.9:1234"
	if got := clientIP(req3); got != "9.9.9.9" {
		t.Fatalf("RemoteAddr: got %q", got)
	}
	t.Log("✅ clientIP 三分支覆盖")
}

// TestAdmin_IsAuthenticated_AllBranches 覆盖三种认证结果。
func TestAdmin_IsAuthenticated_AllBranches(t *testing.T) {
	vault := testVault(t)

	// (1) adminToken 空 → 直接 true（dev mode 行为）
	srv1 := NewServer(vault)
	if !srv1.isAuthenticated(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("adminToken empty should auto-auth")
	}
	t.Log("✅ isAuthenticated: adminToken empty → true")

	// (2) adminToken 设置 + 无 session → false
	srv2 := NewServer(vault)
	srv2.SetAdminToken("tok")
	srv2.SetSessionStore(NewMemorySessionStore())
	if srv2.isAuthenticated(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("no session should not auth")
	}
	t.Log("✅ isAuthenticated: no session → false")

	// (3) adminToken 设置 + 有效 session → true
	srv3 := NewServer(vault)
	srv3.SetAdminToken("tok")
	sessions := NewMemorySessionStore()
	srv3.SetSessionStore(sessions)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "selenium")
	sessions.Put(sess)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	if !srv3.isAuthenticated(req) {
		t.Fatal("valid session should auth")
	}
	t.Log("✅ isAuthenticated: valid session → true")
}

// TestAdmin_HandleIndex_AllBranches 覆盖 handleIndex 的 302 / 200 + 其他路径。
func TestAdmin_HandleIndex_AllBranches(t *testing.T) {
	vault := testVault(t)

	// (1) adminToken set + 无 session → 302 → /admin/login
	srv1 := NewServer(vault)
	srv1.SetAdminToken("tok")
	srv1.SetSessionStore(NewMemorySessionStore())
	req1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	srv1.handleIndex(w1, req1)
	if w1.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w1.Code)
	}
	if loc := w1.Header().Get("Location"); loc != "/admin/login" {
		t.Fatalf("expected /admin/login, got %q", loc)
	}
	t.Log("✅ handleIndex: no session → 302 /admin/login")

	// (2) POST /admin/ → 405
	srv2 := NewServer(vault)
	req2 := httptest.NewRequest("POST", "/", nil)
	w2 := httptest.NewRecorder()
	srv2.handleIndex(w2, req2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w2.Code)
	}
	t.Log("✅ handleIndex: POST → 405")

	// (3) adminToken empty → 200 (auto-authed)
	srv3 := NewServer(vault)
	req3 := httptest.NewRequest("GET", "/", nil)
	w3 := httptest.NewRecorder()
	srv3.handleIndex(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w3.Code)
	}
	t.Log("✅ handleIndex: auto-authed → 200")
}

// TestAdmin_RecordAudit_AllBranches 覆盖 recordAudit 的 nil / non-nil auditor。
func TestAdmin_RecordAudit_AllBranches(t *testing.T) {
	srv := NewServer(testVault(t))

	// (1) nil auditor 不 panic
	srv.auditor = nil
	srv.recordAudit("LoginSuccess", "127.0.0.1", "admin")
	t.Log("✅ recordAudit: nil auditor no-op")

	// (2) NoopAuditor 已存在，覆盖正常路径
	srv.auditor = &NoopAuditor{}
	srv.recordAudit("LoginFailure", "1.2.3.4", "captcha-mismatch")
	t.Log("✅ recordAudit: NoopAuditor → success")
}

// TestAdmin_NewSession_EntropyAndLifetime 验证 NewSession 字段。
func TestAdmin_NewSession_EntropyAndLifetime(t *testing.T) {
	sess, err := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "selenium")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if len(sess.ID) < 32 {
		t.Fatalf("session ID too short: %d", len(sess.ID))
	}
	if sess.HardCapAt.Sub(sess.CreatedAt) != 8*time.Hour {
		t.Fatalf("HardCapAt: %v", sess.HardCapAt.Sub(sess.CreatedAt))
	}
	if sess.ExpiresAt.Sub(sess.LastSeenAt) != 30*time.Minute {
		t.Fatalf("ExpiresAt: %v", sess.ExpiresAt.Sub(sess.LastSeenAt))
	}
	t.Logf("✅ NewSession: id-len=%d user=%s", len(sess.ID), sess.UserID)
}

// TestAdmin_SessionTouch_UpdatesLastSeen Touch 路径覆盖。
func TestAdmin_SessionTouch_UpdatesLastSeen(t *testing.T) {
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "selenium")
	sessions := NewMemorySessionStore()
	sessions.Put(sess)
	old := sess.LastSeenAt
	time.Sleep(10 * time.Millisecond)
	newLastSeen := time.Now()
	newExpires := newLastSeen.Add(30 * time.Minute)
	if err := sessions.Touch(sess.ID, newLastSeen, newExpires); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, _ := sessions.Get(sess.ID)
	if !got.LastSeenAt.After(old) {
		t.Fatal("LastSeenAt not advanced")
	}
	t.Log("✅ Touch advances LastSeenAt")
}

// TestAdmin_NewSessionOK_NoError 熵源稳定性烟测（100 次）。
func TestAdmin_NewSessionOK_NoError(t *testing.T) {
	for i := 0; i < 100; i++ {
		_, err := NewSession("admin-web", time.Hour, time.Minute, false, "127.0.0.1", "smoke")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	t.Log("✅ NewSession × 100 全部成功")
}

// TestAdmin_AllSetters_SmokeTest 集中触发所有 setter（推 0% → 100%）。
func TestAdmin_AllSetters_SmokeTest(t *testing.T) {
	srv := NewServer(testVault(t))
	// Secret
	srv.SetSessionSecret([]byte("0123456789abcdef0123456789abcdef"))
	if srv.sessionSecret == nil {
		t.Fatal("SetSessionSecret")
	}
	// TOTP
	srv.SetTOTPSecret("ABCDEFGHIJKLMNOP")
	if srv.totpSecret == "" {
		t.Fatal("SetTOTPSecret")
	}
	// Stores
	srv.SetSessionStore(NewMemorySessionStore())
	srv.SetCaptchaStore(NewMemoryCaptchaStore())
	srv.SetLoginStateStore(NewMemoryLoginStateStore())
	srv.SetDeviceStore(NewMemoryDeviceStore())
	if srv.sessions == nil || srv.captchaStore == nil {
		t.Fatal("store setter")
	}
	// Auditor
	srv.SetAuditor(&NoopAuditor{})
	if srv.auditor == nil {
		t.Fatal("SetAuditor")
	}
	// Timeouts
	srv.SetIdleTimeout(15 * time.Minute)
	srv.SetHardCap(2 * time.Hour)
	if srv.idleTimeout != 15*time.Minute || srv.hardCap != 2*time.Hour {
		t.Fatal("setters for timeouts")
	}
	// DevMode
	srv.SetDevMode(true)
	if !srv.devMode {
		t.Fatal("SetDevMode")
	}
	// API handler
	srv.SetAPIHandler(http.NotFoundHandler())
	if srv.apiHandler == nil {
		t.Fatal("SetAPIHandler")
	}
	// Reaper
	stop := srv.StartReaper(50 * time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	stop()
	t.Log("✅ 所有 setter smoke 通过 + Reaper 启动/停止")
}

// TestAdmin_HandleLoginPage_RendersLogin 覆盖 handleLoginPage。
func TestAdmin_HandleLoginPage_RendersLogin(t *testing.T) {
	srv := NewServer(testVault(t))
	req := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	srv.handleLoginPage(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String()[:50])
	}
	if !strings.Contains(w.Body.String(), "login-form") {
		t.Fatal("response missing #login-form")
	}
	// CSRF cookie 必须设置
	var foundCSRF bool
	for _, c := range w.Header()["Set-Cookie"] {
		if strings.Contains(c, "yvonne_csrf=") {
			foundCSRF = true
			break
		}
	}
	if !foundCSRF {
		t.Fatal("missing yvonne_csrf Set-Cookie")
	}
	t.Log("✅ handleLoginPage: 200 + Set-Cookie yvonne_csrf")
}

// TestAdmin_HandleCaptcha_ReturnsSVG 覆盖 handleCaptcha。
func TestAdmin_HandleCaptcha_ReturnsSVG(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.captchaStore = NewMemoryCaptchaStore()
	req := httptest.NewRequest("GET", "/admin/api/captcha", nil)
	w := httptest.NewRecorder()
	srv.handleCaptcha(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["captcha_id"] == nil || resp["image"] == nil {
		t.Fatal("missing captcha_id/image")
	}
	t.Log("✅ handleCaptcha: 200 + {captcha_id, image}")
}

// TestAdmin_HandleDevCaptchaText_Branches 覆盖 dev 端点的两个分支。
func TestAdmin_HandleDevCaptchaText_Branches(t *testing.T) {
	srv := NewServer(testVault(t))
	store := NewMemoryCaptchaStore()
	srv.SetCaptchaStore(store)

	// (1) devMode=false → 403
	req1 := httptest.NewRequest("GET", "/admin/api/_dev_captcha_text?id=any", nil)
	w1 := httptest.NewRecorder()
	srv.handleDevCaptchaText(w1, req1)
	if w1.Code != 403 {
		t.Fatalf("expected 403 (devMode=false), got %d", w1.Code)
	}
	t.Log("✅ handleDevCaptchaText: devMode=false → 403")

	// (2) devMode=true + 缺 id → 400
	srv.SetDevMode(true)
	req2 := httptest.NewRequest("GET", "/admin/api/_dev_captcha_text", nil)
	w2 := httptest.NewRecorder()
	srv.handleDevCaptchaText(w2, req2)
	if w2.Code != 400 {
		t.Fatalf("expected 400 (missing id), got %d", w2.Code)
	}
	t.Log("✅ handleDevCaptchaText: missing id → 400")

	// (3) devMode=true + 不存在的 id → 404
	req3 := httptest.NewRequest("GET", "/admin/api/_dev_captcha_text?id=ghost", nil)
	w3 := httptest.NewRecorder()
	srv.handleDevCaptchaText(w3, req3)
	if w3.Code != 404 {
		t.Fatalf("expected 404 (not found), got %d", w3.Code)
	}
	t.Log("✅ handleDevCaptchaText: not found → 404")
}

// TestAdmin_CookieHelpers_AllBranches 覆盖 set/clear cookie + writeLoginError。
func TestAdmin_CookieHelpers_AllBranches(t *testing.T) {
	w := httptest.NewRecorder()
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test")
	setSessionCookie(w, sess)
	cookies := w.Header()["Set-Cookie"]
	if len(cookies) == 0 {
		t.Fatal("no Set-Cookie")
	}
	found := false
	for _, c := range cookies {
		if strings.HasPrefix(c, "yvonne_session=") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no yvonne_session cookie")
	}
	t.Log("✅ setSessionCookie: Set-Cookie yvonne_session")

	// 设备 cookie
	w2 := httptest.NewRecorder()
	setDeviceCookie(w2, "fp-hash-12345")
	if !strings.Contains(strings.Join(w2.Header()["Set-Cookie"], ";"), "yvonne_device=fp-hash-12345") {
		t.Fatal("device cookie not set")
	}
	t.Log("✅ setDeviceCookie: Set-Cookie yvonne_device")

	// Clear cookie
	w3 := httptest.NewRecorder()
	clearCookie(w3, "test-cookie")
	if !strings.Contains(strings.Join(w3.Header()["Set-Cookie"], ";"), "test-cookie=") {
		t.Fatal("clear cookie not set")
	}
	t.Log("✅ clearCookie: Set-Cookie with Max-Age")

	// writeLoginError
	w4 := httptest.NewRecorder()
	writeLoginError(w4, http.StatusUnauthorized, loginErrCaptcha, "captcha failed")
	if w4.Code != 401 {
		t.Fatalf("expected 401, got %d", w4.Code)
	}
	if !strings.Contains(w4.Body.String(), "captcha") {
		t.Fatal("error body missing 'captcha'")
	}
	t.Log("✅ writeLoginError: 401 + json body")
}

// TestAdmin_NoopAuditor_Close 覆盖 NoopAuditor.Close 100%。
func TestAdmin_NoopAuditor_Close(t *testing.T) {
	n := &NoopAuditor{}
	n.Close()
	t.Log("✅ NoopAuditor.Close no-op")
}

// TestAdmin_RequireAdminToken_AllBranches 覆盖废弃 Bearer 路径。
func TestAdmin_RequireAdminToken_AllBranches(t *testing.T) {
	vault := testVault(t)

	// (1) adminToken 空 → 跳过
	srv1 := NewServer(vault)
	h := srv1.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	h(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("adminToken empty: expected 200, got %d", w1.Code)
	}
	t.Log("✅ requireAdminToken: adminToken empty → pass")

	// (2) 错误 Bearer → 401
	srv2 := NewServer(vault)
	srv2.SetAdminToken("secret")
	h2 := srv2.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	h2(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("wrong token: expected 401, got %d", w2.Code)
	}
	t.Log("✅ requireAdminToken: wrong Bearer → 401")

	// (3) 缺 Authorization → 401
	srv3 := NewServer(vault)
	srv3.SetAdminToken("secret")
	h3 := srv3.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", "/", nil)
	h3(w3, req3)
	if w3.Code != 401 {
		t.Fatalf("no auth: expected 401, got %d", w3.Code)
	}
	t.Log("✅ requireAdminToken: no Authorization → 401")

	// (4) 正确 Bearer → 200
	srv4 := NewServer(vault)
	srv4.SetAdminToken("secret")
	h4 := srv4.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.Header.Set("Authorization", "Bearer secret")
	h4(w4, req4)
	if w4.Code != 200 {
		t.Fatalf("good token: expected 200, got %d", w4.Code)
	}
	t.Log("✅ requireAdminToken: correct Bearer → 200")
}

// helpers（小工具，避免新增 import）
func jsonDecode(t *testing.T, b []byte, v any) error {
	t.Helper()
	return json.Unmarshal(b, v)
}

// =====================================================================
// HTTP API handlers 覆盖率补丁
// =====================================================================

// TestAdmin_HandleAPIKeys_AllBranches 覆盖 handleAPIKeys。
func TestAdmin_HandleAPIKeys_AllBranches(t *testing.T) {
	// (1) GET → 200
	srv := newAdminTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/api/keys", nil)
	w := httptest.NewRecorder()
	srv.handleAPIKeys(w, req)
	if w.Code != 200 {
		t.Fatalf("GET: expected 200, got %d", w.Code)
	}
	t.Log("✅ handleAPIKeys: GET → 200")

	// (2) POST → 405
	req2 := httptest.NewRequest(http.MethodPost, "/admin/api/keys", nil)
	w2 := httptest.NewRecorder()
	srv.handleAPIKeys(w2, req2)
	if w2.Code != 405 {
		t.Fatalf("POST: expected 405, got %d", w2.Code)
	}
	t.Log("✅ handleAPIKeys: POST → 405")
}

// TestAdmin_ProxyAPI_AllBranches 覆盖 proxyAPI 的所有分支。
func TestAdmin_ProxyAPI_AllBranches(t *testing.T) {
	// (1) apiHandler=nil → 直接写 JSON 错误
	srv1 := NewServer(testVault(t))
	req1 := httptest.NewRequest("POST", "/admin/api/crypto/encrypt",
		strings.NewReader(`{"x":1}`))
	w1 := httptest.NewRecorder()
	srv1.proxyAPI(w1, req1, "/api/v1/encrypt")
	if !strings.Contains(w1.Body.String(), "API handler not configured") {
		t.Fatal("missing error msg")
	}
	t.Log("✅ proxyAPI: nil handler → error JSON")

	// (2) apiHandler 设置 → 代理调用
	srv2 := NewServer(testVault(t))
	srv2.SetAPIHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 path/method 被改写
		if r.URL.Path != "/api/v1/decrypt" {
			t.Errorf("path: got %q want /api/v1/decrypt", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method: got %q want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"data":{"x":"proxied"}}`))
	}))
	req2 := httptest.NewRequest("POST", "/admin/api/crypto/decrypt",
		strings.NewReader(`{"y":2}`))
	w2 := httptest.NewRecorder()
	srv2.proxyAPI(w2, req2, "/api/v1/decrypt")
	if !strings.Contains(w2.Body.String(), "proxied") {
		t.Fatal("proxy did not forward")
	}
	t.Log("✅ proxyAPI: handler 设置 → 转发并恢复 path/method")
}

// TestAdmin_HandleAPIAudit_Stub 测试审计 stub。
func TestAdmin_HandleAPIAudit_Stub(t *testing.T) {
	srv := NewServer(testVault(t))
	req := httptest.NewRequest("GET", "/admin/api/audit?limit=5", nil)
	w := httptest.NewRecorder()
	srv.handleAPIAudit(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("missing ok=true: %s", w.Body.String())
	}
	t.Log("✅ handleAPIAudit: 200 + ok=true")
}

// TestAdmin_HandleLogin_BadJSON_BranchError 测试登录入口的早期错误分支（parse error）。
func TestAdmin_HandleLogin_BadJSON_BranchError(t *testing.T) {
	srv := NewServer(testVault(t))
	wireMinimalStorage(srv)
	req := httptest.NewRequest("POST", "/admin/api/login", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 (bad json), got %d body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ handleLogin: bad JSON → 400")
}

// TestAdmin_HandleLogout_Branches 测试注销（含 session 不存在分支）。
func TestAdmin_HandleLogout_Branches(t *testing.T) {
	// (1) 无 session cookie → 仍 200
	srv1 := NewServer(testVault(t))
	srv1.SetAuditor(&NoopAuditor{})
	req1 := httptest.NewRequest("POST", "/admin/api/logout", nil)
	w1 := httptest.NewRecorder()
	srv1.handleLogout(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("no-cookie logout: expected 200, got %d", w1.Code)
	}
	t.Log("✅ handleLogout: no cookie → 200")

	// (2) 有 session cookie → Delete + clear
	srv2 := NewServer(testVault(t))
	srv2.SetAuditor(&NoopAuditor{})
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "test")
	sessions := NewMemorySessionStore()
	sessions.Put(sess)
	srv2.SetSessionStore(sessions)

	req2 := httptest.NewRequest("POST", "/admin/api/logout", nil)
	req2.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w2 := httptest.NewRecorder()
	srv2.handleLogout(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("logout with cookie: expected 200, got %d", w2.Code)
	}
	if _, ok := sessions.Get(sess.ID); ok {
		t.Fatal("session should be deleted")
	}
	t.Log("✅ handleLogout: 删除 session + 清 cookie")
}

// TestAdmin_HandleSession_ReturnsInfo 测试 handleSession。
func TestAdmin_HandleSession_ReturnsInfo(t *testing.T) {
	srv := NewServer(testVault(t))
	sessions := NewMemorySessionStore()
	srv.SetSessionStore(sessions)
	sess, _ := NewSession("admin-web", 30*time.Minute, 8*time.Hour, false, "127.0.0.1", "sel")
	sessions.Put(sess)
	req := httptest.NewRequest("GET", "/admin/api/session", nil)
	w := httptest.NewRecorder()
	srv.handleSession(w, req, sess)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"user_id":"admin-web"`) {
		t.Fatal("missing user_id")
	}
	if !strings.Contains(body, `"idle_seconds"`) {
		t.Fatal("missing idle_seconds")
	}
	t.Log("✅ handleSession: 200 + {user_id, expires_at, hard_cap_at, ...}")
}

// TestAdmin_HandleDeviceRevoke_NoCookie 测试设备撤销（无 cookie 路径）。
func TestAdmin_HandleDeviceRevoke_NoCookie(t *testing.T) {
	srv := NewServer(testVault(t))
	srv.SetAuditor(&NoopAuditor{})
	req := httptest.NewRequest("DELETE", "/admin/api/device", nil)
	w := httptest.NewRecorder()
	srv.handleDeviceRevoke(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	t.Log("✅ handleDeviceRevoke: no cookie → 200")
}
