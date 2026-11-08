// Package admin - Login Flow 单元测试（v1.4.2）。
//
// loginFlow 核心函数被 handler 调用，这里直接测逻辑层。
// 覆盖：
//  1. 成功（captcha + token + TOTP 全对）
//  2. captcha 错 → 401，失败计数 +1
//  3. token 错 → 401，失败计数 +1
//  4. TOTP 错 → 401，失败计数 +1
//  5. 3 次失败后被锁
//  6. 设备指纹命中 → 跳过 captcha + TOTP，仍需 adminToken
//  7. dev 模式（adminToken 空）→ 直接通过，无 captcha/TOTP
//  8. TOTP secret 空 → 跳过 TOTP（dev 模式语义一致）
//  9. 登录态被锁 → 401
package admin

import (
	"strings"
	"testing"
	"time"

	"yvonne/internal/auth"
)

// testLoginServer 构造一个最小可用 Server 用于测 loginFlow。
//   - adminToken = "secret-token"
//   - totpSecret = 生成的 base32
//   - sessions / captcha / loginStates / devices 都是内存版
//   - sessionSecret = 32 字节（设备指纹 salt）
//   - idle=30min, hardCap=8h
func testLoginServer(t *testing.T) (*Server, string) {
	t.Helper()
	totpSecret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	s := &Server{
		adminToken:    "secret-token",
		totpSecret:    totpSecret,
		sessionSecret: []byte("test-session-secret-32bytes-pad!"),
		sessions:      NewMemorySessionStore(),
		captchaStore:  NewMemoryCaptchaStore(),
		loginStates:   NewMemoryLoginStateStore(),
		devices:       NewMemoryDeviceStore(),
		auditor:       &NoopAuditor{},
		idleTimeout:   30 * time.Minute,
		hardCap:       8 * time.Hour,
	}
	return s, totpSecret
}

// validCaptcha 在 store 里 Put 一个 captcha，返回其 ID 和文本。
func validCaptcha(t *testing.T, s *Server) (string, string) {
	t.Helper()
	c, err := NewCaptcha(captchaWidth, captchaHeight)
	if err != nil {
		t.Fatalf("NewCaptcha: %v", err)
	}
	s.captchaStore.Put(c)
	return c.ID, c.Text
}

// validTOTP 用 secret 计算当前 6 位 code。
func validTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	return code
}

func TestLoginFlow_Success(t *testing.T) {
	s, totp := testLoginServer(t)
	capID, capText := validCaptcha(t, s)

	sess, dev, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		TOTPCode:    validTOTP(t, totp),
		CaptchaID:   capID,
		CaptchaText: capText,
		Remember:    false,
	}, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("loginFlow: %v", err)
	}
	if sess == nil || sess.ID == "" {
		t.Fatal("session should be created")
	}
	if dev != nil {
		t.Fatal("device should be nil when remember=false")
	}
	// 失败计数应清零
	if s.loginStates.IsLocked(loginClientKey("127.0.0.1", "test-ua", DeviceAttributes{})) {
		t.Fatal("success should reset failure state")
	}
}

func TestLoginFlow_WrongCaptcha(t *testing.T) {
	s, totp := testLoginServer(t)
	capID, _ := validCaptcha(t, s)

	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		TOTPCode:    validTOTP(t, totp),
		CaptchaID:   capID,
		CaptchaText: "WRONG!",
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("wrong captcha should fail")
	}
	// 失败计数应 +1
	state, _ := s.loginStates.Get(loginClientKey("127.0.0.1", "test-ua", DeviceAttributes{}))
	if state.FailedCount != 1 {
		t.Fatalf("expected FailedCount=1, got %d", state.FailedCount)
	}
}

func TestLoginFlow_WrongToken(t *testing.T) {
	s, totp := testLoginServer(t)
	capID, capText := validCaptcha(t, s)

	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "wrong-token",
		TOTPCode:    validTOTP(t, totp),
		CaptchaID:   capID,
		CaptchaText: capText,
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("wrong token should fail")
	}
}

func TestLoginFlow_WrongTOTP(t *testing.T) {
	s, _ := testLoginServer(t)
	capID, capText := validCaptcha(t, s)

	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		TOTPCode:    "000000", // 错误 code
		CaptchaID:   capID,
		CaptchaText: capText,
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("wrong TOTP should fail")
	}
}

func TestLoginFlow_ThreeFailuresLock(t *testing.T) {
	s, totp := testLoginServer(t)
	capID, capText := validCaptcha(t, s)

	// 3 次错误 captcha
	for i := 0; i < 3; i++ {
		_, _, _ = s.loginFlow(&LoginRequest{
			AdminToken:  "secret-token",
			TOTPCode:    validTOTP(t, totp),
			CaptchaID:   capID,
			CaptchaText: "WRONG!",
		}, "127.0.0.1", "test-ua")
	}

	// 第 4 次即使是正确 creds 也被拒
	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		TOTPCode:    validTOTP(t, totp),
		CaptchaID:   capID,
		CaptchaText: capText,
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("locked state should reject even valid creds")
	}
	if !s.loginStates.IsLocked(loginClientKey("127.0.0.1", "test-ua", DeviceAttributes{})) {
		t.Fatal("should be locked after 3 failures")
	}
}

func TestLoginFlow_DeviceFingerprintSkip(t *testing.T) {
	s, totp := testLoginServer(t)

	// 预存设备 token
	attrs := DeviceAttributes{UA: "test-ua", Lang: "zh-CN", Plat: "MacIntel", Screen: "1920x1080x24", TZ: "Asia/Shanghai"}
	fp := DeviceFingerprint(s.sessionSecret, attrs)
	s.devices.Put(&DeviceToken{
		Fingerprint: fp,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		IP:          "127.0.0.1",
	})

	// 1. 仅凭设备指纹 cookie 不传 TOTP 必须被拒绝（防止偷取 cookie 绕过 30 天 MFA）
	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:        "secret-token",
		TOTPCode:          "",
		DeviceFP:          fp,
		CaptchaText:       "",
		CaptchaID:         "",
		DeviceFingerprint: attrs,
	}, "127.0.0.1", "test-ua")
	if le, ok := err.(*loginErr); !ok || le.Kind != loginErrTOTP {
		t.Fatalf("device-trusted login without TOTP must be rejected with loginErrTOTP, got: %v", err)
	}

	// 2. 用设备指纹登录：跳过 captcha，同时提供有效 adminToken + TOTP → 成功
	s.loginStates.ResetFailed("admin-web@127.0.0.1")
	s.loginStates.ResetFailed(loginClientKey("127.0.0.1", "test-ua", attrs))
	s.loginStates.ResetFailed("admin-web@account")
	sess, _, err := s.loginFlow(&LoginRequest{
		AdminToken:        "secret-token",
		TOTPCode:          validTOTP(t, totp),
		DeviceFP:          fp,
		CaptchaText:       "",
		CaptchaID:         "",
		DeviceFingerprint: attrs,
	}, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("device-skip captcha login with valid TOTP should succeed: %v", err)
	}
	if sess == nil {
		t.Fatal("session should be created")
	}

	// 3. 设备属性与 cookie 指纹不匹配（伪造/跨设备窃取 cookie）→ 要求重新校验图形验证码
	mismatchedAttrs := attrs
	mismatchedAttrs.Screen = "800x600x24"
	_, _, err = s.loginFlow(&LoginRequest{
		AdminToken:        "secret-token",
		TOTPCode:          validTOTP(t, totp),
		DeviceFP:          fp,
		CaptchaText:       "",
		CaptchaID:         "",
		DeviceFingerprint: mismatchedAttrs,
	}, "127.0.0.1", "test-ua")
	if le, ok := err.(*loginErr); !ok || le.Kind != loginErrCaptcha {
		t.Fatalf("mismatched device attributes must not trust cookie and should fail captcha, got: %v", err)
	}

	// 4. 错误的 adminToken 仍然被拒
	_, _, err = s.loginFlow(&LoginRequest{
		AdminToken:        "wrong",
		TOTPCode:          validTOTP(t, totp),
		DeviceFP:          fp,
		DeviceFingerprint: attrs,
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("wrong token should still fail with device-skip")
	}
}

func TestLoginFlow_DevModeSkipAll(t *testing.T) {
	// 显式 devMode=true 且 adminToken 空 → 全过
	s, _ := testLoginServer(t)
	s.adminToken = ""
	s.SetDevMode(true)

	sess, _, err := s.loginFlow(&LoginRequest{
		// 全部空
	}, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("dev mode should skip all: %v", err)
	}
	if sess == nil {
		t.Fatal("session should be created in dev mode")
	}
}

func TestLoginFlow_ProdModeEmptyTokenRejected(t *testing.T) {
	// 生产模式（devMode=false）且 adminToken 空 → 必须 fail-closed 拒绝登录
	s, _ := testLoginServer(t)
	s.adminToken = ""
	s.SetDevMode(false)

	_, _, err := s.loginFlow(&LoginRequest{}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("prod mode with empty adminToken must fail-closed and reject login")
	}
}

func TestLoginFlow_NATIsolationAndIPRotationLockout(t *testing.T) {
	// (A) NAT 隔离：同一 IP 下不同 UA 的两个客户端，客户端 A 失败 2 次，不影响客户端 B；
	// 即使客户端 A 失败 3 次被按 clientKey 锁定，同 IP 的客户端 B 仍能正常登录。
	s, _ := testLoginServer(t)
	s.totpSecret = ""
	for i := 0; i < 3; i++ {
		capID, _ := validCaptcha(t, s)
		_, _, _ = s.loginFlow(&LoginRequest{
			AdminToken:  "secret-token",
			CaptchaID:   capID,
			CaptchaText: "WRONG!",
		}, "10.0.0.1", "ua-attacker")
	}
	// ua-attacker 已被锁定
	capIDAtt, capTextAtt := validCaptcha(t, s)
	_, _, errAtt := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		CaptchaID:   capIDAtt,
		CaptchaText: capTextAtt,
	}, "10.0.0.1", "ua-attacker")
	if le, ok := errAtt.(*loginErr); !ok || le.Kind != loginErrLocked {
		t.Fatalf("ua-attacker should be locked after 3 failures, got: %v", errAtt)
	}

	// 同 IP 的 ua-legit 仍能正常登录（NAT 不互锁）
	capID, capText := validCaptcha(t, s)
	sess, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		CaptchaID:   capID,
		CaptchaText: capText,
	}, "10.0.0.1", "ua-legit")
	if err != nil || sess == nil {
		t.Fatalf("legit user behind same NAT IP should not be locked by another UA's 3 failures: %v", err)
	}

	// (B) 换 IP 绕过防护：攻击者每次换不同 IP 尝试错误 token，累计 3 个不同 IP 后触发账户级全局锁定
	s2, _ := testLoginServer(t)
	s2.totpSecret = ""
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		capID, capText := validCaptcha(t, s2)
		_, _, _ = s2.loginFlow(&LoginRequest{
			AdminToken:  "wrong-token",
			CaptchaID:   capID,
			CaptchaText: capText,
		}, ip, "attacker-ua")
	}
	// 第 4 次换第 4 个新 IP 即使填对凭据也被账户级锁定拦截
	capID4, capText4 := validCaptcha(t, s2)
	_, _, err = s2.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		CaptchaID:   capID4,
		CaptchaText: capText4,
	}, "203.0.113.4", "attacker-ua")
	if le, ok := err.(*loginErr); !ok || le.Kind != loginErrLocked {
		t.Fatalf("IP rotation after 3 failures must trigger account lockout, got: %v", err)
	}
}

func TestLoginFlow_TOTPSecretEmpty_SkipTOTP(t *testing.T) {
	// totpSecret 空 → 跳过 TOTP（仍需 captcha + token）
	s, _ := testLoginServer(t)
	s.totpSecret = ""
	capID, capText := validCaptcha(t, s)

	sess, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		CaptchaID:   capID,
		CaptchaText: capText,
		// TOTPCode 留空
	}, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("empty TOTP secret should skip: %v", err)
	}
	if sess == nil {
		t.Fatal("session should be created")
	}
}

func TestLoginFlow_RememberCreatesDeviceToken(t *testing.T) {
	s, _ := testLoginServer(t)
	capID, capText := validCaptcha(t, s)
	// Generate a valid TOTP for this server
	totpSecret := s.totpSecret
	attrs := DeviceAttributes{UA: "test-ua", Lang: "zh-CN", Plat: "MacIntel", Screen: "1920x1080x24", TZ: "Asia/Shanghai"}

	code := validTOTP(t, totpSecret)
	_, dev, err := s.loginFlow(&LoginRequest{
		AdminToken:        "secret-token",
		TOTPCode:          code,
		CaptchaID:         capID,
		CaptchaText:       capText,
		Remember:          true,
		DeviceFingerprint: attrs,
	}, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if dev == nil {
		t.Fatal("remember=true should create device token")
	}
	if !s.devices.Exists(dev.Fingerprint) {
		t.Fatal("device token should be persisted")
	}
}

func TestLoginFlow_LockedRejectedEvenValid(t *testing.T) {
	s, totp := testLoginServer(t)
	capID, capText := validCaptcha(t, s)

	// 手动锁定
	for i := 0; i < 3; i++ {
		s.loginStates.IncFailed("admin-web@127.0.0.1")
	}
	if !s.loginStates.IsLocked("admin-web@127.0.0.1") {
		t.Fatal("should be locked")
	}

	// 即使 creds 全对，也被锁
	_, _, err := s.loginFlow(&LoginRequest{
		AdminToken:  "secret-token",
		TOTPCode:    validTOTP(t, totp),
		CaptchaID:   capID,
		CaptchaText: capText,
	}, "127.0.0.1", "test-ua")
	if err == nil {
		t.Fatal("locked should reject")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Fatalf("error should mention locked: %v", err)
	}
}
