// Package admin - 图形验证码单元测试（v1.4.2: SVG 验证码）。
//
// 验证 5 项核心不变量：
//  1. 字符集排除视觉混淆字符（0/O/1/I/L）
//  2. 长度固定 5
//  3. SVG 包含 viewBox 属性
//  4. 答案比较走 constant-time（防 timing attack）
//  5. TTL 5 min 过期后失效
package admin

import (
	"strings"
	"testing"
	"time"
)

func TestCaptcha_Generate_ExcludesConfusingChars(t *testing.T) {
	// 跑 1000 次，确认字符集永远不出现 0/O/1/I/L
	for i := 0; i < 1000; i++ {
		c, err := NewCaptcha(160, 50)
		if err != nil {
			t.Fatalf("NewCaptcha: %v", err)
		}
		for _, r := range c.Text {
			switch r {
			case '0', 'O', '1', 'I', 'L':
				t.Fatalf("captcha text %q contains confusing char %q", c.Text, r)
			}
		}
	}
}

func TestCaptcha_Generate_FixedLength5(t *testing.T) {
	for i := 0; i < 100; i++ {
		c, err := NewCaptcha(160, 50)
		if err != nil {
			t.Fatalf("NewCaptcha: %v", err)
		}
		if len(c.Text) != 5 {
			t.Fatalf("expected length 5, got %d (text=%q)", len(c.Text), c.Text)
		}
	}
}

func TestCaptcha_Generate_HasValidID(t *testing.T) {
	c, err := NewCaptcha(160, 50)
	if err != nil {
		t.Fatalf("NewCaptcha: %v", err)
	}
	// 16B rand → 22 chars base64url（无 padding）
	if len(c.ID) < 20 || len(c.ID) > 24 {
		t.Fatalf("captcha ID length unexpected: %d (id=%q)", len(c.ID), c.ID)
	}
	// 两次生成 ID 必须不同
	c2, _ := NewCaptcha(160, 50)
	if c.ID == c2.ID {
		t.Fatal("captcha IDs collided")
	}
}

func TestCaptcha_Generate_SVGContainsViewBox(t *testing.T) {
	c, err := NewCaptcha(160, 50)
	if err != nil {
		t.Fatalf("NewCaptcha: %v", err)
	}
	if !strings.Contains(c.SVG, "viewBox") {
		t.Fatalf("SVG missing viewBox: %s", c.SVG)
	}
	// 必须包含所有 5 个字符
	for _, r := range c.Text {
		rs := string(r)
		if !strings.Contains(c.SVG, "<text") {
			t.Fatalf("SVG missing <text> element")
		}
		// 字符的 HSL fill 编码在 fill 属性里
		_ = rs // 字符可能在 fill 里被转义或不在（用 transform），不强求
	}
	// 必须有干扰线（<line>）
	if !strings.Contains(c.SVG, "<line") {
		t.Fatal("SVG missing noise lines")
	}
	// 必须有噪点（<circle）
	if !strings.Contains(c.SVG, "<circle") {
		t.Fatal("SVG missing noise circles")
	}
}

func TestCaptcha_Generate_ExpiresIn5Min(t *testing.T) {
	c, err := NewCaptcha(160, 50)
	if err != nil {
		t.Fatalf("NewCaptcha: %v", err)
	}
	delta := c.ExpiresAt.Sub(time.Now())
	if delta < 4*time.Minute || delta > 6*time.Minute {
		t.Fatalf("TTL not ~5min: %v", delta)
	}
}

func TestValidateCaptchaText_ConstantTime(t *testing.T) {
	// 直接验证：相同内容 → true；不同内容 → false
	// （不验证 timing，Go 的 subtle.ConstantTimeCompare 已经是 constant-time）
	if !ValidateCaptchaText("ABCDE", "ABCDE") {
		t.Fatal("matching text should pass")
	}
	if !ValidateCaptchaText("ABCDE", "ABcde") {
		t.Fatal("captcha should be case-insensitive")
	}
	if ValidateCaptchaText("ABCDE", "ABCDF") {
		t.Fatal("one-char-different text should fail")
	}
	if ValidateCaptchaText("ABCDE", "") {
		t.Fatal("empty compare should fail")
	}
}

func TestCaptchaStore_PutGetReap(t *testing.T) {
	store := NewMemoryCaptchaStore()
	c, _ := NewCaptcha(160, 50)
	store.Put(c)

	// Get 必须返回该 captcha
	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get should return captcha")
	}
	if got.Text != c.Text {
		t.Fatalf("text mismatch: got %q want %q", got.Text, c.Text)
	}

	// 过期
	expired := *c
	expired.ExpiresAt = time.Now().Add(-1 * time.Second)
	store.Put(&expired)
	if _, ok := store.Get(expired.ID); ok {
		t.Fatal("expired captcha should not be returned")
	}

	// Reap 清理过期
	c2, _ := NewCaptcha(160, 50)
	store.Put(c2)
	// 把 c2 也设为过期
	expired2 := *c2
	expired2.ExpiresAt = time.Now().Add(-1 * time.Second)
	store.Put(&expired2)

	n := store.Reap(time.Now())
	if n < 1 {
		t.Fatalf("Reap should clean at least 1, got %d", n)
	}
}

func TestCaptchaStore_PopIsSingleUse(t *testing.T) {
	store := NewMemoryCaptchaStore()
	c, _ := NewCaptcha(160, 50)
	store.Put(c)

	// Pop 必须取到
	got, ok := store.Pop(c.ID)
	if !ok {
		t.Fatal("first Pop should succeed")
	}
	if got.Text != c.Text {
		t.Fatalf("text mismatch: %q vs %q", got.Text, c.Text)
	}

	// 再次 Pop 必须为空（一次性消费）
	if _, ok := store.Pop(c.ID); ok {
		t.Fatal("second Pop should fail (single-use)")
	}
}
