// Package admin - Device Token 单元测试（v1.4.2）。
//
// 设备指纹 HMAC：HMAC-SHA-256(sessionSecret, ua|lang|plat|screen|tz)
// Salt 必须保密（防止伪造）。
//
// 验证：
//  1. 同样输入 + 同样 salt → 同样 fingerprint（确定性）
//  2. 任何字段差异 → fingerprint 完全不同
//  3. 同样输入 + 不同 salt → fingerprint 完全不同（salt 防伪）
//  4. 过期不可用
//  5. Save 一次性消费标记
package admin

import (
	"testing"
	"time"
)

func TestDeviceFingerprint_Deterministic(t *testing.T) {
	salt := []byte("test-salt-32-bytes-minimum-padding!")
	fp1 := DeviceFingerprint(salt, DeviceAttributes{
		UA:     "Mozilla/5.0",
		Lang:   "zh-CN",
		Plat:   "MacIntel",
		Screen: "1920x1080x24",
		TZ:     "Asia/Shanghai",
	})
	fp2 := DeviceFingerprint(salt, DeviceAttributes{
		UA:     "Mozilla/5.0",
		Lang:   "zh-CN",
		Plat:   "MacIntel",
		Screen: "1920x1080x24",
		TZ:     "Asia/Shanghai",
	})
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %s vs %s", fp1, fp2)
	}
	if len(fp1) != 64 { // 32B hex = 64 chars
		t.Fatalf("fingerprint length expected 64, got %d", len(fp1))
	}
}

func TestDeviceFingerprint_DifferentInput(t *testing.T) {
	salt := []byte("test-salt-32-bytes-minimum-padding!")
	base := DeviceAttributes{UA: "Mozilla/5.0", Lang: "zh-CN", Plat: "MacIntel", Screen: "1920x1080x24", TZ: "Asia/Shanghai"}
	baseFP := DeviceFingerprint(salt, base)

	cases := []struct {
		name string
		mut  func(a *DeviceAttributes)
	}{
		{"ua", func(a *DeviceAttributes) { a.UA = "Mozilla/6.0" }},
		{"lang", func(a *DeviceAttributes) { a.Lang = "en-US" }},
		{"plat", func(a *DeviceAttributes) { a.Plat = "Win32" }},
		{"screen", func(a *DeviceAttributes) { a.Screen = "1024x768x24" }},
		{"tz", func(a *DeviceAttributes) { a.TZ = "UTC" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modified := base
			tc.mut(&modified)
			fp := DeviceFingerprint(salt, modified)
			if fp == baseFP {
				t.Fatalf("fingerprint unchanged after mutating %s", tc.name)
			}
		})
	}
}

func TestDeviceFingerprint_DifferentSalt(t *testing.T) {
	a := DeviceAttributes{UA: "Mozilla/5.0", Lang: "zh-CN", Plat: "MacIntel", Screen: "1920x1080x24", TZ: "Asia/Shanghai"}
	salt1 := []byte("salt-one-32-bytes-padding-padding!")
	salt2 := []byte("salt-two-32-bytes-padding-padding!")
	fp1 := DeviceFingerprint(salt1, a)
	fp2 := DeviceFingerprint(salt2, a)
	if fp1 == fp2 {
		t.Fatal("same input + different salt should yield different fingerprint")
	}
}

func TestDeviceToken_ExpiresAt(t *testing.T) {
	tok := &DeviceToken{
		Fingerprint: "abc123",
		CreatedAt:   time.Now().Add(-31 * 24 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // 31 天前创建，已过期
		IP:          "127.0.0.1",
	}
	if !tok.IsExpired(time.Now()) {
		t.Fatal("31-day-old token should be expired")
	}

	tok2 := &DeviceToken{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if tok2.IsExpired(time.Now()) {
		t.Fatal("fresh token should not be expired")
	}
}

func TestDeviceStore_PutGetLookup(t *testing.T) {
	store := NewMemoryDeviceStore()
	tok := &DeviceToken{
		Fingerprint: "fp-abc",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
		IP:          "127.0.0.1",
	}
	store.Put(tok)

	got, ok := store.Get("fp-abc")
	if !ok {
		t.Fatal("Get should return token")
	}
	if got.IP != "127.0.0.1" {
		t.Fatalf("IP mismatch: %q", got.IP)
	}
	if !store.Exists("fp-abc") {
		t.Fatal("Exists should be true")
	}
	if store.Exists("fp-none") {
		t.Fatal("Exists should be false for unknown fp")
	}
}

func TestDeviceStore_GetExpiredReturnsFalse(t *testing.T) {
	store := NewMemoryDeviceStore()
	tok := &DeviceToken{
		Fingerprint: "fp-old",
		CreatedAt:   time.Now().Add(-31 * 24 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	store.Put(tok)
	if _, ok := store.Get("fp-old"); ok {
		t.Fatal("expired token should not be returned")
	}
	if store.Exists("fp-old") {
		t.Fatal("Exists should be false for expired token")
	}
}

func TestDeviceStore_Delete(t *testing.T) {
	store := NewMemoryDeviceStore()
	store.Put(&DeviceToken{Fingerprint: "fp-x", ExpiresAt: time.Now().Add(time.Hour)})
	store.Delete("fp-x")
	if store.Exists("fp-x") {
		t.Fatal("token should be deleted")
	}
}

func TestDeviceStore_Reap(t *testing.T) {
	store := NewMemoryDeviceStore()
	store.Put(&DeviceToken{Fingerprint: "fresh", ExpiresAt: time.Now().Add(time.Hour)})
	store.Put(&DeviceToken{Fingerprint: "old", ExpiresAt: time.Now().Add(-time.Hour)})

	n := store.Reap(time.Now())
	if n != 1 {
		t.Fatalf("expected reap 1, got %d", n)
	}
	if !store.Exists("fresh") {
		t.Fatal("fresh token should survive")
	}
	if store.Exists("old") {
		t.Fatal("old token should be reaped")
	}
}
