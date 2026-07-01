// Package auth - TOTP（基于时间的一次性密码，RFC 6238）。
//
// 兼容 Google Authenticator / Microsoft Authenticator 等 TOTP 应用。
//
// 安全红线：
//   - TOTP secret 用 KEK 加密存储，与密钥同等保护。
//   - 验证窗口默认 ±1（允许 30s 时钟漂移）。
//   - 验证后记录已使用的 code 防重放（30s 窗口内有效）。
package auth

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- SHA-1 是 RFC 6238 TOTP 标准算法，非密码存储用途
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"yvonne/internal/memguard"
)

// TOTP 配置常量。
const (
	totpDigits    = 6  // 6 位数字（Google Authenticator 标准）
	totpPeriod    = 30 // 30 秒窗口
	totpSkew      = 1  // 允许 ±1 窗口（±30s 时钟漂移）
	totpSecretLen = 20 // 160 位 secret（RFC 4226 推荐）
)

// ErrTOTPInvalid 表示 TOTP 验证失败。
var ErrTOTPInvalid = errors.New("auth: invalid TOTP code")

// ErrTOTPAlreadyUsed 表示 TOTP code 已被使用（防重放）。
var ErrTOTPAlreadyUsed = errors.New("auth: TOTP code already used")

// GenerateTOTPSecret 生成随机 TOTP secret（20 字节，base32 编码）。
func GenerateTOTPSecret() (string, error) {
	secret, err := memguard.GenerateSecureRandom(totpSecretLen)
	if err != nil {
		return "", fmt.Errorf("auth: generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateTOTP 根据secret + 时间生成 TOTP code。
// t 为 nil 时用 time.Now()。
func GenerateTOTP(secret string, t time.Time) (string, error) {
	if t.IsZero() {
		t = time.Now()
	}

	hmacKey, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("auth: decode TOTP secret: %w", err)
	}

	// T = floor((unix_time - T0) / period)，T0 = 0。
	// #nosec G115 -- Unix 时间戳转 uint64 不会溢出（2^63 秒 = 2920 亿年）。
	counter := uint64(t.Unix()) / uint64(totpPeriod)
	return hotp(hmacKey, counter), nil
}

// ValidateTOTP 验证 TOTP code，允许 ±1 窗口（±30s 时钟漂移）。
// markUsed 函数用于防重放（原子标记已使用，可选，nil 跳过）。
//
// Bug-1 修复（TOCTOU 并发漏洞）:
//   - 旧实现 usedCodeCheck 只读检查与外部 markUsed 写入分离，并发下可双写。
//   - 新实现改用 markUsed func(time.Time, string) error 原子回调:
//     验证匹配后直接调 markUsed 尝试落库，依赖 DB 唯一约束保证只有一个请求成功。
//   - 向后兼容: 旧 usedCodeCheck 签名通过 ValidateTOTPLegacy 支持。
//
// Bug-8 修复（uint64 溢出陷阱）:
//   - 旧实现 uint64(skew) 当 skew=-1 时环绕为 18446744073709551615。
//   - 新实现统一用 int64 计算 counter，最后转 uint64。
func ValidateTOTP(secret, code string, markUsed func(time.Time, string) error) error {
	if len(code) != totpDigits {
		return ErrTOTPInvalid
	}

	now := time.Now()
	hmacKey, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return fmt.Errorf("auth: decode TOTP secret: %w", err)
	}

	// 检查 current + skew 窗口。
	// Bug-8 修复：用 int64 计算，避免 uint64(skew) 溢出环绕。
	nowUnix := int64(now.Unix())
	baseCounter := nowUnix / int64(totpPeriod)
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		counter := uint64(baseCounter + int64(skew))
		expected := hotp(hmacKey, counter)

		if subtleEqualString(expected, code) {
			// Bug-1 修复：原子标记已使用，依赖 DB 唯一约束防并发重放。
			if markUsed != nil {
				windowStart := now.Add(time.Duration(skew*totpPeriod) * time.Second)
				if err := markUsed(windowStart, code); err != nil {
					return ErrTOTPAlreadyUsed
				}
			}
			return nil
		}
	}

	return ErrTOTPInvalid
}

// ValidateTOTPLegacy 旧版兼容接口（usedCodeCheck 只读检查）。
//
// 已废弃: 仅用于向后兼容，新代码应使用 ValidateTOTP + markUsed 原子回调。
// 此接口存在 TOCTOU 并发风险（Bug-1），仅在不具备原子 markUsed 的场景使用。
func ValidateTOTPLegacy(secret, code string, usedCodeCheck func(time.Time, string) bool) error {
	if len(code) != totpDigits {
		return ErrTOTPInvalid
	}

	now := time.Now()
	hmacKey, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return fmt.Errorf("auth: decode TOTP secret: %w", err)
	}

	nowUnix := int64(now.Unix())
	baseCounter := nowUnix / int64(totpPeriod)
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		counter := uint64(baseCounter + int64(skew))
		expected := hotp(hmacKey, counter)

		if subtleEqualString(expected, code) {
			if usedCodeCheck != nil {
				windowStart := now.Add(time.Duration(skew*totpPeriod) * time.Second)
				if usedCodeCheck(windowStart, code) {
					return ErrTOTPAlreadyUsed
				}
			}
			return nil
		}
	}

	return ErrTOTPInvalid
}

// BuildTOTPURI 构建 otpauth:// URI（Google Authenticator 兼容）。
// issuer: 发行方（如 "Yvonne KMS"）
// account: 账户标识（如 roleID）
// secret: base32 编码的 TOTP secret
func BuildTOTPURI(issuer, account, secret string) string {
	// otpauth://totp/Yvonne%20KMS:admin?secret=JBSWY3DPEHPK3PXP&issuer=Yvonne%20KMS
	label := fmt.Sprintf("%s:%s", urlEscape(issuer), urlEscape(account))
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		label,
		urlEscape(secret),
		urlEscape(issuer),
		totpDigits,
		totpPeriod,
	)
}

// hotp 实现 HOTP（RFC 4226）。
// hmacKey: HMAC 密钥（base32 解码后的临时变量，非长期密钥材料）；counter: 计数器。
func hotp(hmacKey []byte, counter uint64) string {
	// 1. counter 转 8 字节大端。
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	// 2. HMAC-SHA1(hmacKey, counter)。
	h := hmac.New(sha1.New, hmacKey)
	h.Write(buf[:])
	hash := h.Sum(nil)

	// 3. Dynamic truncation。
	offset := int(hash[len(hash)-1] & 0x0f)
	binary := (uint32(hash[offset])&0x7f)<<24 |
		uint32(hash[offset+1])<<16 |
		uint32(hash[offset+2])<<8 |
		uint32(hash[offset+3])

	// 4. 取后 6 位数字。
	code := binary % 1000000
	return fmt.Sprintf("%06d", code)
}

// subtleEqualString 常量时间字符串比较（防计时侧信道）。
func subtleEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// urlEscape 简单 URL 编码（避免 import net/url 的循环依赖）。
func urlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '~':
			b.WriteRune(r)
		case r == ' ':
			b.WriteString("%20")
		case r == ':':
			b.WriteString("%3A")
		default:
			b.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return b.String()
}
