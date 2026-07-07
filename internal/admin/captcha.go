// Package admin - 图形验证码（v1.4.2）。
//
// 纯手写 SVG 验证码，零图像依赖：
//   - 字符集 [A-HJ-NP-Z2-9]（32 字符，排除 0/O/1/I/L 视觉混淆）
//   - 长度 5
//   - 160×50 px，字符旋转 ±25°，干扰线 4 条，噪点 35 个
//   - 有效期 5 分钟，一次性消费
//
// 安全注意：
//   - 答案用 crypto/subtle.ConstantTimeCompare 比较
//   - ID 用 crypto/rand 16 字节
//   - 字符用 crypto/rand 选择（不暴露状态）
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// captchaAlphabet 排除视觉混淆字符：0/O/1/I/L
// 注意：不能含 I（I 和 1 像）、L（L 和 1 像）、O（O 和 0 像）
const captchaAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	captchaLength    = 5
	captchaWidth     = 160
	captchaHeight    = 50
	captchaTTL       = 5 * time.Minute
	captchaNoiseDot  = 35
	captchaNoiseLine = 4
)

// CaptchaChallenge 一次性验证码。
type CaptchaChallenge struct {
	ID        string // 16B rand → base64url
	Text      string // 5 chars from captchaAlphabet
	SVG       string // 完整 <svg> 字符串
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewCaptcha 生成一个新的验证码（字符 + SVG）。
func NewCaptcha(width, height int) (*CaptchaChallenge, error) {
	text, err := randomText(captchaLength, captchaAlphabet)
	if err != nil {
		return nil, fmt.Errorf("random text: %w", err)
	}
	id, err := randomID(16)
	if err != nil {
		return nil, fmt.Errorf("random id: %w", err)
	}
	now := time.Now()
	c := &CaptchaChallenge{
		ID:        id,
		Text:      text,
		ExpiresAt: now.Add(captchaTTL),
		CreatedAt: now,
	}
	c.SVG = renderSVG(text, width, height)
	return c, nil
}

// ValidateCaptchaText constant-time 答案比较。
// 大小写不敏感（运维友好）。
func ValidateCaptchaText(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	// 大小写不敏感：双方都大写后比较
	au := strings.ToUpper(a)
	bu := strings.ToUpper(b)
	return subtle.ConstantTimeCompare([]byte(au), []byte(bu)) == 1
}

// randomText 从 alphabet 选 n 个字符。
func randomText(n int, alphabet string) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

// randomID 生成 n 字节随机 ID → base64url（无 padding）。
func randomID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// renderSVG 渲染字符 + 干扰线 + 噪点到 SVG 字符串。
// 字符位置和颜色用 math/rand + time 种子（不需密码学强度）。
func renderSVG(text string, width, height int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`,
		width, height, width, height)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#fafafa"/>`)

	// 干扰线（4 条）
	for i := 0; i < captchaNoiseLine; i++ {
		x1 := pseudoRand(0, width)
		y1 := pseudoRand(0, height)
		x2 := pseudoRand(0, width)
		y2 := pseudoRand(0, height)
		stroke := fmt.Sprintf("#888%d", 40+pseudoRand(0, 40))
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5" opacity="0.6"/>`,
			x1, y1, x2, y2, stroke)
	}

	// 噪点（35 个 circle r=1）
	for i := 0; i < captchaNoiseDot; i++ {
		cx := pseudoRand(0, width)
		cy := pseudoRand(0, height)
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="1" fill="#aaa"/>`,
			cx, cy)
	}

	// 字符（旋转 + 抖动 + 随机色相）
	charW := width / (captchaLength + 1)
	for i, r := range text {
		x := charW*(i+1) + pseudoRand(-8, 8)
		y := height/2 + pseudoRand(-5, 5)
		rot := pseudoRand(-25, 25)
		hue := pseudoRand(0, 360)
		fill := fmt.Sprintf("hsl(%d, 60%%, 35%%)", hue)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-family="monospace" font-size="32" font-weight="bold" fill="%s" transform="rotate(%d %d %d)">%c</text>`,
			x, y, fill, rot, x, y, r)
	}

	b.WriteString(`</svg>`)
	return b.String()
}

// pseudoRand 返回 [min, max) 之间的伪随机整数。
// 不需要密码学强度（验证码不需不可预测，只需要不重复到 OCR 容易）。
func pseudoRand(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

// =====================================================================
// CaptchaStore：内存实现（dev 模式 + cluster 单实例）
// =====================================================================

// CaptchaStore 验证码存储接口。
type CaptchaStore interface {
	Put(c *CaptchaChallenge)
	Get(id string) (*CaptchaChallenge, bool)
	Pop(id string) (*CaptchaChallenge, bool) // 一次性消费
	Reap(now time.Time) int
}

// MemoryCaptchaStore in-memory 验证码存储（dev 模式 / cluster 单实例够用）。
type MemoryCaptchaStore struct {
	mu   sync.RWMutex
	data map[string]*CaptchaChallenge
}

// NewMemoryCaptchaStore 创建一个空的内存验证码存储。
func NewMemoryCaptchaStore() *MemoryCaptchaStore {
	return &MemoryCaptchaStore{data: make(map[string]*CaptchaChallenge)}
}

// Put 写入验证码。
func (s *MemoryCaptchaStore) Put(c *CaptchaChallenge) {
	s.mu.Lock()
	s.data[c.ID] = c
	s.mu.Unlock()
}

// Get 非破坏性读取（已过期的返回 false）。
func (s *MemoryCaptchaStore) Get(id string) (*CaptchaChallenge, bool) {
	s.mu.RLock()
	c, ok := s.data[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(c.ExpiresAt) {
		s.mu.Lock()
		delete(s.data, id)
		s.mu.Unlock()
		return nil, false
	}
	return c, true
}

// Pop 一次性取出（消费后删除）。
func (s *MemoryCaptchaStore) Pop(id string) (*CaptchaChallenge, bool) {
	s.mu.Lock()
	c, ok := s.data[id]
	if ok {
		delete(s.data, id)
	}
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, false
	}
	return c, true
}

// Reap 删除所有过期项，返回清理数量。
func (s *MemoryCaptchaStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.data {
		if now.After(c.ExpiresAt) {
			delete(s.data, id)
			n++
		}
	}
	return n
}
