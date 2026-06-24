// Package config - Duration：支持 "30s" / "5m" / "2h" 字符串与纳秒整数两种 JSON 形态。
package config

import (
	"encoding/json"
	"time"
)

// Duration 是 time.Duration 的包装，使其支持 JSON 字符串解析。
// 兼容两种形态：
//   - 字符串："30s", "5m", "2h"（推荐，可读性好）
//   - 数字：纳秒（time.Duration 默认 int64 表示）
type Duration time.Duration

// UnmarshalJSON 实现 json.Unmarshaler。
func (d *Duration) UnmarshalJSON(b []byte) error {
	// 优先尝试字符串。
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		s := string(b[1 : len(b)-1])
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	// 否则按数字（纳秒）处理。
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON 实现 json.Marshaler，输出字符串形态。
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Std 返回标准库 time.Duration。
func (d Duration) Std() time.Duration { return time.Duration(d) }
