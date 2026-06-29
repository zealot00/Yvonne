// Package api - CORS 中间件（可配置 AllowedOrigins）。
package api

import (
	"net/http"
	"strings"
)

// CORSConfig 是 CORS 中间件配置。
type CORSConfig struct {
	AllowedOrigins   []string // 允许的 Origin 列表；"*" 表示任意（Dev 模式）
	AllowedMethods   []string // 默认 GET/POST/PUT/PATCH/DELETE/OPTIONS
	AllowedHeaders   []string // 默认 Authorization/Content-Type/X-Request-ID
	AllowCredentials bool     // 是否允许带 Cookie
	MaxAge           int      // 预检缓存秒数，默认 600
}

// DefaultCORSConfig 返回 Dev 模式默认配置（允许所有 Origin）。
// BUG-3 修复：明确标注仅 Dev 模式安全；Cluster 模式必须显式配置 AllowedOrigins。
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"*"}, // Dev 模式安全；Cluster 模式必须覆盖
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: false, // "*" + AllowCredentials=true 是浏览器非法组合
		MaxAge:           600,
	}
}

// CORSMiddleware 返回 CORS 中间件。
// 处理 OPTIONS 预检请求，其他请求添加 CORS 头后透传。
func CORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			origin := req.Header.Get("Origin")
			if origin != "" && isOriginAllowed(origin, cfg.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Access-Control-Max-Age", "600")
			}

			// OPTIONS 预检直接返回 204。
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// isOriginAllowed 检查 Origin 是否在允许列表中。
func isOriginAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}
