// Package admin — Web 控制台 REST API handlers。
package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// handleAPIKeys 列出密钥。
func (s *Server) handleAPIKeys(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	s.handleListKeys(w, req)
}

// handleAPIEncrypt 加密测试 — 代理转发到 V1Router。
func (s *Server) handleAPIEncrypt(w http.ResponseWriter, req *http.Request) {
	s.proxyAPI(w, req, "/api/v1/encrypt")
}

// handleAPIDecrypt 解密测试 — 代理转发到 V1Router。
func (s *Server) handleAPIDecrypt(w http.ResponseWriter, req *http.Request) {
	s.proxyAPI(w, req, "/api/v1/decrypt")
}

// proxyAPI 代理 API 请求到 V1Router。
func (s *Server) proxyAPI(w http.ResponseWriter, req *http.Request, targetPath string) {
	if s.apiHandler == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "API handler not configured"})
		return
	}

	// 保存原始值，defer 恢复。
	origPath := req.URL.Path
	origMethod := req.Method
	defer func() {
		req.URL.Path = origPath
		req.Method = origMethod
	}()

	// 设置为目标路径 + POST method。
	req.URL.Path = targetPath
	req.Method = http.MethodPost

	// 重新读取 body（因为 body 可能已被读取过）。
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	s.apiHandler.ServeHTTP(w, req)
}

// handleAPIAudit 审计查询。
func (s *Server) handleAPIAudit(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"data": map[string]interface{}{"entries": []interface{}{}, "count": 0},
	})
}

// handleAPIDashboard 仪表盘数据。
func (s *Server) handleAPIDashboard(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	keyCount := 0
	if s.manager != nil && !s.seal.IsSealed() {
		if keys, err := s.manager.ListKeyIDs(req.Context()); err == nil {
			keyCount = len(keys)
		}
	}

	writeJSON(w, map[string]interface{}{
		"ok": true,
		"data": map[string]interface{}{
			"key_count": keyCount,
			"sealed":    s.seal.IsSealed(),
			"state":     s.seal.State().String(),
		},
	})
}

// writeJSON 写 JSON 响应。
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data) // #nosec G104
}
