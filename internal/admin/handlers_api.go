// Package admin — Web 控制台 REST API handlers。
//
// 提供密钥管理、密码运算、审计查看、MFA/Quorum 管理的 REST API。
// 所有端点需 adminToken 认证。
package admin

import (
	"encoding/json"
	"io"
	"net/http"
)

// adminAPIRequest 是通用请求体。
type adminAPIRequest struct {
	KeyID      string `json:"key_id,omitempty"`
	KeyType    string `json:"key_type,omitempty"`
	Data       []byte `json:"data,omitempty"`
	Plaintext  []byte `json:"plaintext,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Signature  []byte `json:"signature,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Version    int    `json:"version,omitempty"`
}

// handleAPIKeys 列出密钥。
func (s *Server) handleAPIKeys(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	s.handleListKeys(w, req)
}

// handleAPIEncrypt 加密测试。
func (s *Server) handleAPIEncrypt(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"data": map[string]interface{}{"message": "encrypt endpoint — connect to V1Router for actual crypto"},
	})
}

// handleAPIDecrypt 解密测试。
func (s *Server) handleAPIDecrypt(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"data": map[string]interface{}{"message": "decrypt endpoint — connect to V1Router for actual crypto"},
	})
}

// handleAPIAudit 审计查询。
func (s *Server) handleAPIAudit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
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
	json.NewEncoder(w).Encode(data)
}

// readBody 读取请求体。
func readBody(req *http.Request) ([]byte, error) {
	return io.ReadAll(req.Body)
}
