// Package admin - handler 与最小 API。
package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
)

type sealStatusResp struct {
	Sealed      bool   `json:"sealed"`
	State       string `json:"state"`
	TotalShares int    `json:"total_shares"`
	Threshold   int    `json:"threshold"`
}

func (s *Server) handleSealStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := sealStatusResp{
		Sealed:      s.seal.IsSealed(),
		State:       s.seal.State().String(),
		TotalShares: s.seal.TotalShares(),
		Threshold:   s.seal.Threshold(),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleSeal 触发重新封印（清零 Master Key）。
func (s *Server) handleSeal(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.seal.Seal(req.Context())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"sealed": true})
}

// unsealRequest 是提交单份 Shamir Share 的请求体。
type unsealRequest struct {
	Share []byte `json:"share"`
}

// handleUnseal 提交单份 Shamir Share 推进解封。
// 每次提交一份 Share，达到 threshold 后自动解封。
//
// 安全：Share 明文用后立即 clear+KeepAlive。
func (s *Server) handleUnseal(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	defer func() {
		if bodyBytes != nil {
			clear(bodyBytes)
			runtime.KeepAlive(bodyBytes)
		}
	}()

	var body unsealRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	unsealed, err := s.seal.ProvideShare(body.Share)
	// 立即清理 share 明文。
	clear(body.Share)
	runtime.KeepAlive(body.Share)
	clear(bodyBytes)
	runtime.KeepAlive(bodyBytes)

	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"unsealed": unsealed,
			"error":    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"unsealed": unsealed,
	})
}

// handleIndex 返回 SPA 入口 HTML。
func (s *Server) handleIndex(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path != "/" {
		// 未匹配的路径回退到 index.html，供前端路由使用。
		req.URL.Path = "/"
	}
	data, err := staticFS.ReadFile("web/static/index.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
