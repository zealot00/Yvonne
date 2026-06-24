// Package api - 公用 HTTP 工具函数。
package api

import (
	"encoding/json"
	"net/http"
)

type envelope struct {
	OK   bool        `json:"ok"`
	Data interface{} `json:"data,omitempty"`
	Err  string      `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, envelope{OK: false, Err: msg})
}

func writeJSONOK(w http.ResponseWriter, payload interface{}) {
	writeJSON(w, http.StatusOK, envelope{OK: true, Data: payload})
}

// requireMethod 检查 HTTP 方法，不匹配返回 405。
func requireMethod(w http.ResponseWriter, req *http.Request, method string) bool {
	if req.Method != method {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}
