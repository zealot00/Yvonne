// Package api - 公用 HTTP 工具函数。
package api

import (
	"encoding/json"
	"net/http"
	"strings"
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

// writeAPIError 将 service 层 error 映射为 HTTP 状态码。
func writeAPIError(w http.ResponseWriter, err error) {
	msg := err.Error()
	code := http.StatusInternalServerError
	if strings.Contains(msg, "not found") {
		code = http.StatusNotFound
	} else if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "denied") || strings.Contains(msg, "cannot access") {
		code = http.StatusForbidden
	} else if strings.Contains(msg, "sealed") {
		code = http.StatusServiceUnavailable
	} else if strings.Contains(msg, "requires asymmetric") || strings.Contains(msg, "requires symmetric") || strings.Contains(msg, "no public key") {
		code = http.StatusBadRequest
	}
	writeJSONError(w, code, msg)
}
