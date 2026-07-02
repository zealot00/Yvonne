// Package api - PKI HTTP handlers（v1.4.x 新增）。
//
// 端点：
//
//	POST /api/v1/pki/ca           创建 CA（自签根证书）
//	POST /api/v1/pki/issue        签发终端证书
//	POST /api/v1/pki/verify       验证证书链
//	GET  /api/v1/pki/cert/{id}    获取证书 PEM
//	POST /api/v1/pki/revoke       吊销证书
//	GET  /api/v1/pki/ca/{id}/crl  获取 CRL
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"

	"yvonne/internal/auth"
)

// === 请求/响应结构 ===

type createCARequest struct {
	KeyID    string `json:"key_id"`
	Algo     string `json:"algo"`      // rsa / ecdsa / sm2
	Subject  string `json:"subject"`   // CN=...
	TTLYears int    `json:"ttl_years"` // 有效期（年），默认 10
}

type issueCertRequest struct {
	CAKeyID      string `json:"ca_key_id"`
	Subject      string `json:"subject"`
	Algo         string `json:"algo"`           // rsa / ecdsa / sm2
	PublicKeyPEM []byte `json:"public_key_pem"` // 请求方公钥 PEM
	CertType     string `json:"cert_type"`      // sign / encrypt / dual
	TTLDays      int    `json:"ttl_days"`       // 有效期（天），默认 90
}

type verifyCertRequest struct {
	CertPEM   []byte `json:"cert_pem"`
	CACertPEM []byte `json:"ca_cert_pem,omitempty"`
}

type revokeCertRequest struct {
	CAKeyID string `json:"ca_key_id"`
	CertID  string `json:"cert_id"`
	Reason  string `json:"reason"`
}

// === Handlers ===

// handlePKICA 处理 POST /api/v1/pki/ca（创建 CA）。
func (r *V1Router) handlePKICA(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body createCARequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.KeyID == "" || body.Algo == "" || body.Subject == "" {
		writeJSONError(w, http.StatusBadRequest, "key_id, algo, subject are required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedKeyID := auth.ScopedKeyID(tenantID, body.KeyID)

	result, err := r.core.CreateCA(req.Context(), scopedKeyID, body.Algo, body.Subject, body.TTLYears, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"key_id":  result.KeyID,
		"cert_id": result.CertID,
		"pem":     result.PEM,
		"serial":  result.Serial,
	})
}

// handlePKIIssue 处理 POST /api/v1/pki/issue（签发证书）。
func (r *V1Router) handlePKIIssue(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body issueCertRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.CAKeyID == "" || body.Subject == "" || body.Algo == "" || len(body.PublicKeyPEM) == 0 {
		writeJSONError(w, http.StatusBadRequest, "ca_key_id, subject, algo, public_key_pem are required")
		return
	}
	if body.CertType == "" {
		body.CertType = "sign"
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedCAKeyID := auth.ScopedKeyID(tenantID, body.CAKeyID)

	result, err := r.core.IssueCert(req.Context(), scopedCAKeyID, body.Subject, body.Algo, body.PublicKeyPEM, body.CertType, body.TTLDays, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"cert_id":   result.CertID,
		"pem":       result.PEM,
		"serial":    result.Serial,
		"not_after": result.NotAfter,
	})
}

// handlePKIVerify 处理 POST /api/v1/pki/verify（验证证书链）。
func (r *V1Router) handlePKIVerify(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body verifyCertRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(body.CertPEM) == 0 {
		writeJSONError(w, http.StatusBadRequest, "cert_pem is required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	result, err := r.core.VerifyCert(req.Context(), body.CertPEM, body.CACertPEM, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"valid":   result.Valid,
		"revoked": result.Revoked,
		"expired": result.Expired,
		"error":   result.Error,
	})
}

// handlePKIGetCert 处理 GET /api/v1/pki/cert/{certID}（获取证书）。
func (r *V1Router) handlePKIGetCert(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// 解析路径：/api/v1/pki/cert/{certID}
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/pki/cert/")
	certID := strings.TrimSpace(path)
	if certID == "" {
		writeJSONError(w, http.StatusBadRequest, "cert_id is required in path")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	meta, err := r.core.GetCert(req.Context(), certID, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"cert_id":        meta.CertID,
		"ca_key_id":      meta.CAKeyID,
		"serial_number":  meta.SerialNumber,
		"subject":        meta.Subject,
		"pem":            meta.PEM,
		"state":          meta.State,
		"cert_type":      meta.CertType,
		"issued_at":      meta.IssuedAt,
		"expires_at":     meta.ExpiresAt,
		"revoked_at":     meta.RevokedAt,
		"revoked_reason": meta.RevokedReason,
	})
}

// handlePKIRevoke 处理 POST /api/v1/pki/revoke（吊销证书）。
func (r *V1Router) handlePKIRevoke(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body failed")
		return
	}
	defer func() {
		clear(bodyBytes)
		runtime.KeepAlive(bodyBytes)
	}()

	var body revokeCertRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.CAKeyID == "" || body.CertID == "" {
		writeJSONError(w, http.StatusBadRequest, "ca_key_id, cert_id are required")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedCAKeyID := auth.ScopedKeyID(tenantID, body.CAKeyID)

	if err := r.core.RevokeCert(req.Context(), scopedCAKeyID, body.CertID, body.Reason, policy); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"revoked": true,
	})
}

// handlePKIGetCRL 处理 GET /api/v1/pki/ca/{caKeyID}/crl（获取 CRL）。
func (r *V1Router) handlePKIGetCRL(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// 解析路径：/api/v1/pki/ca/{caKeyID}/crl
	path := strings.TrimPrefix(req.URL.Path, "/api/v1/pki/ca/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "crl" {
		writeJSONError(w, http.StatusBadRequest, "invalid CRL path, expected /api/v1/pki/ca/{caKeyID}/crl")
		return
	}
	caKeyID := strings.TrimSpace(parts[0])
	if caKeyID == "" {
		writeJSONError(w, http.StatusBadRequest, "ca_key_id is required in path")
		return
	}

	policy := auth.PolicyFromContext(req.Context())
	tenantID := auth.TenantFromContext(req.Context())
	scopedCAKeyID := auth.ScopedKeyID(tenantID, caKeyID)

	crlDER, err := r.core.GetCRL(req.Context(), scopedCAKeyID, policy)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSONOK(w, map[string]interface{}{
		"crl": crlDER,
	})
}
