// Package yvonne - PKI 请求/响应类型（v1.4.0）。
//
// 与 internal/api/handler_pki.go 的 JSON 字段严格一致。
package yvonne

// === PKI 请求类型 ===

// CreateCARequest 创建 CA 请求。
type CreateCARequest struct {
	KeyID    string `json:"key_id"`
	Algo     string `json:"algo"`      // "rsa" / "ecdsa" / "sm2"
	Subject  string `json:"subject"`   // "CN=Test CA"
	TTLYears int    `json:"ttl_years"` // 有效期（年），0=默认 10
}

// IssueCertRequest 签发终端证书请求。
type IssueCertRequest struct {
	CAKeyID      string `json:"ca_key_id"`
	Subject      string `json:"subject"`
	Algo         string `json:"algo"`           // "rsa" / "ecdsa" / "sm2"
	PublicKeyPEM []byte `json:"public_key_pem"` // 请求方公钥 PEM
	CertType     string `json:"cert_type"`      // "sign" / "encrypt" / "dual"，默认 "sign"
	TTLDays      int    `json:"ttl_days"`       // 有效期（天），0=默认 90
}

// VerifyCertRequest 验证证书链请求。
type VerifyCertRequest struct {
	CertPEM   []byte `json:"cert_pem"`
	CACertPEM []byte `json:"ca_cert_pem,omitempty"`
}

// RevokeCertRequest 吊销证书请求。
type RevokeCertRequest struct {
	CAKeyID string `json:"ca_key_id"`
	CertID  string `json:"cert_id"`
	Reason  string `json:"reason"`
}

// === PKI 响应类型 ===

// CreateCAResponse 创建 CA 响应。
type CreateCAResponse struct {
	KeyID  string `json:"key_id"`
	CertID string `json:"cert_id"`
	PEM    []byte `json:"pem"`
	Serial string `json:"serial"`
}

// IssueCertResponse 签发证书响应。
type IssueCertResponse struct {
	CertID   string `json:"cert_id"`
	PEM      []byte `json:"pem"`
	Serial   string `json:"serial"`
	NotAfter string `json:"not_after"`
}

// VerifyCertResponse 验证证书链响应。
type VerifyCertResponse struct {
	Valid   bool   `json:"valid"`
	Revoked bool   `json:"revoked"`
	Expired bool   `json:"expired"`
	Error   string `json:"error"`
}

// GetCertResponse 获取证书响应。
type GetCertResponse struct {
	CertID        string `json:"cert_id"`
	CAKeyID       string `json:"ca_key_id"`
	SerialNumber  string `json:"serial_number"`
	Subject       string `json:"subject"`
	PEM           []byte `json:"pem"`
	State         string `json:"state"`
	CertType      string `json:"cert_type"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
	RevokedReason string `json:"revoked_reason,omitempty"`
}

// RevokeCertResponse 吊销证书响应。
type RevokeCertResponse struct {
	Revoked bool `json:"revoked"`
}

// GetCRLResponse 获取 CRL 响应。
type GetCRLResponse struct {
	CRL []byte `json:"crl"`
}
