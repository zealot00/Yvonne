package yvonne

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// pkiMockServer 返回 PKI mock server。
// 注意: []byte 字段在 JSON 中自动 base64 编码，mock 需返回 base64 字符串。
func pkiMockServer(t *testing.T) *httptest.Server {
	pemCA := []byte("-----BEGIN CERTIFICATE-----\nMOCKCA\n-----END CERTIFICATE-----\n")
	pemCert := []byte("-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----\n")
	crlDER := []byte("MOCK-CRL-DER-BYTES")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/pki/ca":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"key_id":  "test-ca",
					"cert_id": "cert-abc123",
					"pem":     base64.StdEncoding.EncodeToString(pemCA),
					"serial":  "123456",
				},
			})
		case "/api/v1/pki/issue":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"cert_id":   "cert-def456",
					"pem":       base64.StdEncoding.EncodeToString(pemCert),
					"serial":    "789012",
					"not_after": "2027-01-01T00:00:00Z",
				},
			})
		case "/api/v1/pki/verify":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"valid":   true,
					"revoked": false,
					"expired": false,
					"error":   "",
				},
			})
		case "/api/v1/pki/cert/cert-abc123":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"cert_id":       "cert-abc123",
					"ca_key_id":     "test-ca",
					"serial_number": "123456",
					"subject":       "CN=Test CA",
					"pem":           base64.StdEncoding.EncodeToString(pemCA),
					"state":         "Active",
					"cert_type":     "ca",
					"issued_at":     "2026-07-01T00:00:00Z",
					"expires_at":    "2036-07-01T00:00:00Z",
				},
			})
		case "/api/v1/pki/revoke":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"data": map[string]interface{}{"revoked": true},
			})
		case "/api/v1/pki/ca/test-ca/crl":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"crl": base64.StdEncoding.EncodeToString(crlDER),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "not found"})
		}
	}))
}

func TestClient_CreateCA(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	resp, err := c.CreateCA(context.Background(), &CreateCARequest{
		KeyID:    "test-ca",
		Algo:     "rsa",
		Subject:  "CN=Test CA",
		TTLYears: 10,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	if resp.CertID != "cert-abc123" {
		t.Fatalf("CertID = %q", resp.CertID)
	}
	if resp.KeyID != "test-ca" {
		t.Fatalf("KeyID = %q", resp.KeyID)
	}
	t.Logf("✅ CreateCA: cert_id=%s", resp.CertID)
}

func TestClient_IssueCert(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	resp, err := c.IssueCert(context.Background(), &IssueCertRequest{
		CAKeyID:      "test-ca",
		Subject:      "CN=Server",
		Algo:         "rsa",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n"),
		CertType:     "sign",
		TTLDays:      90,
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if resp.CertID != "cert-def456" {
		t.Fatalf("CertID = %q", resp.CertID)
	}
	t.Logf("✅ IssueCert: cert_id=%s", resp.CertID)
}

func TestClient_VerifyCert(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	resp, err := c.VerifyCert(context.Background(), &VerifyCertRequest{
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"),
	})
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected valid=true")
	}
	if resp.Revoked || resp.Expired {
		t.Fatal("expected revoked=false, expired=false")
	}
	t.Log("✅ VerifyCert: valid=true")
}

func TestClient_GetCert(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	resp, err := c.GetCert(context.Background(), "cert-abc123")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if resp.CertID != "cert-abc123" {
		t.Fatalf("CertID = %q", resp.CertID)
	}
	if resp.State != "Active" {
		t.Fatalf("State = %q", resp.State)
	}
	t.Logf("✅ GetCert: cert_id=%s state=%s", resp.CertID, resp.State)
}

func TestClient_RevokeCert(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	err := c.RevokeCert(context.Background(), &RevokeCertRequest{
		CAKeyID: "test-ca",
		CertID:  "cert-abc123",
		Reason:  "keyCompromise",
	})
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	t.Log("✅ RevokeCert: success")
}

func TestClient_GetCRL(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	crl, err := c.GetCRL(context.Background(), "test-ca")
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	if len(crl) == 0 {
		t.Fatal("CRL should not be empty")
	}
	t.Logf("✅ GetCRL: %d bytes", len(crl))
}

func TestClient_PKI_Error(t *testing.T) {
	srv := pkiMockServer(t)
	defer srv.Close()

	c := New(srv.URL, "test-token")
	// 未知路径返回 404
	_, err := c.GetCert(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent cert")
	}
	t.Logf("✅ PKI error path: %v", err)
}
