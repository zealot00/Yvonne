// PKI HTTP handler 单元测试。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// newPKITestRouter 创建带 CertManager 的测试 router，返回 router + manager + masterKey。
func newPKITestRouter(t *testing.T) (*V1Router, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	router, mgr, mk := newV12TestRouter(t)
	certMgr := lifecycle.NewCertManager(mgr.Store())
	router.core.SetCertManager(certMgr)
	return router, mgr, mk
}

// TestHandler_PKI_CreateCA_RSA POST /api/v1/pki/ca 创建 RSA CA。
func TestHandler_PKI_CreateCA_RSA(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	body := createCARequest{
		KeyID:    "handler-rsa-ca",
		Algo:     "rsa",
		Subject:  "CN=Handler RSA CA",
		TTLYears: 10,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(bodyJSON))
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("CreateCA: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			KeyID  string `json:"key_id"`
			CertID string `json:"cert_id"`
			PEM    []byte `json:"pem"`
			Serial string `json:"serial"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.OK {
		t.Fatal("ok should be true")
	}
	if resp.Data.CertID == "" {
		t.Fatal("cert_id should not be empty")
	}
	if len(resp.Data.PEM) == 0 {
		t.Fatal("pem should not be empty")
	}
	t.Logf("✅ Handler CreateCA RSA: cert_id=%s", resp.Data.CertID)
}

// TestHandler_PKI_CreateCA_ECDSA POST /api/v1/pki/ca 创建 ECDSA CA。
func TestHandler_PKI_CreateCA_ECDSA(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	body := createCARequest{
		KeyID:    "handler-ecdsa-ca",
		Algo:     "ecdsa",
		Subject:  "CN=Handler ECDSA CA",
		TTLYears: 10,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(bodyJSON))
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("CreateCA ECDSA: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	t.Log("✅ Handler CreateCA ECDSA passed")
}

// TestHandler_PKI_CreateCA_MissingFields 缺字段返回 400。
func TestHandler_PKI_CreateCA_MissingFields(t *testing.T) {
	router, _, _ := newPKITestRouter(t)

	body := createCARequest{KeyID: "incomplete"} // 缺 algo + subject
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(bodyJSON))
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	t.Log("✅ Handler CreateCA missing fields → 400")
}

// TestHandler_PKI_IssueCert_RSA 签发终端证书。
func TestHandler_PKI_IssueCert_RSA(t *testing.T) {
	router, mgr, mk := newPKITestRouter(t)
	ctx := context.Background()

	// 1. 创建 CA。
	caBody := createCARequest{KeyID: "h-rsa-ca", Algo: "rsa", Subject: "CN=H RSA CA", TTLYears: 10}
	caJSON, _ := json.Marshal(caBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(caJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateCA: %d %s", w.Code, w.Body.String())
	}

	var caResp struct {
		Data struct {
			KeyID string `json:"key_id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &caResp)

	// 2. 创建终端密钥（通过 manager 直接创建）。
	endKeyID := "h-rsa-end"
	mgr.CreateAsymmetricKey(ctx, endKeyID, "rsa", seal.NewSoftwareKEK(mk))
	endMeta, _ := mgr.GetActiveKey(ctx, endKeyID)

	// 3. 签发证书。
	issueBody := issueCertRequest{
		CAKeyID:      caResp.Data.KeyID,
		Subject:      "CN=H End",
		Algo:         "rsa",
		PublicKeyPEM: endMeta.PublicKey,
		CertType:     "sign",
		TTLDays:      90,
	}
	issueJSON, _ := json.Marshal(issueBody)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/pki/issue", bytes.NewReader(issueJSON))
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	router.handlePKIIssue(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("IssueCert: got %d, want 200, body=%s", w2.Code, w2.Body.String())
	}

	var issueResp struct {
		Data struct {
			CertID string `json:"cert_id"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &issueResp)
	if issueResp.Data.CertID == "" {
		t.Fatal("cert_id should not be empty")
	}
	t.Logf("✅ Handler IssueCert RSA: cert_id=%s", issueResp.Data.CertID)
}

// TestHandler_PKI_GetCert 获取证书。
func TestHandler_PKI_GetCert(t *testing.T) {
	router, _, _ := newPKITestRouter(t)
	ctx := context.Background()

	// 创建 CA。
	caBody := createCARequest{KeyID: "g-ca", Algo: "rsa", Subject: "CN=G CA", TTLYears: 10}
	caJSON, _ := json.Marshal(caBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(caJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	var caResp struct {
		Data struct {
			CertID string `json:"cert_id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &caResp)

	// GET /api/v1/pki/cert/{certID}。
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/pki/cert/"+caResp.Data.CertID, nil)
	req2 = req2.WithContext(ctx)
	req2.SetPathValue("certID", caResp.Data.CertID)
	w2 := httptest.NewRecorder()
	router.handlePKIGetCert(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("GetCert: got %d, want 200, body=%s", w2.Code, w2.Body.String())
	}
	t.Log("✅ Handler GetCert passed")
}

// TestHandler_PKI_VerifyCert 验证证书。
func TestHandler_PKI_VerifyCert(t *testing.T) {
	router, mgr, mk := newPKITestRouter(t)
	ctx := context.Background()

	// 创建 CA。
	caBody := createCARequest{KeyID: "v-ca", Algo: "rsa", Subject: "CN=V CA", TTLYears: 10}
	caJSON, _ := json.Marshal(caBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(caJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	var caResp struct {
		Data struct {
			KeyID string `json:"key_id"`
			PEM   []byte `json:"pem"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &caResp)

	// 创建终端证书。
	endKeyID := "v-end"
	mgr.CreateAsymmetricKey(ctx, endKeyID, "rsa", seal.NewSoftwareKEK(mk))
	endMeta, _ := mgr.GetActiveKey(ctx, endKeyID)

	issueBody := issueCertRequest{
		CAKeyID: caResp.Data.KeyID, Subject: "CN=V End", Algo: "rsa",
		PublicKeyPEM: endMeta.PublicKey, CertType: "sign", TTLDays: 90,
	}
	issueJSON, _ := json.Marshal(issueBody)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/pki/issue", bytes.NewReader(issueJSON))
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	router.handlePKIIssue(w2, req2)

	var issueResp struct {
		Data struct {
			PEM []byte `json:"pem"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &issueResp)

	// 验证证书链。
	verifyBody := verifyCertRequest{CertPEM: issueResp.Data.PEM, CACertPEM: caResp.Data.PEM}
	verifyJSON, _ := json.Marshal(verifyBody)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/pki/verify", bytes.NewReader(verifyJSON))
	req3 = req3.WithContext(ctx)
	w3 := httptest.NewRecorder()
	router.handlePKIVerify(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("VerifyCert: got %d, want 200, body=%s", w3.Code, w3.Body.String())
	}

	var vResp struct {
		Data struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}
	json.Unmarshal(w3.Body.Bytes(), &vResp)
	if !vResp.Data.Valid {
		t.Fatal("cert should be valid")
	}
	t.Log("✅ Handler VerifyCert: valid=true")
}

// TestHandler_PKI_RevokeAndCRL 吊销 + CRL 获取。
func TestHandler_PKI_RevokeAndCRL(t *testing.T) {
	router, _, _ := newPKITestRouter(t)
	ctx := context.Background()

	// 创建 CA。
	caBody := createCARequest{KeyID: "r-ca", Algo: "rsa", Subject: "CN=R CA", TTLYears: 10}
	caJSON, _ := json.Marshal(caBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(caJSON))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	router.handlePKICA(w, req)

	var caResp struct {
		Data struct {
			KeyID  string `json:"key_id"`
			CertID string `json:"cert_id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &caResp)

	// 吊销 CA 证书（测试用）。
	revokeBody := revokeCertRequest{CAKeyID: caResp.Data.KeyID, CertID: caResp.Data.CertID, Reason: "test"}
	revokeJSON, _ := json.Marshal(revokeBody)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/pki/revoke", bytes.NewReader(revokeJSON))
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	router.handlePKIRevoke(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Revoke: got %d, want 200, body=%s", w2.Code, w2.Body.String())
	}

	// 获取 CRL。
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/pki/ca/"+caResp.Data.KeyID+"/crl", nil)
	req3 = req3.WithContext(ctx)
	req3.SetPathValue("caKeyID", caResp.Data.KeyID)
	w3 := httptest.NewRecorder()
	router.handlePKIGetCRL(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("GetCRL: got %d, want 200, body=%s", w3.Code, w3.Body.String())
	}
	t.Log("✅ Handler Revoke + GetCRL passed")
}
