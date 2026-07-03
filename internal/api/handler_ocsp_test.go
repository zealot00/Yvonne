// OCSP HTTP handler 单元测试。
//
// 端点：
//   - GET  /api/v1/ocsp/{base64}    标准 RFC 6960 §A.1 GET 协议
//   - POST /api/v1/ocsp             标准 RFC 6960 §A.2 POST 协议（raw DER）
//
// 安全红线：
//   - 响应 Content-Type 必须是 application/ocsp-response（RFC 6960 强制）
//   - 错误也按 RFC 6960 字节返回（MalformedRequestErrorResponse 等）
//   - 审计日志记录 OCSPQuery 事件
package api

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // OCSP IssuerNameHash 强制 SHA-1
	stdcrypto "crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"
)

// setupHandlerOCSPFixture creates a router with one RSA CA + one active leaf cert.
// Returns the router, CA cert, and active leaf serial for OCSP request construction.
func setupHandlerOCSPFixture(t *testing.T) (*V1Router, *x509.Certificate, *big.Int) {
	t.Helper()
	router, _, _ := newPKITestRouter(t)

	// 创建 CA。
	body := createCARequest{
		KeyID:    "handler-ocsp-ca-" + randSuffix(t),
		Algo:     "rsa",
		Subject:  "CN=Handler OCSP CA",
		TTLYears: 10,
	}
	caJSON := mustMarshalJSON(t, body)
	rec := httptest.NewRecorder()
	router.handlePKICA(rec, httptest.NewRequest(http.MethodPost, "/api/v1/pki/ca", bytes.NewReader(caJSON)))
	if rec.Code != http.StatusOK {
		t.Fatalf("CreateCA: got %d, body=%s", rec.Code, rec.Body.String())
	}
	var caResult struct {
		OK   bool `json:"ok"`
		Data struct {
			KeyID  string `json:"key_id"`
			CertID string `json:"cert_id"`
			PEM    []byte `json:"pem"`
			Serial string `json:"serial"`
		} `json:"data"`
	}
	mustUnmarshalJSON(t, rec.Body.Bytes(), &caResult)
	if !caResult.OK {
		t.Fatalf("CreateCA not OK: %s", rec.Body.String())
	}
	caCert := mustParseCAPEM(t, caResult.Data.PEM)

	// 签发一个叶子证书（使用 RSA 客户端密钥）。
	priv, err := rsaGenKeyTest()
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubPEM, err := encodeRSAPubPEMTest(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode pub: %v", err)
	}
	issueBody := issueCertRequest{
		CAKeyID:      caResult.Data.KeyID,
		Subject:      "CN=leaf.yvonne.test",
		Algo:         "rsa",
		PublicKeyPEM: pubPEM,
		CertType:     "sign",
		TTLDays:      90,
	}
	issueJSON := mustMarshalJSON(t, issueBody)
	rec2 := httptest.NewRecorder()
	router.handlePKIIssue(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/pki/issue", bytes.NewReader(issueJSON)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("IssueCert: got %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var issueRes struct {
		OK   bool `json:"ok"`
		Data struct {
			CertID string `json:"cert_id"`
			Serial string `json:"serial"`
		} `json:"data"`
	}
	mustUnmarshalJSON(t, rec2.Body.Bytes(), &issueRes)

	serial := new(big.Int)
	if _, ok := serial.SetString(issueRes.Data.Serial, 10); !ok {
		t.Fatalf("invalid serial: %s", issueRes.Data.Serial)
	}
	return router, caCert, serial
}

// TestHandler_OCSP_GET_Base64 GET /api/v1/ocsp/{base64} 标准协议。
func TestHandler_OCSP_GET_Base64(t *testing.T) {
	router, caCert, serial := setupHandlerOCSPFixture(t)
	reqDER := mustBuildOCSPReq(t, caCert, serial)
	encoded := mustEncodeBase64(t, reqDER)

	rec := httptest.NewRecorder()
	url := "/api/v1/ocsp/" + encoded
	router.HandleOCSPQuery(rec, httptest.NewRequest(http.MethodGet, url, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET OCSP: got %d, want 200, body=%d bytes", rec.Code, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("Content-Type: got %q, want application/ocsp-response", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("response body should not be empty")
	}
	// 解析响应验证签名。
	resp, err := stdocsp.ParseResponse(rec.Body.Bytes(), caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Good {
		t.Fatalf("status: got %d, want Good(%d)", resp.Status, stdocsp.Good)
	}
	t.Logf("✅ GET OCSP: serial=%s, %d bytes", serial.String(), rec.Body.Len())
}

// TestHandler_OCSP_POST_DER POST /api/v1/ocsp 标准协议（raw DER）。
func TestHandler_OCSP_POST_DER(t *testing.T) {
	router, caCert, serial := setupHandlerOCSPFixture(t)
	reqDER := mustBuildOCSPReq(t, caCert, serial)

	rec := httptest.NewRecorder()
	router.HandleOCSPQuery(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ocsp", bytes.NewReader(reqDER)))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST OCSP: got %d, want 200, body=%d bytes", rec.Code, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("Content-Type: got %q, want application/ocsp-response", ct)
	}
	resp, err := stdocsp.ParseResponse(rec.Body.Bytes(), caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Good {
		t.Fatalf("status: got %d, want Good(%d)", resp.Status, stdocsp.Good)
	}
	t.Logf("✅ POST OCSP: serial=%s, %d bytes", serial.String(), rec.Body.Len())
}

// TestHandler_OCSP_GET_InvalidBase64 无效 base64 → RFC 6960 MalformedRequestErrorResponse。
func TestHandler_OCSP_GET_InvalidBase64(t *testing.T) {
	router, _, _ := setupHandlerOCSPFixture(t)

	rec := httptest.NewRecorder()
	router.HandleOCSPQuery(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ocsp/!!!invalid-base64!!!", nil))

	// RFC 6960 要求即使错误也返回 application/ocsp-response（标准错误字节）。
	if ct := rec.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Fatalf("Content-Type: got %q, want application/ocsp-response", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("malformed request should return error response bytes")
	}
	t.Logf("✅ invalid base64 → %d-byte error response", rec.Body.Len())
}

// TestHandler_OCSP_POST_Empty POST 空请求体 → 错误响应。
func TestHandler_OCSP_POST_Empty(t *testing.T) {
	router, _, _ := setupHandlerOCSPFixture(t)

	rec := httptest.NewRecorder()
	router.HandleOCSPQuery(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ocsp", nil))

	if rec.Body.Len() == 0 {
		t.Fatal("empty POST should return error response bytes")
	}
	t.Logf("✅ empty POST → %d-byte error response", rec.Body.Len())
}

// TestHandler_OCSP_UnknownSerial 未知 serial → Unknown 状态。
func TestHandler_OCSP_UnknownSerial(t *testing.T) {
	router, caCert, _ := setupHandlerOCSPFixture(t)
	reqDER := mustBuildOCSPReq(t, caCert, big.NewInt(0xFFFFFFFFFF))

	rec := httptest.NewRecorder()
	router.HandleOCSPQuery(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ocsp", bytes.NewReader(reqDER)))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST OCSP: got %d, want 200", rec.Code)
	}
	resp, err := stdocsp.ParseResponse(rec.Body.Bytes(), caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Unknown {
		t.Fatalf("status: got %d, want Unknown(%d)", resp.Status, stdocsp.Unknown)
	}
	t.Logf("✅ unknown serial → Unknown")
}

// === shared test helpers (local copies of service helpers) ===

// mustParseCAPEM parses a CA PEM into *x509.Certificate.
func mustParseCAPEM(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// mustBuildOCSPReq constructs an OCSP request DER from CA cert + serial.
func mustBuildOCSPReq(t *testing.T, caCert *x509.Certificate, serial *big.Int) []byte {
	t.Helper()
	nameHash := sha1.Sum(caCert.RawSubject)              //nolint:gosec
	keyHash := sha1.Sum(caCert.RawSubjectPublicKeyInfo) //nolint:gosec
	req := stdocsp.Request{
		HashAlgorithm:  stdcrypto.SHA1,
		IssuerNameHash: nameHash[:],
		IssuerKeyHash:  keyHash[:],
		SerialNumber:   serial,
	}
	der, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return der
}

// mustEncodeBase64 base64 编码（URL-safe，padding）。
func mustEncodeBase64(t *testing.T, data []byte) string {
	t.Helper()
	// URL-safe 不带 padding（与 RFC 6960 附录一致）。
	return base64URLEncode(data)
}

// mustMarshalJSON json.Marshal 包装（错误立即 fail）。
func mustMarshalJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := jsonMarshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// mustUnmarshalJSON json.Unmarshal 包装（错误立即 fail）。
func mustUnmarshalJSON(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := jsonUnmarshal(data, v); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
}

// randSuffix 随机短串（用于唯一化 keyID）。
func randSuffix(t *testing.T) string {
	t.Helper()
	now := time.Now().UnixNano()
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = hex[(now>>(i*4))&0xf]
	}
	return string(out)
}

// 用于 lint：保持 pkix import 引用（未来 SM2 handler 测试可能用到）。
var _ = pkix.Name{}