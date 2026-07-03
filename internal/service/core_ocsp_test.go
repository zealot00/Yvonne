// Package service - OCSP 业务层测试（TDD 严格，先 RED）。
//
// Core.OCSP 接受 raw OCSP 请求 DER，返回 raw OCSP 响应 DER。
// 业务流程：
//  1. 解析请求 → 提取 issuerNameHash/issuerKeyHash/serial
//  2. 遍历已知 CA，找到匹配 issuer hash 的 CA
//  3. 在该 CA 下按 serial 查询证书元数据
//  4. 命中：判断 Active/Revoked → 签发 Good/Revoked 响应
//     未命中：签发 Unknown 响应
//  5. 找不到 CA：返回错误
//
// 安全红线：
//   - SecureSigner 必须 defer Dispose()
//   - 审计日志记录 OCSPQuery 事件
//   - 错误路径不能泄露私钥/PEM 内容
package service

import (
	"context"
	"crypto/sha1" //nolint:gosec // OCSP IssuerNameHash 强制 SHA-1（RFC 6960 §4.1.1）
	stdcrypto "crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"
)

// === Tests ===

// TestCore_OCSP_ActiveCert 命中 active 证书 → Good 响应。
func TestCore_OCSP_ActiveCert(t *testing.T) {
	core, caKeyID, caCert := setupOCAChain(t)

	activeSerial := issueLeafUnder(t, core, caKeyID, "CN=active.yvonne.test")

	reqDER := mustBuildOCSPReq(t, caCert, activeSerial)
	respDER, err := core.OCSP(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Core.OCSP: %v", err)
	}

	resp, err := stdocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Good {
		t.Fatalf("status: got %d, want Good(%d)", resp.Status, stdocsp.Good)
	}
	if resp.SerialNumber.Cmp(activeSerial) != 0 {
		t.Fatalf("serial mismatch: got %s, want %s", resp.SerialNumber.String(), activeSerial.String())
	}
	t.Logf("✅ active cert → Good: serial=%s", activeSerial.String())
}

// TestCore_OCSP_RevokedCert 命中 revoked 证书 → Revoked 响应。
func TestCore_OCSP_RevokedCert(t *testing.T) {
	core, caKeyID, caCert := setupOCAChain(t)

	revokedSerial, leafID := issueLeafUnderWithID(t, core, caKeyID, "CN=revoked.yvonne.test")
	if err := core.RevokeCert(context.Background(), caKeyID, leafID, "key compromise", nil); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	reqDER := mustBuildOCSPReq(t, caCert, revokedSerial)
	respDER, err := core.OCSP(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Core.OCSP: %v", err)
	}
	resp, err := stdocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Revoked {
		t.Fatalf("status: got %d, want Revoked(%d)", resp.Status, stdocsp.Revoked)
	}
	t.Logf("✅ revoked cert → Revoked: serial=%s", revokedSerial.String())
}

// TestCore_OCSP_UnknownSerial serial 在 CA 范围内但未签发 → Unknown 响应。
func TestCore_OCSP_UnknownSerial(t *testing.T) {
	core, _, caCert := setupOCAChain(t)

	unknownSerial := big.NewInt(0xFFFFFFFFFF)
	reqDER := mustBuildOCSPReq(t, caCert, unknownSerial)
	respDER, err := core.OCSP(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Core.OCSP: %v", err)
	}
	resp, err := stdocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != stdocsp.Unknown {
		t.Fatalf("status: got %d, want Unknown(%d)", resp.Status, stdocsp.Unknown)
	}
	t.Logf("✅ unknown serial → Unknown: serial=%s", unknownSerial.String())
}

// TestCore_OCSP_UnknownIssuer 来自陌生 CA 的请求（issuer hash 不匹配任何已知 CA）→ 错误。
func TestCore_OCSP_UnknownIssuer(t *testing.T) {
	core, _, _ := setupOCAChain(t)

	rogue := makeRSACertForOCSP(t)
	issuerNameHash := sha1.Sum(rogue.RawSubject)              //nolint:gosec
	issuerKeyHash := sha1.Sum(rogue.RawSubjectPublicKeyInfo) //nolint:gosec
	req := stdocsp.Request{
		HashAlgorithm:  stdcrypto.SHA1,
		IssuerNameHash: issuerNameHash[:],
		IssuerKeyHash:  issuerKeyHash[:],
		SerialNumber:   big.NewInt(1),
	}
	reqDER, err := req.Marshal()
	if err != nil {
		t.Fatalf("req.Marshal: %v", err)
	}
	if _, err := core.OCSP(context.Background(), reqDER); err == nil {
		t.Fatal("unknown issuer should error")
	}
	t.Log("✅ unknown issuer properly rejected")
}

// TestCore_OCSP_EmptyRequest nil/空请求应报错。
func TestCore_OCSP_EmptyRequest(t *testing.T) {
	core, _, _ := setupOCAChain(t)
	if _, err := core.OCSP(context.Background(), nil); err == nil {
		t.Fatal("nil request should error")
	}
	if _, err := core.OCSP(context.Background(), []byte{}); err == nil {
		t.Fatal("empty request should error")
	}
	t.Log("✅ empty request rejected")
}

// TestCore_OCSP_MalformedDER 畸形 DER 应报错。
func TestCore_OCSP_MalformedDER(t *testing.T) {
	core, _, _ := setupOCAChain(t)
	if _, err := core.OCSP(context.Background(), []byte{0xff, 0xff}); err == nil {
		t.Fatal("malformed DER should error")
	}
	t.Log("✅ malformed DER rejected")
}

// TestCore_OCSP_PKINotConfigured 未配置 CertManager 时报错。
func TestCore_OCSP_PKINotConfigured(t *testing.T) {
	core, _, _ := newTestCore(t)
	if _, err := core.OCSP(context.Background(), []byte{0x30, 0x00}); err == nil {
		t.Fatal("should error when certManager is nil")
	}
	t.Logf("✅ Core.OCSP without CertManager errored")
}

// === helpers used by tests ===

// setupOCAChain creates a core with one RSA CA ready for issuing leaves.
func setupOCAChain(t *testing.T) (*Core, string, *x509.Certificate) {
	t.Helper()
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	caResult, err := core.CreateCA(ctx, "ocsp-ca-"+randSuffix(t), "rsa", "CN=OCSP Test CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	caCert, err := parseCAPEM(caResult.PEM)
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	return core, caResult.KeyID, caCert
}

// parseCAPEM 从 CA PEM 还原 *x509.Certificate。
func parseCAPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, pemDecodeErr("no PEM block in CA PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

type pemDecodeErr string

func (e pemDecodeErr) Error() string { return "pem: " + string(e) }

// issueLeafUnder creates a leaf key + leaf cert under caKeyID; returns serial *big.Int.
func issueLeafUnder(t *testing.T, core *Core, caKeyID, subject string) *big.Int {
	t.Helper()
	serial, _ := issueLeafUnderWithID(t, core, caKeyID, subject)
	return serial
}

// issueLeafUnderWithID creates a leaf key + leaf cert under caKeyID; returns (serial, certID).
func issueLeafUnderWithID(t *testing.T, core *Core, caKeyID, subject string) (*big.Int, string) {
	t.Helper()
	priv, err := rsaGenerateKeyForTest()
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pubPEM, err := encodeRSAPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode pub: %v", err)
	}
	res, err := core.IssueCert(
		context.Background(),
		caKeyID,
		subject,
		"rsa",
		pubPEM,
		"sign",
		90,
		nil,
	)
	if err != nil {
		t.Fatalf("IssueCert %s: %v", subject, err)
	}
	serial, ok := new(big.Int).SetString(res.Serial, 10)
	if !ok {
		t.Fatalf("invalid serial in IssueCert result: %q", res.Serial)
	}
	return serial, res.CertID
}

// mustBuildOCSPReq 构造 OCSP 请求 DER。
func mustBuildOCSPReq(t *testing.T, caCert *x509.Certificate, serial *big.Int) []byte {
	t.Helper()
	issuerNameHash := sha1.Sum(caCert.RawSubject)              //nolint:gosec
	issuerKeyHash := sha1.Sum(caCert.RawSubjectPublicKeyInfo) //nolint:gosec
	req := stdocsp.Request{
		HashAlgorithm:  stdcrypto.SHA1,
		IssuerNameHash: issuerNameHash[:],
		IssuerKeyHash:  issuerKeyHash[:],
		SerialNumber:   serial,
	}
	der, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return der
}

// makeRSACertForOCSP 创建一个独立的 RSA 自签证书（用于伪造 issuer）。
func makeRSACertForOCSP(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := rsaGenerateKeyForTest()
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "OCSP Rogue CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(randReader(), tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}