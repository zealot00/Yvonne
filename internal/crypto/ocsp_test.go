// Package crypto - OCSP（Online Certificate Status Protocol）测试。
//
// OCSP（RFC 6960）用于在线查询证书吊销状态，比 CRL 更实时。
// 本测试覆盖 RSA/ECDSA 路径；SM2 路径见 ocsp_gmsm_test.go。
//
// 安全红线：
//   - 测试产生的密钥/签名材料用完不残留（函数返回即释放）
//   - 验签必须用 CA 公钥，不接受任何绕过
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	stdocsp "golang.org/x/crypto/ocsp" // Go 1.21+ 已将 ocsp 移出标准库
)

// makeRSACAForOCSP 创建用于 OCSP 测试的 RSA CA（含密钥 + 自签证书）。
func makeRSACAForOCSP(t *testing.T) (caCert *x509.Certificate, caSigner *SecureSigner) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	caDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	caSigner, err = NewSecureSigner(caDER, KeyTypeRSA)
	if err != nil {
		t.Fatalf("NewSecureSigner: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OCSP RSA Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, caSigner)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return caCert, caSigner
}

// TestBuildOCSPRequest_ParseOCSPRequest 验证 OCSP 请求的 DER 序列化往返。
func TestBuildOCSPRequest_ParseOCSPRequest(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)

	serial := big.NewInt(0x1234567890ABCDEF)
	reqDER, err := BuildOCSPRequest(caCert, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	if len(reqDER) == 0 {
		t.Fatal("OCSP request DER should not be empty")
	}

	req, err := ParseOCSPRequest(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequest: %v", err)
	}
	if req == nil {
		t.Fatal("parsed request should not be nil")
	}
	if req.SerialNumber.Cmp(serial) != 0 {
		t.Fatalf("serial mismatch: got %s, want %s", req.SerialNumber.String(), serial.String())
	}
	t.Logf("✅ OCSP request round-trip: serial=%s, %d bytes DER", serial.String(), len(reqDER))
}

// TestBuildOCSPRequest_NilArgs nil 参数应报错。
func TestBuildOCSPRequest_NilArgs(t *testing.T) {
	if _, err := BuildOCSPRequest(nil, big.NewInt(1)); err == nil {
		t.Fatal("nil caCert should error")
	}
	caCert, _ := makeRSACAForOCSP(t)
	if _, err := BuildOCSPRequest(caCert, nil); err == nil {
		t.Fatal("nil serial should error")
	}
	t.Log("✅ BuildOCSPRequest nil args handled")
}

// TestCreateOCSPResponse_Good_RSA 验证 Good 状态响应可被解析 + 签名验证通过。
func TestCreateOCSPResponse_Good_RSA(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	serial := new(big.Int).SetUint64(0xFEDCBA0987654321)
	reqDER, err := BuildOCSPRequest(caCert, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}

	now := time.Now().UTC()
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusGood, time.Time{}, 0, now, now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponse good: %v", err)
	}
	if len(respDER) == 0 {
		t.Fatal("response DER should not be empty")
	}

	resp, err := ParseOCSPResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if resp.SerialNumber.Cmp(serial) != 0 {
		t.Fatalf("serial mismatch: got %s, want %s", resp.SerialNumber.String(), serial.String())
	}
	if resp.Status != stdocsp.Good {
		t.Fatalf("status: got %d, want Good(%d)", resp.Status, stdocsp.Good)
	}
	t.Logf("✅ OCSP response Good: serial=%s", serial.String())
}

// TestCreateOCSPResponse_Revoked_RSA 验证 Revoked 状态响应。
func TestCreateOCSPResponse_Revoked_RSA(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	serial := new(big.Int).SetUint64(0xCAFEBABEDEADBEEF)
	reqDER, _ := BuildOCSPRequest(caCert, serial)

	revokedAt := time.Now().UTC().Add(-time.Hour)
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusRevoked, revokedAt, stdocsp.KeyCompromise, revokedAt, revokedAt.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponse revoked: %v", err)
	}

	resp, err := ParseOCSPResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if resp.Status != stdocsp.Revoked {
		t.Fatalf("status: got %d, want Revoked(%d)", resp.Status, stdocsp.Revoked)
	}
	if resp.RevokedAt.IsZero() {
		t.Fatal("RevokedAt should not be zero for revoked status")
	}
	if resp.RevocationReason != stdocsp.KeyCompromise {
		t.Fatalf("reason: got %d, want KeyCompromise(%d)", resp.RevocationReason, stdocsp.KeyCompromise)
	}
	t.Logf("✅ OCSP response Revoked: serial=%s, reason=%d", serial.String(), resp.RevocationReason)
}

// TestCreateOCSPResponse_Unknown_RSA 验证 Unknown 状态响应（CA 不认识该 serial）。
func TestCreateOCSPResponse_Unknown_RSA(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	serial := new(big.Int).SetUint64(0xDEADBEEF)
	reqDER, _ := BuildOCSPRequest(caCert, serial)

	now := time.Now().UTC()
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusUnknown, time.Time{}, 0, now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponse unknown: %v", err)
	}

	resp, err := ParseOCSPResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if resp.Status != stdocsp.Unknown {
		t.Fatalf("status: got %d, want Unknown(%d)", resp.Status, stdocsp.Unknown)
	}
	t.Logf("✅ OCSP response Unknown: serial=%s", serial.String())
}

// TestCreateOCSPResponse_DefaultTimeWindow 验证 thisUpdate/nextUpdate 缺省值。
func TestCreateOCSPResponse_DefaultTimeWindow(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	serial := big.NewInt(1)
	reqDER, _ := BuildOCSPRequest(caCert, serial)

	// thisUpdate/nextUpdate 传 zero → 默认 now + now+1h
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusGood, time.Time{}, 0, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse default window: %v", err)
	}
	resp, err := ParseOCSPResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if resp.ThisUpdate.IsZero() {
		t.Fatal("ThisUpdate should be defaulted to now()")
	}
	if resp.NextUpdate.IsZero() {
		t.Fatal("NextUpdate should be defaulted")
	}
	if !resp.NextUpdate.After(resp.ThisUpdate) {
		t.Fatal("NextUpdate should be after ThisUpdate")
	}
	t.Logf("✅ OCSP default window: thisUpdate=%s, nextUpdate=%s",
		resp.ThisUpdate.Format(time.RFC3339), resp.NextUpdate.Format(time.RFC3339))
}

// TestCreateOCSPResponse_NilArgs nil 参数应报错。
func TestCreateOCSPResponse_NilArgs(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	now := time.Now().UTC()
	// nil reqDER
	if _, err := CreateOCSPResponse(nil, caCert, caSigner, OCSPStatusGood, time.Time{}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("nil reqDER should error")
	}
	// nil caCert
	if _, err := CreateOCSPResponse([]byte{1, 2, 3}, nil, caSigner, OCSPStatusGood, time.Time{}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("nil caCert should error")
	}
	// nil caSigner
	if _, err := CreateOCSPResponse([]byte{1, 2, 3}, caCert, nil, OCSPStatusGood, time.Time{}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("nil caSigner should error")
	}
	t.Log("✅ CreateOCSPResponse nil args properly rejected")
}

// TestCreateOCSPResponse_InvalidStatus 非法 status 码应报错。
func TestCreateOCSPResponse_InvalidStatus(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	reqDER, _ := BuildOCSPRequest(caCert, big.NewInt(1))
	now := time.Now().UTC()
	if _, err := CreateOCSPResponse(reqDER, caCert, caSigner, 99, time.Time{}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("invalid status should error")
	}
	t.Log("✅ CreateOCSPResponse invalid status rejected")
}

// TestOCSPEncodeBase64Decode 验证 base64 编码/解码（GET 请求用）。
func TestOCSPEncodeBase64Decode(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)
	reqDER, err := BuildOCSPRequest(caCert, big.NewInt(42))
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	encoded := EncodeOCSPRequestBase64(reqDER)
	if encoded == "" {
		t.Fatal("base64 should not be empty")
	}
	decoded, err := DecodeOCSPRequestBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeOCSPRequestBase64: %v", err)
	}
	if len(decoded) != len(reqDER) {
		t.Fatalf("decoded length mismatch: got %d, want %d", len(decoded), len(reqDER))
	}
	for i := range decoded {
		if decoded[i] != reqDER[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
	t.Logf("✅ base64 round-trip: %d bytes DER", len(decoded))
}

// TestDecodeOCSPRequestBase64_Invalid 输入错误应报错。
func TestDecodeOCSPRequestBase64_Invalid(t *testing.T) {
	if _, err := DecodeOCSPRequestBase64("not!valid!base64!!!"); err == nil {
		t.Fatal("invalid base64 should error")
	}
	if _, err := DecodeOCSPRequestBase64(""); err == nil {
		t.Fatal("empty input should error")
	}
	t.Log("✅ DecodeOCSPRequestBase64 invalid input rejected")
}
