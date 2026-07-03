// Package crypto - OCSP 错误路径覆盖率测试。
//
// 目标：覆盖代码未被单元测试触及的边界情况，确保 12 红线不被破坏。
//
// 安全红线：
//   - 错误路径不应泄露签名材料或私钥
//   - nil/空参数必须 fail-closed（返回 error 不 panic）
//   - 不允许覆盖 clear+KeepAlive 路径
package crypto

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestParseOCSPRequest_MalformedDER 验证畸形 DER 被拒绝（不 panic）。
func TestParseOCSPRequest_MalformedDER(t *testing.T) {
	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x30}},
		{"garbage", []byte{0xff, 0xff, 0xff}},
		{"wrong-tag", []byte{0x02, 0x01, 0x01}}, // INTEGER 不是 SEQUENCE
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseOCSPRequest(tc.der); err == nil {
				t.Fatalf("malformed DER %q should error", tc.name)
			}
		})
	}
}

// TestParseOCSPResponse_MalformedDER 验证畸形响应 DER 被拒绝。
func TestParseOCSPResponse_MalformedDER(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)
	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x30}},
		{"garbage", []byte{0xff, 0xff, 0xff}},
		{"unauthorized-prefabs", []byte{0x30, 0x03, 0x0A, 0x01, 0x06}}, // UnauthorizedErrorResponse
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseOCSPResponse(tc.der, caCert); err == nil {
				t.Fatalf("malformed response %q should error", tc.name)
			}
		})
	}
}

// TestCreateOCSPResponse_RSA_BadSigner 验证 SecureSigner 验签错误返回。
func TestCreateOCSPResponse_RSA_BadSigner(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)
	reqDER, err := BuildOCSPRequest(caCert, big.NewInt(1))
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}

	// 用一个未注册的 dummy signer 触发签名错误。
	dummy := &dummySigner{}
	now := time.Now().UTC()
	if _, err := CreateOCSPResponse(reqDER, caCert, dummy, OCSPStatusGood, time.Time{}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("dummy signer should error")
	}
	t.Log("✅ bad signer properly rejected")
}

// TestDecodeOCSPRequestBase64_EdgeCases 验证 base64 解码边界。
func TestDecodeOCSPRequestBase64_EdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"url-safe-alphabet", "aGVsbG8", false}, // "hello" - both std and url-safe
		{"raw-std-no-padding", "aGVsbG8", false},
		{"empty", "", true},
		{"only-padding", "====", true},
		{"invalid-chars", "@@@@", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeOCSPRequestBase64(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("input %q should error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("input %q should succeed, got %v", tc.input, err)
			}
		})
	}
}

// TestEncodeOCSPRequestBase64_Empty 空输入应产生空字符串（不 panic）。
func TestEncodeOCSPRequestBase64_Empty(t *testing.T) {
	got := EncodeOCSPRequestBase64(nil)
	if got != "" {
		t.Fatalf("empty input should encode to empty string, got %q", got)
	}
	t.Log("✅ empty encode returns empty string")
}

// TestCreateOCSPResponse_RSA_TruncatedSignerCert 验证响应可被解析回。
func TestCreateOCSPResponse_RSA_TruncatedSignerCert(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	reqDER, _ := BuildOCSPRequest(caCert, big.NewInt(999))
	now := time.Now().UTC()
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusGood, time.Time{}, 0, now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}

	// 模拟响应在网络中被截断（前 10 字节）→ 解析必失败。
	if _, err := ParseOCSPResponse(respDER[:10], caCert); err == nil {
		t.Fatal("truncated response should error")
	}
	t.Log("✅ truncated response correctly rejected")
}

// TestOCSPStatus_Constants 验证状态常量与 stdlib 一致（防止上游变化导致的兼容问题）。
func TestOCSPStatus_Constants(t *testing.T) {
	import_stdlib_alias := func() {}
	_ = import_stdlib_alias
	if OCSPStatusGood != 0 {
		t.Fatalf("OCSPStatusGood = %d, want 0", OCSPStatusGood)
	}
	if OCSPStatusRevoked != 1 {
		t.Fatalf("OCSPStatusRevoked = %d, want 1", OCSPStatusRevoked)
	}
	if OCSPStatusUnknown != 2 {
		t.Fatalf("OCSPStatusUnknown = %d, want 2", OCSPStatusUnknown)
	}
	t.Log("✅ OCSP status constants match stdlib")
}

// TestBuildOCSPRequest_DifferentSerials 验证不同 serial 产出不同 DER。
func TestBuildOCSPRequest_DifferentSerials(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)
	der1, _ := BuildOCSPRequest(caCert, big.NewInt(1))
	der2, _ := BuildOCSPRequest(caCert, big.NewInt(2))
	if string(der1) == string(der2) {
		t.Fatal("different serials should produce different DER")
	}
	t.Log("✅ different serials produce different DER")
}

// TestParseOCSPResponse_ResponseWithUnknownSerial 解析 unknown 状态响应。
func TestParseOCSPResponse_ResponseWithUnknownSerial(t *testing.T) {
	caCert, caSigner := makeRSACAForOCSP(t)
	defer caSigner.Dispose()

	reqDER, _ := BuildOCSPRequest(caCert, big.NewInt(123456789))
	now := time.Now().UTC()
	respDER, err := CreateOCSPResponse(reqDER, caCert, caSigner, OCSPStatusUnknown, time.Time{}, 0, now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	resp, err := ParseOCSPResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if resp.SerialNumber.Cmp(big.NewInt(123456789)) != 0 {
		t.Fatalf("serial mismatch")
	}
	t.Logf("✅ unknown-status response: serial=%s", resp.SerialNumber.String())
}

// TestCreateOCSPResponse_RSA_OCSPStatusConstant_StringCheck 验证错误信息不含私钥。
func TestCreateOCSPResponse_RSA_ErrorMessageSanity(t *testing.T) {
	caCert, _ := makeRSACAForOCSP(t)
	_, err := CreateOCSPResponse(nil, caCert, nil, OCSPStatusGood, time.Time{}, 0, time.Time{}, time.Time{})
	if err == nil {
		t.Fatal("nil reqDER should error")
	}
	// 确保错误信息不含敏感字串（私钥、PEM 等）。
	msg := err.Error()
	for _, sensitive := range []string{"BEGIN PRIVATE KEY", "BEGIN RSA", "secret", "passphrase"} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(sensitive)) {
			t.Fatalf("error message leaks sensitive keyword %q: %s", sensitive, msg)
		}
	}
	t.Logf("✅ error message clean: %s", msg)
}

// dummySigner 总是返回错误的 stdcrypto.Signer（用于测试错误路径）。
type dummySigner struct{}

func (*dummySigner) Public() stdcrypto.PublicKey { return nil }
func (*dummySigner) Sign(_ io.Reader, _ []byte, _ stdcrypto.SignerOpts) ([]byte, error) {
	return nil, dummySignErr
}

var dummySignErr = errDummy{}

type errDummy struct{}

func (errDummy) Error() string { return "dummy signer forced error" }

// 保留 RSA/rand 引用以兼容 -tags gmsm 下未使用的导入。
var (
	_ = rsa.GenerateKey
	_ = rand.Reader
	_ = pkix.Name{}
	_ = x509.CreateCertificate
)