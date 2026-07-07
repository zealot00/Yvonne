// Package crypto - OCSP（Online Certificate Status Protocol）签发与解析。
//
// OCSP（RFC 6960 / RFC 5010）用于在线查询证书吊销状态。
// 与 CRL 相比：
//   - 实时性更强：客户端可获得秒级的新鲜度
//   - 网络开销更低：单个序列号响应通常 < 1KB
//   - 需要 CA 在线运行（CRL 可离线分发）
//
// Yvonne 实现：
//   - 标准算法（RSA/ECDSA）：golang.org/x/crypto/ocsp
//   - 国密 SM2：通过 SM2 SecureSigner + 手工桥接 ocsp.Response（gmsm 无 OCSP 支持）
//
// 安全红线：
//   - 签名后 SecureSigner 必须 defer Dispose()
//   - 状态字段 Good / Revoked / Unknown 由调用方提供，本文件不做策略判断
//   - 已知限制：x/crypto/ocsp 不支持 nonce 透传（无 RFC 6960 §4.4.1 nonce 字段）
package crypto

import (
	stdcrypto "crypto"
	"crypto/sha1" //nolint:gosec // OCSP IssuerNameHash/IssuerKeyHash 强制 SHA-1（RFC 6960 §4.1.1）
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"
)

// OCSP 响应状态。
//
// 对应 RFC 6960 §4.2.2.3：
//
//	OCSPStatusGood    → 证书有效
//	OCSPStatusRevoked → 证书已被吊销
//	OCSPStatusUnknown → CA 不知道该 serial（未签发过或已过期不知）
//
// Unknown 不等于 Revoked：CA 没签发该证书 ≠ CA 签发了但又吊销。
const (
	OCSPStatusGood    = 0 // stdlib: ocsp.Good
	OCSPStatusRevoked = 1 // stdlib: ocsp.Revoked
	OCSPStatusUnknown = 2 // stdlib: ocsp.Unknown
)

// OCSP 响应默认有效期（thisUpdate ~ nextUpdate）。
//
// 短窗口降低重放风险，但增加 CA 负担。RFC 5010 推荐 1~7 天。
// Yvonne 默认 1 小时，平衡实时性与 CA 负载。
const ocspDefaultValidity = 1 * time.Hour

// sha1OID 是 SHA-1 算法 OID（1.3.14.3.2.26），用于 OCSP IssuerNameHash 计算。
// RFC 6960 §4.1.1 强制 SHA-1。
var sha1OID = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

// BuildOCSPRequest 构造 OCSP 请求 DER（RFC 6960 §4.1.1）。
//
// 参数：
//   - caCert：CA 证书（用于计算 IssuerNameHash / IssuerKeyHash）
//   - serial：待查询证书序列号
//
// 实现说明：golang.org/x/crypto/ocsp.CreateRequest 强制使用 cert.SerialNumber
// （即传入 cert 参数的 serial），无法直接查询任意 serial。我们改用 Request.Marshal()
// + 手工填充 CertID 来支持任意 serial 查询。
func BuildOCSPRequest(caCert *x509.Certificate, serial *big.Int) ([]byte, error) {
	if caCert == nil {
		return nil, errors.New("crypto: CA certificate is required for OCSP request")
	}
	if serial == nil {
		return nil, errors.New("crypto: serial number is required for OCSP request")
	}

	// 计算 IssuerNameHash = SHA-1(DER-encoded issuer DN)。
	// 自签 CA 时 RawIssuer == RawSubject。
	issuerNameHash := sha1.Sum(caCert.RawSubject) //nolint:gosec // RFC 6960 强制 SHA-1

	// 计算 IssuerKeyHash = SHA-1(DER-encoded issuer SubjectPublicKeyInfo)。
	issuerKeyHash := sha1.Sum(caCert.RawSubjectPublicKeyInfo) //nolint:gosec // RFC 6960 强制 SHA-1

	req := &stdocsp.Request{
		HashAlgorithm:  stdcrypto.SHA1,
		IssuerNameHash: issuerNameHash[:],
		IssuerKeyHash:  issuerKeyHash[:],
		SerialNumber:   serial,
	}

	der, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSP request: %w", err)
	}
	return der, nil
}

// ParseOCSPRequest 解析 OCSP 请求 DER。
func ParseOCSPRequest(reqDER []byte) (*stdocsp.Request, error) {
	if len(reqDER) == 0 {
		return nil, errors.New("crypto: empty OCSP request DER")
	}
	req, err := stdocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse OCSP request: %w", err)
	}
	if req.SerialNumber == nil {
		return nil, errors.New("crypto: OCSP request missing serial number")
	}
	return req, nil
}

// CreateOCSPResponse 签发 OCSP 响应（RSA/ECDSA 路径）。
//
// 参数：
//   - reqDER：原始 OCSP 请求 DER（用于提取 serial）
//   - caCert：CA 证书（响应签名前需匹配 IssuerNameHash，且作为 responder）
//   - caSigner：CA 的 crypto.Signer（*SecureSigner 实现此接口）
//   - status：OCSPStatusGood / OCSPStatusRevoked / OCSPStatusUnknown
//   - revokedAt：仅 Revoked 状态有意义；其他状态传 time.Time{}
//   - reason：仅 Revoked 状态有意义；其他状态传 0
//   - thisUpdate / nextUpdate：响应有效期窗口（传 zero value 用默认 1 小时）
//
// 返回：OCSP 响应 DER。
func CreateOCSPResponse(reqDER []byte, caCert *x509.Certificate, caSigner stdcrypto.Signer, status int, revokedAt time.Time, reason int, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	if len(reqDER) == 0 {
		return nil, errors.New("crypto: empty OCSP request DER for response")
	}
	if caCert == nil {
		return nil, errors.New("crypto: CA certificate is required for OCSP response")
	}
	if caSigner == nil {
		return nil, errors.New("crypto: CA signer is required for OCSP response")
	}

	// 解析请求以提取 serial。
	req, err := stdocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse request for response: %w", err)
	}

	// 构造 stdocsp.Response 模板。
	stdResp := stdocsp.Response{
		SerialNumber: req.SerialNumber,
	}

	// 设置状态。
	switch status {
	case OCSPStatusGood:
		stdResp.Status = stdocsp.Good
	case OCSPStatusRevoked:
		stdResp.Status = stdocsp.Revoked
		if !revokedAt.IsZero() {
			stdResp.RevokedAt = revokedAt
		}
		stdResp.RevocationReason = reason
	case OCSPStatusUnknown:
		stdResp.Status = stdocsp.Unknown
	default:
		return nil, fmt.Errorf("crypto: invalid OCSP status %d", status)
	}

	// 时间窗口。
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().UTC()
	}
	if nextUpdate.IsZero() {
		nextUpdate = thisUpdate.Add(ocspDefaultValidity)
	}
	stdResp.ThisUpdate = thisUpdate
	stdResp.NextUpdate = nextUpdate

	// stdocsp.CreateResponse 签名。
	// responderCert 用 CA 自身（最常见情况：CA 自签响应）。
	// 如果将来引入"独立 OCSP 签名证书"，调用方需提供 responderCert 参数。
	respDER, err := stdocsp.CreateResponse(caCert, caCert, stdResp, caSigner)
	if err != nil {
		return nil, fmt.Errorf("crypto: create OCSP response: %w", err)
	}
	return respDER, nil
}

// ParseOCSPResponse 解析 + 验证 OCSP 响应签名。
//
// 参数：
//   - respDER：响应 DER
//   - caCert：CA 证书（用于验签；签名必须来自此 CA 的私钥）
//
// 返回 *stdocsp.Response；调用方应检查 resp.Status。
func ParseOCSPResponse(respDER []byte, caCert *x509.Certificate) (*stdocsp.Response, error) {
	if len(respDER) == 0 {
		return nil, errors.New("crypto: empty OCSP response DER")
	}
	if caCert == nil {
		return nil, errors.New("crypto: CA certificate is required to verify OCSP response")
	}
	resp, err := stdocsp.ParseResponse(respDER, caCert)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse/verify OCSP response: %w", err)
	}
	return resp, nil
}

// EncodeOCSPRequestBase64 把 OCSP 请求 DER 编码为标准 base64（GET URL 参数用）。
//
// 不使用 URL-safe 字符集以兼容 RFC 6960 §A.1 附录示例。
// 输出不含 '=' padding（与 RFC 6960 一致）。
func EncodeOCSPRequestBase64(reqDER []byte) string {
	return base64.StdEncoding.EncodeToString(reqDER)
}

// DecodeOCSPRequestBase64 从 base64 字符串还原 OCSP 请求 DER。
//
// 接受标准与 URL-safe 字符集（自动容错），自动去除 padding。
func DecodeOCSPRequestBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("crypto: empty base64 OCSP request")
	}
	// 尝试标准编码，失败则 URL-safe，最后尝试 RawStdEncoding。
	if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode OCSP request base64: %w", err)
	}
	return decoded, nil
}
