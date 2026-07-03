//go:build gmsm

// SM2 OCSP 签发（gmsm 构建标签）。
//
// gmsm 无 OCSP 实现，且 stdlib x509.ParseCertificate 无法解析 SM2 证书。
// 因此 SM2 OCSP 必须手工构造 BasicOCSPResponse ASN.1 结构。
//
// 本实现要点：
//   - 不依赖 stdlib stdocsp.CreateResponse（签名算法硬编码为 SHA-1 + RSA/ECDSA）
//   - 手工构造 ResponseData + BasicOCSPResponse（RFC 6960 §4.2.1）
//   - 摘要算法用 SM3（RFC 6960 允许非 SHA-1 摘要）
//   - 签名算法 OID 用 SM2WithSM3（1.2.156.10197.1.501）
//
// 安全红线：
//   - SecureSigner 必须 defer Dispose()
//   - TBSResponseData 序列化后立即 SM3 摘要，摘要不缓存
package crypto

import (
	"crypto/sha1" //nolint:gosec // OCSP IssuerNameHash/IssuerKeyHash 强制 SHA-1（RFC 6960 §4.1.1）
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/tjfoc/gmsm/sm3"
	gmx509 "github.com/tjfoc/gmsm/x509"

	stdocsp "golang.org/x/crypto/ocsp"
)

// SM2 OCSP 签名算法 OID（SM2WithSM3 = 1.2.156.10197.1.501）。
var sm2WithSM3OID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

// SM2 OCSP 摘要算法 OID（SM3 = 1.2.156.10197.1.401）。
var sm3OID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

// idPKIXOCSPBasic 是 id-pkix-ocsp-basic OID（1.3.6.1.5.5.7.48.1.1）。
var idPKIXOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// CreateSM2OCSPResponse 签发 SM2 OCSP 响应。
//
// 参数：
//   - reqDER：原始 OCSP 请求 DER（用于提取 serial）
//   - sm2CertDER：SM2 CA 证书 DER（gmsm 格式）
//   - sm2Signer：SM2 SecureSigner
//   - status：OCSPStatusGood / OCSPStatusRevoked / OCSPStatusUnknown
//   - revokedAt：仅 Revoked 状态有意义
//   - reason：仅 Revoked 状态有意义
//   - thisUpdate / nextUpdate：响应有效期窗口（zero → 默认 1 小时）
//
// 返回：OCSPResponse DER（含 envelope 外层）。
func CreateSM2OCSPResponse(reqDER, sm2CertDER []byte, sm2Signer *SecureSigner, status int, revokedAt time.Time, reason int, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	if len(reqDER) == 0 {
		return nil, errors.New("crypto: empty OCSP request DER for SM2 response")
	}
	if len(sm2CertDER) == 0 {
		return nil, errors.New("crypto: empty SM2 CA certificate DER")
	}
	if sm2Signer == nil {
		return nil, errors.New("crypto: SM2 signer is required for OCSP response")
	}

	// 1. 解析 OCSP 请求以提取 serial。
	serial, err := extractSerialFromOCSPRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 OCSP request: %w", err)
	}

	// 2. 解析 SM2 CA 证书（gmsm 路径）。
	sm2Cert, err := gmx509.ParseCertificate(sm2CertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse SM2 CA cert: %w", err)
	}

	// 3. 计算时间窗口。
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().UTC()
	}
	if nextUpdate.IsZero() {
		nextUpdate = thisUpdate.Add(ocspDefaultValidity)
	}

	// 4. 构造 ResponseData。
	issuerNameHash := sha1.Sum(sm2Cert.RawSubject)         //nolint:gosec // RFC 6960 强制 SHA-1
	issuerKeyHash := sha1.Sum(sm2Cert.RawSubjectPublicKeyInfo) //nolint:gosec // RFC 6960 强制 SHA-1

	certStatus, err := buildSM2CertStatus(status, revokedAt, reason)
	if err != nil {
		return nil, err
	}

	respData := responseDataASN1{
		Version: 0,
		ResponderID: responderIDASN1{
			ByName: pkix.RDNSequence(sm2Cert.Subject.ToRDNSequence()),
		},
		ProducedAt: time.Now().UTC(),
		Responses: []singleResponseASN1{
			{
				CertID: certIDASN1Ocsp{
					HashAlgorithm: pkix.AlgorithmIdentifier{
						Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // SHA-1
					},
					IssuerNameHash: issuerNameHash[:],
					IssuerKeyHash:  issuerKeyHash[:],
					SerialNumber:   serial,
				},
				CertStatus: certStatus,
				ThisUpdate: thisUpdate,
				NextUpdate: nextUpdate,
			},
		},
	}

	tbsDER, err := asn1.Marshal(respData)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal TBSResponseData: %w", err)
	}

	// 5. 用 SM3 摘要 + SM2 签名。
	sm3Hasher := sm3.New()
	sm3Hasher.Write(tbsDER)
	digest := sm3Hasher.Sum(nil)
	sig, err := sm2Signer.Sign(nil, digest, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: SM2 sign OCSP response: %w", err)
	}

	// 6. 构造 BasicOCSPResponse。
	basicResp := basicOCSPResponseASN1{
		TBSResponseData: asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassContextSpecific, IsCompound: true, FullBytes: tbsDER},
		// 这里用一个 trick：把 TBSResponseData 整个包进 explicit [0] 还是 SEQUENCE？
		// RFC 6960 §4.2.1：tbsResponseData ResponseData（裸 SEQUENCE）
		// 但 asn1.Marshal 已输出完整 SEQUENCE 头，所以直接传 FullBytes（包内会自动剥 tag）
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sm2WithSM3OID},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
		Certs:              []asn1.RawValue{{Tag: asn1.TagSequence, FullBytes: sm2CertDER}},
	}
	basicDER, err := asn1.Marshal(basicResp)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal BasicOCSPResponse: %w", err)
	}

	// 7. 包装 OCSPResponse envelope。
	envelope := ocspResponseEnvelopeASN1{
		ResponseStatus: 0, // successful
		ResponseBytes: ocspResponseBytesASN1{
			ResponseType: idPKIXOCSPBasic,
			Response:     asn1.RawValue{Tag: asn1.TagOctetString, FullBytes: basicDER},
		},
	}
	finalDER, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal OCSPResponse envelope: %w", err)
	}
	return finalDER, nil
}

// === ASN.1 结构定义（RFC 6960 §4.2.1） ===

// responseDataASN1 是 ResponseData 的 ASN.1 结构。
type responseDataASN1 struct {
	Version     int                  `asn1:"tag:0,default:0,optional"`
	ResponderID responderIDASN1      `asn1:"choice"`
	ProducedAt  time.Time            `asn1:"generalized"`
	Responses   []singleResponseASN1 `asn1:"sequence"`
}

// responderIDASN1 是 ResponderID 的 CHOICE 结构（byName [1] or byKey [2]）。
type responderIDASN1 struct {
	ByName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	ByKey  []byte           `asn1:"explicit,tag:2,optional"`
}

// singleResponseASN1 是 SingleResponse 的 ASN.1 结构。
type singleResponseASN1 struct {
	CertID     certIDASN1Ocsp `asn1:"sequence"`
	CertStatus certStatusASN1 `asn1:"choice"`
	ThisUpdate time.Time      `asn1:"generalized"`
	NextUpdate time.Time      `asn1:"generalized,optional"`
}

// certIDASN1Ocsp 是 CertID 的 ASN.1 结构（用于 OCSP response）。
// 注意：serial 在 RFC 6960 是 INTEGER，但 gmsm 工具链常用 []byte 编码大数。
type certIDASN1Ocsp struct {
	HashAlgorithm  pkix.AlgorithmIdentifier `asn1:"sequence"`
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   []byte
}

// certStatusASN1 是 CertStatus 的 CHOICE 结构。
type certStatusASN1 struct {
	Good    asn1.RawValue `asn1:"implicit,tag:0,optional"`
	Revoked revokedInfoASN1 `asn1:"explicit,tag:1,optional"`
	Unknown asn1.RawValue `asn1:"implicit,tag:2,optional"`
}

// revokedInfoASN1 是 RevokedInfo 的 ASN.1 结构（RFC 6960 §4.2.1）。
type revokedInfoASN1 struct {
	RevocationTime   time.Time       `asn1:"generalized"`
	RevocationReason asn1.RawValue   `asn1:"explicit,tag:0,optional"`
}

// basicOCSPResponseASN1 是 BasicOCSPResponse 的 ASN.1 结构。
type basicOCSPResponseASN1 struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,tag:0"`
}

// ocspResponseEnvelopeASN1 是 OCSPResponse envelope。
type ocspResponseEnvelopeASN1 struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  ocspResponseBytesASN1 `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytesASN1 struct {
	ResponseType asn1.ObjectIdentifier
	Response     asn1.RawValue
}

// buildSM2CertStatus 构造 CertStatus CHOICE。
func buildSM2CertStatus(status int, revokedAt time.Time, reason int) (certStatusASN1, error) {
	switch status {
	case OCSPStatusGood:
		// good = NULL
		return certStatusASN1{
			Good: asn1.RawValue{Tag: asn1.TagNull},
		}, nil
	case OCSPStatusRevoked:
		if revokedAt.IsZero() {
			return certStatusASN1{}, errors.New("crypto: revoked status requires non-zero revokedAt")
		}
		ri := revokedInfoASN1{
			RevocationTime: revokedAt,
		}
		if reason != 0 {
			ri.RevocationReason = encodeRevocationReason(reason)
		}
		return certStatusASN1{Revoked: ri}, nil
	case OCSPStatusUnknown:
		return certStatusASN1{
			Unknown: asn1.RawValue{Tag: asn1.TagNull},
		}, nil
	default:
		return certStatusASN1{}, fmt.Errorf("crypto: invalid SM2 OCSP status %d", status)
	}
}

// encodeRevocationReason 把 reason int 编码为 asn1.RawValue（enumerated）。
func encodeRevocationReason(reason int) asn1.RawValue {
	if reason < 0 || reason > 10 {
		reason = 0 // unspecified
	}
	encoded, _ := asn1.Marshal(asn1.Enumerated(reason))
	return asn1.RawValue{FullBytes: encoded}
}

// extractSerialFromOCSPRequest 从 OCSP 请求 DER 中提取 serial bytes。
//
// 复用 stdlib stdocsp.ParseRequest（仅做 ASN.1 unmarshal，不验签）。
func extractSerialFromOCSPRequest(reqDER []byte) ([]byte, error) {
	req, err := stdocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: unmarshal OCSP request: %w", err)
	}
	if req.SerialNumber == nil {
		return nil, errors.New("crypto: OCSP request missing serial number")
	}
	return req.SerialNumber.Bytes(), nil
}