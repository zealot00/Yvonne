// Package crypto - X.509 证书签发（RSA/ECDSA，标准库路径）。
//
// 提供 CA 自签根证书 + 终端证书签发能力。
// SM2 证书签发在 x509cert_gmsm.go（//go:build gmsm）。
//
// 安全红线：
//   - SerialNumber 用 crypto/rand 生成 128-bit 随机（防枚举）
//   - CA 证书强制 KeyUsage: CertSign | CRLSign
//   - 禁止签发 KeyUsage=Any 的证书
//   - 签名用 SecureSigner（KEK 解密后的私钥，签名后 Wipe）
package crypto

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// 证书有效期约束。
const (
	MaxRootCATTL    = 10 * 365 * 24 * time.Hour // 根 CA 最长 10 年
	MaxEndCertTTL   = 365 * 24 * time.Hour      // 终端证书最长 1 年
	DefaultRootTTL  = 10 * 365 * 24 * time.Hour
	DefaultCertTTL  = 90 * 24 * time.Hour // 默认 90 天
	SerialBits      = 128                 // 序列号位数（防枚举）
)

// CertType 证书用途类型（国密双证书体系）。
type CertType string

const (
	CertTypeSign    CertType = "sign"    // 签名证书
	CertTypeEncrypt CertType = "encrypt" // 加密证书
	CertTypeDual    CertType = "dual"    // 双证书（同时签发签名+加密）
	CertTypeCA      CertType = "ca"      // CA 证书
)

// CertRequest 证书签发请求。
type CertRequest struct {
	Subject      pkix.Name // 主题（CN/O/OU 等）
	PublicKey    interface{} // 公钥（*rsa.PublicKey / *ecdsa.PublicKey / *sm2.PublicKey）
	KeyType      string      // "rsa" / "ecdsa" / "sm2"
	CertType     CertType    // 用途类型
	TTL          time.Duration // 有效期
	IsCA         bool        // 是否 CA 证书
	KeyUsage     x509.KeyUsage // 自定义 KeyUsage（0=按 CertType 自动设置）
	ExtKeyUsage  []x509.ExtKeyUsage
	DNSNames     []string // SAN DNS 名
	IPAddresses  []string // SAN IP
}

// CertResult 证书签发结果。
type CertResult struct {
	PEM          []byte // 证书 PEM
	DER          []byte // 证书 DER（供 CRL 用）
	SerialNumber *big.Int
	NotBefore    time.Time
	NotAfter     time.Time
}

// IssueCertificate 签发 X.509 证书（RSA/ECDSA 路径）。
//
// 参数：
//   - req: 证书请求
//   - caCert: CA 证书（签发终端证书时传入；自签根 CA 时传 nil）
//   - caSigner: CA 的 crypto.Signer（签名用）
//
// 自签根 CA：caCert=nil, caSigner=自身私钥的 SecureSigner
func IssueCertificate(req CertRequest, caCert *x509.Certificate, caSigner stdcrypto.Signer) (*CertResult, error) {
	if req.PublicKey == nil {
		return nil, errors.New("crypto: public key is required")
	}
	if caSigner == nil {
		return nil, errors.New("crypto: CA signer is required")
	}

	// SM2 走 gmsm 路径。
	if req.KeyType == KeyTypeSM2 {
		return issueSM2Certificate(req, caCert, caSigner)
	}

	// RSA/ECDSA 走标准库路径。
	return issueStandardCertificate(req, caCert, caSigner)
}

// issueStandardCertificate 用 Go 标准库签发 RSA/ECDSA 证书。
func issueStandardCertificate(req CertRequest, caCert *x509.Certificate, caSigner stdcrypto.Signer) (*CertResult, error) {
	// 生成随机序列号。
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), SerialBits))
	if err != nil {
		return nil, fmt.Errorf("crypto: generate serial number: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.Add(req.TTL)
	if req.IsCA && req.TTL > MaxRootCATTL {
		notAfter = now.Add(MaxRootCATTL)
	}
	if !req.IsCA && req.TTL > MaxEndCertTTL {
		notAfter = now.Add(MaxEndCertTTL)
	}

	// 构造模板。
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		DNSNames:              req.DNSNames,
	}

	// 按用途设置 KeyUsage（如果调用方未指定）。
	if req.KeyUsage == 0 {
		template.KeyUsage = defaultKeyUsage(req.CertType, req.IsCA)
	}

	// CA 证书强制设置 MaxPathLen。
	if req.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if caCert == nil {
			// 自签根 CA。
			template.IsCA = true
			template.MaxPathLen = 1
		} else {
			// 中间 CA（暂不支持多级，v1.4 只做根 CA + 终端证书）。
			template.MaxPathLen = 0
		}
	}

	// 确定签发者。
	parent := template
	if caCert != nil {
		parent = caCert
		template.Issuer = caCert.Subject
	}

	// 签发证书。
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, req.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("crypto: create certificate: %w", err)
	}

	// PEM 编码。
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &CertResult{
		PEM:          certPEM,
		DER:          certDER,
		SerialNumber: serial,
		NotBefore:    now,
		NotAfter:     notAfter,
	}, nil
}

// defaultKeyUsage 按证书用途返回默认 KeyUsage。
func defaultKeyUsage(certType CertType, isCA bool) x509.KeyUsage {
	if isCA {
		return x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	switch certType {
	case CertTypeSign:
		return x509.KeyUsageDigitalSignature
	case CertTypeEncrypt:
		return x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	case CertTypeDual:
		// 双证书场景：单张证书同时含签名+加密用途（不推荐，应签两张）
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		return x509.KeyUsageDigitalSignature
	}
}

// ParseCertificatePEM 从 PEM 解析 X.509 证书（RSA/ECDSA 路径）。
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("crypto: no PEM block found in certificate")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("crypto: trailing data after certificate PEM (%d bytes)", len(rest))
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("crypto: unexpected PEM type %q, want %q", block.Type, "CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse certificate: %w", err)
	}
	return cert, nil
}
