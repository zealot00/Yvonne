// Package service - OCSP 业务层（v1.4.x 新增）。
//
// Core.OCSP 接受 raw OCSP 请求 DER，返回 raw OCSP 响应 DER。
// 业务流程：
//  1. 解析请求 → 提取 issuerNameHash/issuerKeyHash/serial
//  2. 遍历已知 CA 列表，匹配 issuer hash 找到对应 CA
//  3. 在该 CA 下按 serial 查询证书元数据
//  4. 命中：判断 Active/Revoked → 签发 Good/Revoked 响应
//     未命中：签发 Unknown 响应
//  5. 找不到 CA：返回错误（OCSP 请求无法路由）
//
// 安全红线：
//   - SecureSigner 必须 defer Dispose()
//   - 审计日志记录 OCSPQuery 事件
//   - 错误路径不返回 PEM/私钥明文
//   - 复用 extractSigner 模式（core_pki.go:355）
package service

import (
	"context"
	"crypto/sha1" //nolint:gosec // OCSP IssuerNameHash 强制 SHA-1（RFC 6960 §4.1.1）
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	stdocsp "golang.org/x/crypto/ocsp"

	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
)

// OCSP 响应默认有效期（与 crypto.ocspDefaultValidity 对齐：1 小时）。
const ocspDefaultValiditySeconds = 3600

// OCSP 处理业务方法。
//
// 参数：
//   - ctx：请求上下文
//   - reqDER：原始 OCSP 请求 DER
//
// 返回：响应 DER（HTTP handler 应返回 application/ocsp-response）。
func (c *Core) OCSP(ctx context.Context, reqDER []byte) ([]byte, error) {
	if len(reqDER) == 0 {
		c.recordAudit(ctx, "OCSPQuery", "", 0, "error", "empty request")
		return nil, errors.New("service: empty OCSP request")
	}
	if c.certManager == nil {
		c.recordAudit(ctx, "OCSPQuery", "", 0, "error", "PKI not configured")
		return nil, fmt.Errorf("service: PKI not configured")
	}

	// 1. 解析请求（提取 issuer hash + serial）。
	req, err := crypto.ParseOCSPRequest(reqDER)
	if err != nil {
		c.recordAudit(ctx, "OCSPQuery", "", 0, "error", "malformed request: "+err.Error())
		return nil, fmt.Errorf("service: parse OCSP request: %w", err)
	}

	// 2. 遍历所有 CA 找到匹配的 issuer。
	caMeta, caCert, err := c.findCAMatch(ctx, req.IssuerNameHash, req.IssuerKeyHash)
	if err != nil {
		c.recordAudit(ctx, "OCSPQuery", "", 0, "error", "no CA matches issuer")
		return nil, fmt.Errorf("service: no CA matches issuer hash: %w", err)
	}

	// 3. 在 CA 下按 serial 查询证书元数据。
	state, reason, revokedAt, err := c.classifyCertState(ctx, caMeta.KeyID, req.SerialNumber)
	if err != nil {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "error", err.Error())
		return nil, err
	}

	// 4. 取出 CA 私钥 → SecureSigner，签名响应。
	signer, err := c.extractSigner(ctx, caMeta, caMeta.KeyType)
	if err != nil {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "error", "extract signer: "+err.Error())
		return nil, fmt.Errorf("service: extract CA signer: %w", err)
	}
	defer signer.Dispose()

	// 5. 签发响应（SM2 走手工 ASN.1 路径，其他走 stdlib）。
	respDER, err := signOCSPResponse(caMeta, caCert, signer, reqDER, req.SerialNumber, state, revokedAt, reason)
	if err != nil {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "error", "sign: "+err.Error())
		return nil, fmt.Errorf("service: sign OCSP response: %w", err)
	}

	if state == lifecycle.CertStateRevoked {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "ok", "revoked")
	} else if state == lifecycle.CertStateUnknown {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "ok", "unknown serial")
	} else {
		c.recordAudit(ctx, "OCSPQuery", caMeta.KeyID, 0, "ok", "good")
	}
	return respDER, nil
}

// findCAMatch 遍历所有 CA，匹配 issuerNameHash / issuerKeyHash。
//
// 返回：匹配的 CA 元数据 + 已解析的 *x509.Certificate。
func (c *Core) findCAMatch(ctx context.Context, issuerNameHash, issuerKeyHash []byte) (*lifecycle.KeyMetadata, *x509.Certificate, error) {
	keyIDs, err := c.manager.ListKeyIDs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list key IDs: %w", err)
	}
	for _, keyID := range keyIDs {
		caMeta, caCert, found, err := c.matchCertByIssuerHash(ctx, keyID, issuerNameHash, issuerKeyHash)
		if err != nil {
			continue
		}
		if found {
			return caMeta, caCert, nil
		}
	}
	return nil, nil, errors.New("no matching CA found")
}

// matchCertByIssuerHash 在指定 CA key 下查找与 issuer hash 匹配的 CA 证书。
func (c *Core) matchCertByIssuerHash(ctx context.Context, caKeyID string, issuerNameHash, issuerKeyHash []byte) (*lifecycle.KeyMetadata, *x509.Certificate, bool, error) {
	certs, err := c.certManager.ListByCA(ctx, caKeyID)
	if err != nil {
		return nil, nil, false, err
	}
	for _, cm := range certs {
		if cm.CertType != "ca" {
			continue
		}
		caCert, err := crypto.ParseCertificatePEM(cm.PEM)
		if err != nil || caCert == nil {
			continue
		}
		nameHash := sha1.Sum(caCert.RawSubject)              //nolint:gosec
		keyHash := sha1.Sum(caCert.RawSubjectPublicKeyInfo) //nolint:gosec
		if subtle.ConstantTimeCompare(nameHash[:], issuerNameHash) == 1 &&
			subtle.ConstantTimeCompare(keyHash[:], issuerKeyHash) == 1 {
			caMeta, err := c.manager.GetActiveKey(ctx, caKeyID)
			if err != nil {
				return nil, nil, false, err
			}
			return caMeta, caCert, true, nil
		}
	}
	return nil, nil, false, nil
}

// classifyCertState 在指定 CA 下按 serial 查证书元数据。
//
// 返回：
//   - state：lifecycle.CertState
//   - reason：仅 Revoked 有意义（int）
//   - revokedAt：仅 Revoked 有意义（time.Time）
func (c *Core) classifyCertState(ctx context.Context, caKeyID string, serial *big.Int) (lifecycle.CertState, int, time.Time, error) {
	meta, err := c.certManager.FindBySerial(ctx, caKeyID, serial)
	if err != nil {
		// 未命中 → Unknown（OCSP 协议层"未签发过"语义）
		return lifecycle.CertStateUnknown, 0, time.Time{}, nil
	}
	if meta.State == lifecycle.CertStateRevoked {
		return lifecycle.CertStateRevoked, mapReasonToInt(meta.RevokedReason), meta.RevokedAt, nil
	}
	return lifecycle.CertStateActive, 0, time.Time{}, nil
}

// signOCSPResponse 根据 CA 类型走对应签发路径（SM2 走手工 ASN.1）。
func signOCSPResponse(caMeta *lifecycle.KeyMetadata, caCert *x509.Certificate, signer *crypto.SecureSigner, reqDER []byte, serial *big.Int, state lifecycle.CertState, revokedAt time.Time, reason int) ([]byte, error) {
	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(time.Duration(ocspDefaultValiditySeconds) * time.Second)

	// SM2 走手工 ASN.1 路径（stdocsp.CreateResponse 走 SHA-1/RSA/ECDSA，SM2 不兼容）。
	if subtle.ConstantTimeCompare([]byte(caMeta.KeyType), []byte(crypto.KeyTypeSM2)) == 1 {
		// SM2 路径直接传 caCert.Raw（DER），让 CreateSM2OCSPResponse 自包装 envelope。
		return crypto.CreateSM2OCSPResponse(reqDER, caCert.Raw, signer, ocspStatusFromState(state), revokedAt, reason, thisUpdate, nextUpdate)
	}

	// RSA/ECDSA 走 stdlib 路径。
	return crypto.CreateOCSPResponse(reqDER, caCert, signer, ocspStatusFromState(state), revokedAt, reason, thisUpdate, nextUpdate)
}

// ocspStatusFromState 把 CertState 映射到 OCSPStatusInt。
func ocspStatusFromState(state lifecycle.CertState) int {
	switch state {
	case lifecycle.CertStateRevoked:
		return crypto.OCSPStatusRevoked
	case lifecycle.CertStateUnknown:
		return crypto.OCSPStatusUnknown
	default:
		return crypto.OCSPStatusGood
	}
}

// mapReasonToInt 把 string reason 映射为 OCSP reason int（RFC 6960 §4.2.2.1）。
func mapReasonToInt(reason string) int {
	switch reason {
	case "keyCompromise", "key compromise":
		return 1 // KeyCompromise
	case "caCompromise", "ca compromise":
		return 2
	case "affiliationChanged", "affiliation changed":
		return 3
	case "superseded":
		return 4
	case "cessationOfOperation", "cessation of operation":
		return 5
	case "certificateHold", "certificate hold":
		return 6
	case "privilegeWithdrawn", "privilege withdrawn":
		return 7
	case "aACompromise", "aa compromise":
		return 8
	default:
		return 0 // unspecified
	}
}

// 引用 stdocsp 仅为未来扩展（x/crypto/ocsp 无 nonce，但响应解析需要）。
var _ = stdocsp.Revoked