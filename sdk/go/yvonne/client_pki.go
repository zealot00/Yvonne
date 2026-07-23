// Package yvonne - PKI API 方法（v1.4.0）。
package yvonne

import (
	"context"
	"fmt"
	"net/http"
)

// === PKI API 方法 ===

// CreateCA 创建 CA（自签根证书）。
// algo: "rsa" / "ecdsa" / "sm2"。subject 如 "CN=Root CA"。ttlYears 为 0 时默认 10。
func (c *Client) CreateCA(ctx context.Context, req *CreateCARequest) (*CreateCAResponse, error) {
	var resp struct {
		OK   bool             `json:"ok"`
		Data CreateCAResponse `json:"data"`
		Err  string           `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/pki/ca", req, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// IssueCert 用 CA 签发终端证书。
// certType: "sign" / "encrypt" / "dual"（国密双证书）。
func (c *Client) IssueCert(ctx context.Context, req *IssueCertRequest) (*IssueCertResponse, error) {
	var resp struct {
		OK   bool              `json:"ok"`
		Data IssueCertResponse `json:"data"`
		Err  string            `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/pki/issue", req, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// VerifyCert 验证证书链。
// caCertPEM 可为 nil（此时仅验证自签或从系统信任库）。
func (c *Client) VerifyCert(ctx context.Context, req *VerifyCertRequest) (*VerifyCertResponse, error) {
	var resp struct {
		OK   bool               `json:"ok"`
		Data VerifyCertResponse `json:"data"`
		Err  string             `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/pki/verify", req, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// GetCert 获取证书元数据与 PEM。
func (c *Client) GetCert(ctx context.Context, certID string) (*GetCertResponse, error) {
	var resp struct {
		OK   bool            `json:"ok"`
		Data GetCertResponse `json:"data"`
		Err  string          `json:"error"`
	}
	if err := c.get(ctx, "/api/v1/pki/cert/"+certID, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// RevokeCert 吊销证书（同时刷新 CRL）。
func (c *Client) RevokeCert(ctx context.Context, req *RevokeCertRequest) error {
	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			Revoked bool `json:"revoked"`
		} `json:"data"`
		Err string `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/pki/revoke", req, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("yvonne: %s", resp.Err)
	}
	return nil
}

// GetCRL 获取 CA 的当前 CRL（DER 格式）。
func (c *Client) GetCRL(ctx context.Context, caKeyID string) ([]byte, error) {
	var resp struct {
		OK   bool           `json:"ok"`
		Data GetCRLResponse `json:"data"`
		Err  string         `json:"error"`
	}
	if err := c.get(ctx, "/api/v1/pki/ca/"+caKeyID+"/crl", &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return resp.Data.CRL, nil
}

// 确保 net/http 被引用（Get 方法间接使用）。
var _ = http.MethodGet
