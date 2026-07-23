// Package yvonne - SDF API 方法（v1.4.0，GM/T 0018-2023 软件密码机）。
//
// 二进制数据（密钥/密文/签名/哈希）在 SDK 层做 hex 编解码，
// 调用方传入/接收 []byte，无需关心 hex 细节。
package yvonne

import (
	"context"
	"encoding/hex"
	"fmt"
)

// === SDF API 方法 ===

// SDFDeviceInfo 获取 SDF 设备信息。
func (c *Client) SDFDeviceInfo(ctx context.Context) (*SDFDeviceInfoResponse, error) {
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFDeviceInfoResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/device/info", map[string]interface{}{}, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// SDFRandom 生成随机数（length 字节，1-65536）。
func (c *Client) SDFRandom(ctx context.Context, length int) ([]byte, error) {
	body := map[string]interface{}{"length": length}
	var resp struct {
		OK   bool              `json:"ok"`
		Data SDFRandomResponse `json:"data"`
		Err  string            `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/random", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Random)
}

// SDFSM2GenerateKeyPair 生成 SM2 密钥对（返回 PEM 编码公私钥）。
func (c *Client) SDFSM2GenerateKeyPair(ctx context.Context) (pubKeyPEM, privKeyPEM string, err error) {
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFSM2KeyPairResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm2/generate", map[string]interface{}{}, &resp); err != nil {
		return "", "", err
	}
	if !resp.OK {
		return "", "", fmt.Errorf("yvonne: %s", resp.Err)
	}
	return resp.Data.PublicKey, resp.Data.PrivateKey, nil
}

// SDFSM2Sign SM2 签名。privKeyPEM 为 PEM 编码私钥，data 为原始数据。
// 返回签名 []byte。
func (c *Client) SDFSM2Sign(ctx context.Context, privKeyPEM string, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"private_key": privKeyPEM,
		"data":        hex.EncodeToString(data),
	}
	var resp struct {
		OK   bool               `json:"ok"`
		Data SDFSM2SignResponse `json:"data"`
		Err  string             `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm2/sign", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Signature)
}

// SDFSM2Verify SM2 验签。pubKeyPEM 为 PEM 编码公钥。
func (c *Client) SDFSM2Verify(ctx context.Context, pubKeyPEM string, data, signature []byte) (bool, error) {
	body := map[string]interface{}{
		"public_key": pubKeyPEM,
		"data":       hex.EncodeToString(data),
		"signature":  hex.EncodeToString(signature),
	}
	var resp struct {
		OK   bool                 `json:"ok"`
		Data SDFSM2VerifyResponse `json:"data"`
		Err  string               `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm2/verify", body, &resp); err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return resp.Data.Valid, nil
}

// SDFSM2Encrypt SM2 加密。pubKeyPEM 为 PEM 编码公钥。
func (c *Client) SDFSM2Encrypt(ctx context.Context, pubKeyPEM string, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"public_key": pubKeyPEM,
		"data":       hex.EncodeToString(data),
	}
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFSM2EncryptResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm2/encrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Ciphertext)
}

// SDFSM2Decrypt SM2 解密。privKeyPEM 为 PEM 编码私钥。
func (c *Client) SDFSM2Decrypt(ctx context.Context, privKeyPEM string, ciphertext []byte) ([]byte, error) {
	body := map[string]interface{}{
		"private_key": privKeyPEM,
		"ciphertext":  hex.EncodeToString(ciphertext),
	}
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFSM2DecryptResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm2/decrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Plaintext)
}

// SDFSM3Hash SM3 哈希。
func (c *Client) SDFSM3Hash(ctx context.Context, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"data": hex.EncodeToString(data),
	}
	var resp struct {
		OK   bool               `json:"ok"`
		Data SDFSM3HashResponse `json:"data"`
		Err  string             `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm3/hash", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Hash)
}

// SDFSM4Encrypt SM4 对称加密。key 为 16 字节 SM4 密钥。
func (c *Client) SDFSM4Encrypt(ctx context.Context, key, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"key":  hex.EncodeToString(key),
		"data": hex.EncodeToString(data),
	}
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFSM4EncryptResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm4/encrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Ciphertext)
}

// SDFSM4Decrypt SM4 对称解密。key 为 16 字节 SM4 密钥。
func (c *Client) SDFSM4Decrypt(ctx context.Context, key, ciphertext []byte) ([]byte, error) {
	body := map[string]interface{}{
		"key":        hex.EncodeToString(key),
		"ciphertext": hex.EncodeToString(ciphertext),
	}
	var resp struct {
		OK   bool                  `json:"ok"`
		Data SDFSM4DecryptResponse `json:"data"`
		Err  string                `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/sdf/sm4/decrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return hex.DecodeString(resp.Data.Plaintext)
}
