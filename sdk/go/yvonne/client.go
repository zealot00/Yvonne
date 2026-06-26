// Package yvonne - Go SDK for Yvonne KMS.
//
// 提供 Yvonne KMS HTTP API 的类型安全客户端封装。
//
// 快速开始：
//
//	client := yvonne.New("http://127.0.0.1:8400", "your-token")
//	resp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
//	    KeyID:     "order-key",
//	    Plaintext: []byte("secret"),
//	})
//	// resp.Ciphertext, resp.Version
package yvonne

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client 是 Yvonne KMS 客户端。
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New 创建客户端。baseURL 不含尾斜杠（如 http://127.0.0.1:8400）。
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewWithHTTP 创建客户端（自定义 http.Client）。
func NewWithHTTP(baseURL, token string, httpClient *http.Client) *Client {
	c := New(baseURL, token)
	c.http = httpClient
	return c
}

// === 请求/响应结构 ===

// HealthResponse 健康检查响应。
type HealthResponse struct {
	Status string `json:"status"`
	Sealed bool   `json:"sealed"`
	State  string `json:"state"`
}

// CreateKeyRequest 创建密钥请求。
type CreateKeyRequest struct {
	KeyID     string `json:"key_id"`
	ReturnDEK *bool  `json:"return_dek,omitempty"`
}

// CreateKeyResponse 创建密钥响应。
type CreateKeyResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	PlaintextDEK []byte `json:"plaintext_dek"`
}

// RotateKeyResponse 轮转密钥响应。
type RotateKeyResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	PlaintextDEK []byte `json:"plaintext_dek"`
}

// EncryptRequest 加密请求。
type EncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"` // 原始明文，SDK 内部 base64 编码
}

// EncryptResponse 加密响应。
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"` // 版本化密文
	Version    int    `json:"version"`
}

// DecryptRequest 解密请求。
type DecryptRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"` // 版本化密文
}

// DecryptResponse 解密响应。
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
	Version   int    `json:"version"`
}

// GenerateDataKeyResponse GDK 响应。
type GenerateDataKeyResponse struct {
	PlaintextDEK  []byte `json:"plaintext_dek"`
	CiphertextDEK []byte `json:"ciphertext_dek"`
}

// === API 方法 ===

// Health 健康检查（无需认证）。
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.get(ctx, "/api/v1/sys/health", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateKey 创建密钥。
func (c *Client) CreateKey(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	var resp struct {
		OK   bool              `json:"ok"`
		Data CreateKeyResponse `json:"data"`
		Err  string            `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/keys", req, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// RotateKey 轮转密钥。
func (c *Client) RotateKey(ctx context.Context, keyID string) (*RotateKeyResponse, error) {
	var resp struct {
		OK   bool              `json:"ok"`
		Data RotateKeyResponse `json:"data"`
		Err  string            `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/keys/"+keyID+"/rotate", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// ShredKey 物理粉碎密钥版本。
func (c *Client) ShredKey(ctx context.Context, keyID string, version int) error {
	body := map[string]interface{}{"version": version}
	var resp struct {
		OK  bool   `json:"ok"`
		Err string `json:"error"`
	}
	if err := c.do(ctx, http.MethodDelete, "/api/v1/keys/"+keyID+"/shred", body, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("yvonne: %s", resp.Err)
	}
	return nil
}

// Encrypt 加密。plaintext 为原始明文，SDK 自动 base64 编码。
func (c *Client) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	body := map[string]interface{}{
		"key_id":    req.KeyID,
		"plaintext": base64.StdEncoding.EncodeToString(req.Plaintext),
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Data EncryptResponse `json:"data"`
		Err  string          `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/encrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	// Ciphertext 和 Plaintext 在 JSON 中是 base64 []byte，Go json 会自动解码。
	return &resp.Data, nil
}

// Decrypt 解密。ciphertext 为版本化密文。
func (c *Client) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	body := map[string]interface{}{
		"key_id":     req.KeyID,
		"ciphertext": base64.StdEncoding.EncodeToString(req.Ciphertext),
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Data DecryptResponse `json:"data"`
		Err  string          `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/decrypt", body, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// GenerateDataKey 生成数据密钥（客户端信封加密用）。
func (c *Client) GenerateDataKey(ctx context.Context, keyID string) (*GenerateDataKeyResponse, error) {
	var resp struct {
		OK   bool                    `json:"ok"`
		Data GenerateDataKeyResponse `json:"data"`
		Err  string                  `json:"error"`
	}
	if err := c.post(ctx, "/api/v1/keys/"+keyID+"/generate-data-key", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("yvonne: %s", resp.Err)
	}
	return &resp.Data, nil
}

// === 内部 HTTP 辅助 ===

// envelope 是 Yvonne 的统一响应包装。
type envelope struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data,omitempty"`
	Err  string          `json:"error,omitempty"`
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, out interface{}) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("yvonne: marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("yvonne: new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("yvonne: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp envelope
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Err != "" {
			return fmt.Errorf("yvonne: HTTP %d: %s", resp.StatusCode, errResp.Err)
		}
		return fmt.Errorf("yvonne: HTTP %d", resp.StatusCode)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("yvonne: decode response: %w", err)
		}
	}
	return nil
}
