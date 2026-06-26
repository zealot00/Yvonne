// Package mcp — Yvonne KMS MCP（Model Context Protocol）server。
//
// 仅暴露 Encrypt + 受限 Decrypt 两个 Tool，供 AI agent 安全调用。
// 鉴权：独立 mcp_token（ConstantTimeCompare）。
// Decrypt 强约束：AllowedKeys 白名单 + 全量审计 + Sealed 拒绝。
// 传输：stdio + Streamable HTTP。
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/service"
)

// Config 是 MCP server 配置。
type Config struct {
	Token       string   // MCP 专用 token（必填）
	AllowedKeys []string // Decrypt 白名单（空=拒绝所有 Decrypt）
}

// Server 是 Yvonne MCP server，包装 mcp.Server。
type Server struct {
	core   *service.Core
	config Config
	server *mcp.Server
}

// NewServer 创建 MCP server。
func NewServer(core *service.Core, cfg Config) *Server {
	s := &Server{
		core:   core,
		config: cfg,
	}
	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "yvonne-kms",
		Version: "0.4.0",
	}, nil)

	s.registerTools()
	return s
}

// registerTools 注册 yvonne_encrypt + yvonne_decrypt。
func (s *Server) registerTools() {
	// yvonne_encrypt
	type encryptArgs struct {
		KeyID     string `json:"key_id" jsonschema:"the key ID to encrypt with"`
		Plaintext string `json:"plaintext" jsonschema:"base64-encoded plaintext"`
	}
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "yvonne_encrypt",
		Description: "Encrypt data using Yvonne KMS. Returns base64 ciphertext + version.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args encryptArgs) (*mcp.CallToolResult, any, error) {
		if !s.authenticate(req) {
			return errorResult("unauthorized: invalid or missing mcp token"), nil, nil
		}

		plaintext, err := base64.StdEncoding.DecodeString(args.Plaintext)
		if err != nil {
			return errorResult("invalid base64 plaintext"), nil, nil
		}

		// MCP 用固定 Policy（受限角色）。
		policy := &auth.Policy{
			RoleID:         "mcp-agent",
			AllowedKeys:    s.config.AllowedKeys,
			AllowedActions: []string{"Encrypt"},
		}
		result, err := s.core.Encrypt(ctx, args.KeyID, plaintext, policy)
		if err != nil {
			return errorResult("encrypt failed: " + err.Error()), nil, nil
		}

		ctB64 := base64.StdEncoding.EncodeToString(result.Ciphertext)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: ctB64},
			},
		}, nil, nil
	})

	// yvonne_decrypt
	type decryptArgs struct {
		KeyID      string `json:"key_id" jsonschema:"the key ID to decrypt with"`
		Ciphertext string `json:"ciphertext" jsonschema:"base64-encoded ciphertext"`
	}
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "yvonne_decrypt",
		Description: "Decrypt data using Yvonne KMS. Subject to key whitelist.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args decryptArgs) (*mcp.CallToolResult, any, error) {
		if !s.authenticate(req) {
			return errorResult("unauthorized: invalid or missing mcp token"), nil, nil
		}

		// 白名单检查（强制）。
		if !s.isKeyAllowed(args.KeyID) {
			return errorResult("key not in MCP whitelist"), nil, nil
		}

		ciphertext, err := base64.StdEncoding.DecodeString(args.Ciphertext)
		if err != nil {
			return errorResult("invalid base64 ciphertext"), nil, nil
		}

		policy := &auth.Policy{
			RoleID:         "mcp-agent",
			AllowedKeys:    s.config.AllowedKeys,
			AllowedActions: []string{"Decrypt"},
		}
		result, err := s.core.Decrypt(ctx, args.KeyID, ciphertext, policy)
		if err != nil {
			return errorResult("decrypt failed: " + err.Error()), nil, nil
		}
		defer result.Plaintext.Wipe()

		var plainB64 string
		_ = result.Plaintext.WithKey(func(d []byte) error {
			plainB64 = base64.StdEncoding.EncodeToString(d)
			return nil
		})

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: plainB64},
			},
		}, nil, nil
	})
}

// authenticate 验证 MCP token。
// token 通过 CallToolRequest 的 Meta 字段传递（key: "mcp_token"）。
func (s *Server) authenticate(req *mcp.CallToolRequest) bool {
	if s.config.Token == "" {
		return false // 未配置 token 则拒绝
	}
	// 从 Meta 提取 token。
	meta := req.Params.Meta
	if meta == nil {
		return false
	}
	tokenVal, ok := meta["mcp_token"]
	if !ok {
		return false
	}
	tokenStr, ok := tokenVal.(string)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tokenStr), []byte(s.config.Token)) == 1
}

// isKeyAllowed 检查 keyID 是否在白名单中。
func (s *Server) isKeyAllowed(keyID string) bool {
	for _, k := range s.config.AllowedKeys {
		if k == keyID || k == "*" {
			return true
		}
	}
	return false
}

// errorResult 返回错误文本 Content。
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "ERROR: " + msg},
		},
		IsError: true,
	}
}

// ServeStdio 在 stdio 上运行 MCP server（AI agent 子进程模式）。
func (s *Server) ServeStdio(ctx context.Context) error {
	log.Printf("MCP server: starting stdio transport")
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

// HTTPHandler 返回 Streamable HTTP handler（路径 /mcp）。
func (s *Server) HTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.server
	}, nil)
}

// 确保 audit 包被引用（审计由 Core 内部处理）。
var _ = audit.LogEntry{}

// 确保 os 包被引用（stdio 需要 os.Stdin/Stdout，由 StdioTransport 内部使用）。
var _ = os.Stdin
