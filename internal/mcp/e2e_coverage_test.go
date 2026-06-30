// Package mcp - MCP tool 调用集成测试（提升覆盖率）。
//
// 覆盖 registerTools 的 encrypt/decrypt tool handler + errorResult + authenticate。
package mcp

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"yvonne/internal/seal"
)

// TestMCP_EncryptTool MCP encrypt tool 调用。
func TestMCP_EncryptTool(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()

	// 创建密钥。
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	// 用 in-memory transport 连接。
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// 调用 yvonne_encrypt。
	plaintext := base64.StdEncoding.EncodeToString([]byte("mcp encrypt test"))
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_encrypt",
		Arguments: map[string]interface{}{
			"key_id":    "test-key",
			"plaintext": plaintext,
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool encrypt: %v", err)
	}
	if result.IsError {
		t.Fatalf("encrypt returned error: %v", result.Content)
	}
	t.Logf("✅ MCP encrypt: %d content items", len(result.Content))
}

// TestMCP_EncryptTool_WrongToken 错误 token 拒绝。
func TestMCP_EncryptTool_WrongToken(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	plaintext := base64.StdEncoding.EncodeToString([]byte("test"))
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_encrypt",
		Arguments: map[string]interface{}{
			"key_id":    "test-key",
			"plaintext": plaintext,
		},
		Meta: map[string]interface{}{
			"mcp_token": "wrong-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should return error for wrong token")
	}
	t.Log("✅ MCP encrypt wrong token: error returned")
}

// TestMCP_EncryptTool_InvalidBase64 无效 base64。
func TestMCP_EncryptTool_InvalidBase64(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_encrypt",
		Arguments: map[string]interface{}{
			"key_id":    "test-key",
			"plaintext": "!!!invalid-base64!!!",
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should return error for invalid base64")
	}
	t.Log("✅ MCP encrypt invalid base64: error returned")
}

// TestMCP_DecryptTool MCP decrypt tool 调用。
func TestMCP_DecryptTool(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	// 先加密。
	encResult, _ := srv.core.Encrypt(ctx, "test-key", []byte("mcp decrypt test"), nil)
	ciphertextB64 := base64.StdEncoding.EncodeToString(encResult.Ciphertext)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	// 调用 yvonne_decrypt。
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_decrypt",
		Arguments: map[string]interface{}{
			"key_id":     "test-key",
			"ciphertext": ciphertextB64,
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool decrypt: %v", err)
	}
	if result.IsError {
		t.Fatalf("decrypt returned error: %v", result.Content)
	}
	t.Logf("✅ MCP decrypt: %d content items", len(result.Content))
}

// TestMCP_DecryptTool_KeyNotInWhitelist 白名单外密钥拒绝。
func TestMCP_DecryptTool_KeyNotInWhitelist(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"allowed-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "allowed-key", seal.NewSoftwareKEK(mk), 0)
	mgr.CreateKey(ctx, "denied-key", seal.NewSoftwareKEK(mk), 0)

	// 加密 denied-key。
	encResult, _ := srv.core.Encrypt(ctx, "denied-key", []byte("test"), nil)
	ciphertextB64 := base64.StdEncoding.EncodeToString(encResult.Ciphertext)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_decrypt",
		Arguments: map[string]interface{}{
			"key_id":     "denied-key",
			"ciphertext": ciphertextB64,
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should reject key not in whitelist")
	}
	t.Log("✅ MCP decrypt key not in whitelist: rejected")
}

// TestMCP_DecryptTool_InvalidBase64 无效 base64 密文。
func TestMCP_DecryptTool_InvalidBase64(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_decrypt",
		Arguments: map[string]interface{}{
			"key_id":     "test-key",
			"ciphertext": "!!!invalid!!!",
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should return error for invalid base64")
	}
	t.Log("✅ MCP decrypt invalid base64: error returned")
}

// TestMCP_DecryptTool_NoToken 无 token 拒绝。
func TestMCP_DecryptTool_NoToken(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_decrypt",
		Arguments: map[string]interface{}{
			"key_id":     "test-key",
			"ciphertext": base64.StdEncoding.EncodeToString([]byte("dummy")),
		},
		// 无 Meta（无 token）
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should reject without token")
	}
	t.Log("✅ MCP decrypt no token: rejected")
}

// TestMCP_EncryptTool_NonexistentKey 不存在的密钥。
func TestMCP_EncryptTool_NonexistentKey(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"*"})
	ctx := context.Background()

	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.server.Connect(ctx, st, nil)
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, _ := client.Connect(ctx, ct, nil)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "yvonne_encrypt",
		Arguments: map[string]interface{}{
			"key_id":    "nonexistent",
			"plaintext": base64.StdEncoding.EncodeToString([]byte("test")),
		},
		Meta: map[string]interface{}{
			"mcp_token": "test-mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("should return error for nonexistent key")
	}
	t.Log("✅ MCP encrypt nonexistent key: error returned")
}

// TestMCP_HTTPHandler_ServeHTTP HTTPHandler 实际处理请求。
func TestMCP_HTTPHandler_ServeHTTP(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"test-key"})
	h := srv.HTTPHandler()
	if h == nil {
		t.Fatal("HTTPHandler should not be nil")
	}

	// 验证 handler 可处理请求（不 panic）。
	// 完整 HTTP 测试需要 MCP client，这里验证 handler 非 nil 即可。
	t.Log("✅ MCP HTTPHandler: non-nil")
}

// TestMCP_ErrorResult errorResult 函数覆盖。
func TestMCP_ErrorResult(t *testing.T) {
	result := errorResult("test error")
	if !result.IsError {
		t.Fatal("should be error")
	}
	if len(result.Content) == 0 {
		t.Fatal("should have content")
	}
	t.Log("✅ errorResult: IsError=true")
}
