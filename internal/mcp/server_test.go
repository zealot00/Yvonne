package mcp

import (
	"bytes"
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"yvonne/internal/audit"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/service"
	"yvonne/internal/storage"
)

// newTestServer 创建测试 MCP server。
func newTestServer(t *testing.T, allowedKeys []string) (*Server, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	vault := seal.NewVaultState(1, 1, 0)
	if err := vault.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)

	var buf bytes.Buffer
	auditLog, _ := audit.NewAuditLogger(&buf)
	t.Cleanup(auditLog.Close)

	core := service.NewManager(mgr, vault, auditLog)
	srv := NewServer(core, Config{
		Token:       "test-mcp-token",
		AllowedKeys: allowedKeys,
	})
	return srv, mgr, mk
}

// TestMCP_AuthenticateWrongToken 错误 token 被拒。
func TestMCP_AuthenticateWrongToken(t *testing.T) {
	srv, mgr, mk := newTestServer(t, []string{"test-key"})
	ctx := context.Background()
	mgr.CreateKey(ctx, "test-key", seal.NewSoftwareKEK(mk), 0)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "yvonne_encrypt",
			Arguments: nil,
			Meta: mcp.Meta{
				"mcp_token": "wrong-token",
			},
		},
	}

	_ = req
	if srv.authenticate(req) {
		t.Fatal("wrong token should not authenticate")
	}
}

// TestMCP_AuthenticateCorrectToken 正确 token 通过。
func TestMCP_AuthenticateCorrectToken(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"test-key"})

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Meta: mcp.Meta{
				"mcp_token": "test-mcp-token",
			},
		},
	}

	if !srv.authenticate(req) {
		t.Fatal("correct token should authenticate")
	}
}

// TestMCP_AuthenticateNoToken 无 token 被拒。
func TestMCP_AuthenticateNoToken(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"test-key"})

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{},
	}

	if srv.authenticate(req) {
		t.Fatal("no token should not authenticate")
	}
}

// TestMCP_KeyWhitelist 白名单检查。
func TestMCP_KeyWhitelist(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"allowed-key"})

	if !srv.isKeyAllowed("allowed-key") {
		t.Fatal("allowed-key should be allowed")
	}
	if srv.isKeyAllowed("denied-key") {
		t.Fatal("denied-key should not be allowed")
	}
}

// TestMCP_KeyWhitelistWildcard 通配符。
func TestMCP_KeyWhitelistWildcard(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"*"})

	if !srv.isKeyAllowed("any-key") {
		t.Fatal("wildcard should allow any key")
	}
}

// TestMCP_HTTPHandler 返回非 nil handler。
func TestMCP_HTTPHandler(t *testing.T) {
	srv, _, _ := newTestServer(t, []string{"test-key"})
	h := srv.HTTPHandler()
	if h == nil {
		t.Fatal("HTTPHandler should not be nil")
	}
}
