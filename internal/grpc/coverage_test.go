// Package grpc - 补充覆盖测试（Unseal + ImportKey + AuditQuery + wipingCodec Name）。
package grpc

import (
	"context"
	"testing"

	pb "yvonne/gen/proto/yvonne/v1"
)

// TestGRPC_Unseal gRPC Unseal 端点（sealed 状态下调用）。
func TestGRPC_Unseal(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	// EmergencySeal 让 vault 进入 sealed。
	core.SetAdminToken("test")
	grpcSrv := startTestServer(t, core, nil)
	client := newAuthClient(t, grpcSrv, "")

	// EmergencySeal。
	client.EmergencySeal(ctx, &pb.EmergencySealRequest{AdminToken: "test", Confirm: true})

	// Unseal（空 shares → error）。
	_, err := client.Unseal(ctx, &pb.UnsealRequest{Shares: nil})
	if err == nil {
		t.Fatal("should fail with empty shares")
	}
	t.Logf("✅ gRPC Unseal empty shares: %v", err)
}

// TestGRPC_ImportKey gRPC ImportKey 端点。
func TestGRPC_ImportKey(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	grpcSrv := startTestServer(t, core, nil)
	client := newAuthClient(t, grpcSrv, "")

	// ImportKey 空参数 → error。
	_, err := client.ImportKey(ctx, &pb.ImportKeyRequest{})
	if err == nil {
		t.Fatal("should fail with empty params")
	}
	t.Logf("✅ gRPC ImportKey empty: %v", err)
}

// TestGRPC_AuditQuery gRPC AuditQuery 端点。
func TestGRPC_AuditQuery(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	grpcSrv := startTestServer(t, core, nil)
	client := newAuthClient(t, grpcSrv, "")

	// AuditQuery 无配置 → error。
	_, err := client.AuditQuery(ctx, &pb.AuditQueryRequest{Limit: 10})
	if err == nil {
		t.Fatal("should fail without audit config")
	}
	t.Logf("✅ gRPC AuditQuery: %v", err)
}

// TestWipingCodec_Name wipingCodec Name 方法。
func TestWipingCodec_Name(t *testing.T) {
	codec := &wipingCodec{}
	if codec.Name() != "proto" {
		t.Fatalf("name = %s, want proto", codec.Name())
	}
	t.Log("✅ wipingCodec.Name() = proto")
}
