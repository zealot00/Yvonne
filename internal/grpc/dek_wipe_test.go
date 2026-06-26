package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "yvonne/gen/proto/yvonne/v1"
	"yvonne/internal/seal"
)

// TestGRPC_CreateKey_DEKNotZeroed 验证 CreateKey 返回的 DEK 非全零。
// 若 defer clear 过早执行，客户端会收到全零 DEK。
func TestGRPC_CreateKey_DEKNotZeroed(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	_ = grpcSrv
	conn, _ := grpc.NewClient(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	// 用 manager 直接创建 key（绕过 gRPC），让 CreateKey gRPC 能用。
	_ = mgr
	_ = mk

	resp, err := client.CreateKey(ctx, &pb.CreateKeyRequest{
		KeyId:     "dek-test-key",
		ReturnDek: true,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if len(resp.PlaintextDek) != 32 {
		t.Fatalf("DEK length = %d, want 32", len(resp.PlaintextDek))
	}

	// 检查是否全零（defer clear 过早执行的标志）。
	allZero := true
	for _, b := range resp.PlaintextDek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("CreateKey returned all-zero DEK — defer clear executed before serialization")
	}

	t.Logf("DEK first 4 bytes: %x (non-zero = correct)", resp.PlaintextDek[:4])
}

// TestGRPC_RotateKey_DEKNotZeroed 验证 RotateKey 返回的 DEK 非全零。
func TestGRPC_RotateKey_DEKNotZeroed(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	// 先创建 key。
	mgr.CreateKey(ctx, "rotate-dek-key", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := grpc.NewClient(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	resp, err := client.RotateKey(ctx, &pb.RotateKeyRequest{
		KeyId:   "rotate-dek-key",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if len(resp.PlaintextDek) != 32 {
		t.Fatalf("DEK length = %d, want 32", len(resp.PlaintextDek))
	}

	allZero := true
	for _, b := range resp.PlaintextDek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("RotateKey returned all-zero DEK")
	}
}

// TestGRPC_GenerateDataKey_DEKNotZeroed 验证 GDK 返回的 DEK 非全零。
func TestGRPC_GenerateDataKey_DEKNotZeroed(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	mgr.CreateKey(ctx, "gdk-dek-key", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := grpc.NewClient(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	resp, err := client.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{
		KeyId: "gdk-dek-key",
	})
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}

	if len(resp.PlaintextDek) != 32 {
		t.Fatalf("DEK length = %d, want 32", len(resp.PlaintextDek))
	}

	allZero := true
	for _, b := range resp.PlaintextDek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("GenerateDataKey returned all-zero DEK")
	}
}
