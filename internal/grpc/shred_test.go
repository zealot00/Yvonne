package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "yvonne/gen/proto/yvonne/v1"
	"yvonne/internal/lifecycle"
	"yvonne/internal/seal"
	"yvonne/internal/service"
	"yvonne/internal/storage"
)

// TestGRPC_ShredKey_Success gRPC 粉碎密钥成功。
func TestGRPC_ShredKey_Success(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "grpc-shred-key", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	resp, err := client.ShredKey(ctx, &pb.ShredKeyRequest{
		KeyId:   "grpc-shred-key",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("ShredKey: %v", err)
	}
	if !resp.Destroyed {
		t.Fatal("should be destroyed")
	}

	// 验证已删除。
	_, err = mgr.GetKey(ctx, "grpc-shred-key", 1)
	if err == nil {
		t.Fatal("key should be destroyed in DB")
	}
	t.Log("✅ gRPC ShredKey success + verified in DB")
}

// TestGRPC_ShredKey_NotFound gRPC 粉碎不存在的密钥。
func TestGRPC_ShredKey_NotFound(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	_, err := client.ShredKey(ctx, &pb.ShredKeyRequest{
		KeyId:   "nonexistent",
		Version: 1,
	})
	if err == nil {
		t.Fatal("should fail for nonexistent key")
	}

	// gRPC 应返回错误码。
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("should be gRPC status error: %v", err)
	}
	if st.Code() == codes.OK {
		t.Fatal("should not be OK")
	}
	t.Logf("✅ gRPC ShredKey correctly returned error: %s", st.Code())
}

// TestGRPC_SoftDeleteAndRestore gRPC 软删除 + 恢复。
func TestGRPC_SoftDeleteAndRestore(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "grpc-softdel", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	// 软删除。
	_, err := client.SoftDeleteKey(ctx, &pb.SoftDeleteKeyRequest{
		KeyId:   "grpc-softdel",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("SoftDeleteKey: %v", err)
	}
	t.Log("✅ gRPC SoftDeleteKey success")

	// 恢复。
	_, err = client.RestoreKey(ctx, &pb.RestoreKeyRequest{
		KeyId:   "grpc-softdel",
		Version: 1,
	})
	if err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}
	t.Log("✅ gRPC RestoreKey success")
}

// TestGRPC_ShredKey_SealedRefused sealed 状态拒绝。
func TestGRPC_ShredKey_SealedRefused(t *testing.T) {
	// 用 sealed vault 创建 core。
	vault := seal.NewVaultState(5, 3, 0) // sealed（未 unseal）

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	core := service.NewCore(mgr, vault, nil)

	testVault = vault
	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	_, err := client.ShredKey(context.Background(), &pb.ShredKeyRequest{
		KeyId:   "any-key",
		Version: 1,
	})
	if err == nil {
		t.Fatal("should fail when sealed")
	}
	t.Log("✅ gRPC ShredKey correctly rejected when sealed")
}
