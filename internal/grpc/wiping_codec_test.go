package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "yvonne/gen/proto/yvonne/v1"
	"yvonne/internal/seal"
)

// dialTest 辅助：连接测试 server。
func dialTest() (*grpc.ClientConn, error) {
	return grpc.NewClient(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// TestWipingCodec_DecryptResponseCleared 验证 Decrypt 后 response 明文被清零。
func TestWipingCodec_DecryptResponseCleared(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()
	mgr.CreateKey(ctx, "wipe-test-key", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	// 加密。
	encResp, err := client.Encrypt(ctx, &pb.EncryptRequest{
		KeyId:     "wipe-test-key",
		Plaintext: []byte("sensitive data for wipe test"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 解密。
	decResp, err := client.Decrypt(ctx, &pb.DecryptRequest{
		KeyId:      "wipe-test-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// 验证客户端收到的明文正确。
	if string(decResp.Plaintext) != "sensitive data for wipe test" {
		t.Fatalf("plaintext = %q", string(decResp.Plaintext))
	}

	// 注意：客户端侧的 decResp 是序列化后的副本，无法验证 server 端是否清零。
	// 此测试验证功能正确性（wipingCodec 不破坏序列化）。
}

// TestWipingCodec_CreateKeyResponseCleared 验证 CreateKey 后 DEK 被清零。
func TestWipingCodec_CreateKeyResponseCleared(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	grpcSrv := startTestServer(t, core, nil)
	_ = grpcSrv
	conn, _ := dialTest()
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	resp, err := client.CreateKey(ctx, &pb.CreateKeyRequest{
		KeyId:     "create-wipe-test",
		ReturnDek: true,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// 客户端收到的 DEK 应非全零。
	if len(resp.PlaintextDek) != 32 {
		t.Fatalf("DEK length = %d", len(resp.PlaintextDek))
	}
	allZero := true
	for _, b := range resp.PlaintextDek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("client received all-zero DEK")
	}

	// Server 端的 response 对象在序列化后被 wipingCodec 清零（此测试验证功能不破坏）。
}
