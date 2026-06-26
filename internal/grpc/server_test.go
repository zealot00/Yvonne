package grpc

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "yvonne/gen/proto/yvonne/v1"
	"yvonne/internal/auth"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/service"
	"yvonne/internal/storage"
)

// TestGRPC_Health 健康检查（无认证豁免）。
func TestGRPC_Health(t *testing.T) {
	core, _, _ := newTestCore(t)
	grpcSrv := startTestServer(t, core, nil)

	conn, err := grpc.NewClient(getAddr(grpcSrv), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewYvonneServiceClient(conn)
	resp, err := client.Health(context.Background(), &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if resp.State != "unsealed" {
		t.Fatalf("state = %s, want unsealed", resp.State)
	}
}

// TestGRPC_EncryptDecrypt gRPC 端到端加解密。
func TestGRPC_EncryptDecrypt(t *testing.T) {
	core, mgr, mk := newTestCore(t)
	ctx := context.Background()

	// 创建 key。
	mgr.CreateKey(ctx, "grpc-key", seal.NewSoftwareKEK(mk), 0)

	grpcSrv := startTestServer(t, core, nil)

	conn, _ := grpc.NewClient(getAddr(grpcSrv), grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	// Encrypt。
	plaintext := []byte("grpc test")
	encResp, err := client.Encrypt(ctx, &pb.EncryptRequest{
		KeyId:     "grpc-key",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encResp.Version != 1 {
		t.Fatalf("version = %d", encResp.Version)
	}

	// Decrypt。
	decResp, err := client.Decrypt(ctx, &pb.DecryptRequest{
		KeyId:      "grpc-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.Plaintext) != string(plaintext) {
		t.Fatalf("plaintext = %q, want %q", string(decResp.Plaintext), string(plaintext))
	}
}

// TestGRPC_SealedRefused Sealed 状态下业务操作被拒。
func TestGRPC_SealedRefused(t *testing.T) {
	// 重新创建 sealed vault。
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(5, 3, 0) // sealed

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	core := service.NewManager(mgr, vault, nil)

	grpcSrv := startTestServer(t, core, nil)

	conn, _ := grpc.NewClient(getAddr(grpcSrv), grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewYvonneServiceClient(conn)

	_, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
		KeyId:     "any",
		Plaintext: []byte("x"),
	})
	if err == nil {
		t.Fatal("Encrypt on sealed vault should fail")
	}
}

// startTestServer 启动测试 gRPC server，返回 *grpc.Server。
func startTestServer(t *testing.T, core *service.Core, authenticator auth.Authenticator) *grpc.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// 从 core 提取 vault（通过反射或直接传参）——简化：测试用 nil vault，Sealed 检查跳过。
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		InterceptorChain(authenticator, testVault),
	))
	pbServer := NewServer(core, authenticator)
	pb.RegisterYvonneServiceServer(srv, pbServer)

	go srv.Serve(ln)
	t.Cleanup(srv.Stop)

	testServerAddr = ln.Addr().String()
	return srv
}

var testServerAddr string
var testVault seal.Unsealer

func getAddr(srv *grpc.Server) string {
	return testServerAddr
}

// newTestCore 创建测试 Core（复用 service 包的逻辑）。
func newTestCore(t *testing.T) (*service.Core, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	t.Cleanup(mk.Wipe)

	vault := seal.NewVaultState(1, 1, 0)
	if err := vault.DirectUnseal(mk); err != nil {
		t.Fatalf("DirectUnseal: %v", err)
	}
	testVault = vault

	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	core := service.NewManager(mgr, vault, nil)
	return core, mgr, mk
}

// 确保 auth 引用（避免 import 警告）。
var _ = auth.Policy{}
