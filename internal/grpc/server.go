// Package grpc — Yvonne KMS gRPC server。
//
// 全量镜像 HTTP 端点，共享 internal/service.Core 业务逻辑。
// 拦截器链：rate-limit → 认证 → Sealed 检查 → audit + recover。
package grpc

import (
	"context"
	"errors"

	pb "yvonne/gen/proto/yvonne/v1"
	"yvonne/internal/auth"
	"yvonne/internal/memguard"
	"yvonne/internal/service"
)

// Server 实现 YvonneService gRPC 接口。
type Server struct {
	pb.UnimplementedYvonneServiceServer
	core *service.Core
	auth auth.Authenticator
}

// NewServer 创建 gRPC server。
func NewServer(core *service.Core, authenticator auth.Authenticator) *Server {
	return &Server{core: core, auth: authenticator}
}

// === 系统管理 ===

func (s *Server) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	state, emergency, err := s.core.Health(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.HealthResponse{
		State:           state,
		EmergencySealed: emergency,
	}, nil
}

func (s *Server) EmergencySeal(ctx context.Context, req *pb.EmergencySealRequest) (*pb.EmergencySealResponse, error) {
	// EmergencySeal 不走 Core.authorize（需要 admin_token 而非 Policy）。
	// 拦截器已校验 admin token。
	if !req.Confirm {
		return nil, errors.New("grpc: confirm must be true")
	}
	if err := s.core.EmergencySeal(ctx, req.AdminToken); err != nil {
		return nil, err
	}
	return &pb.EmergencySealResponse{
		EmergencySealed: true,
		Message:         "vault is now emergency sealed",
	}, nil
}

func (s *Server) Unseal(ctx context.Context, req *pb.UnsealRequest) (*pb.UnsealResponse, error) {
	// Unseal 走 seal.Unsealer，不通过 Core（Core 在 Sealed 时拒绝）。
	// 此处简化：gRPC 不支持 Shamir Unseal（需专用仪式接口），返回 error。
	return nil, errors.New("grpc: unseal not supported via gRPC (use HTTP or admin UI)")
}

// === 密钥生命周期 ===

func (s *Server) CreateKey(ctx context.Context, req *pb.CreateKeyRequest) (*pb.CreateKeyResponse, error) {
	returnDEK := req.ReturnDek
	policy := auth.PolicyFromContext(ctx)
	result, err := s.core.CreateKey(ctx, req.KeyId, int(req.RotationPeriodDays), returnDEK, policy)
	if err != nil {
		return nil, err
	}

	var dekBytes []byte
	if result.PlaintextDEK != nil {
		_ = result.PlaintextDEK.WithKey(func(d []byte) error {
			dekBytes = make([]byte, len(d))
			copy(dekBytes, d)
			return nil
		})
		result.PlaintextDEK.Wipe()
	}
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	return &pb.CreateKeyResponse{
		KeyId:        result.KeyID,
		Version:      int32(result.Version),
		PlaintextDek: dekBytes,
	}, nil
}

func (s *Server) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	result, err := s.core.RotateKey(ctx, req.KeyId, policy)
	if err != nil {
		return nil, err
	}

	var dekBytes []byte
	if result.PlaintextDEK != nil {
		_ = result.PlaintextDEK.WithKey(func(d []byte) error {
			dekBytes = make([]byte, len(d))
			copy(dekBytes, d)
			return nil
		})
		result.PlaintextDEK.Wipe()
	}

	return &pb.RotateKeyResponse{
		KeyId:        result.KeyID,
		NewVersion:   int32(result.NewVersion),
		PlaintextDek: dekBytes,
	}, nil
}

func (s *Server) ShredKey(ctx context.Context, req *pb.ShredKeyRequest) (*pb.ShredKeyResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	if err := s.core.ShredKey(ctx, req.KeyId, int(req.Version), policy); err != nil {
		return nil, err
	}
	return &pb.ShredKeyResponse{Destroyed: true}, nil
}

func (s *Server) SoftDeleteKey(ctx context.Context, req *pb.SoftDeleteKeyRequest) (*pb.SoftDeleteKeyResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	if err := s.core.SoftDeleteKey(ctx, req.KeyId, int(req.Version), policy); err != nil {
		return nil, err
	}
	return &pb.SoftDeleteKeyResponse{SoftDeleted: true}, nil
}

func (s *Server) RestoreKey(ctx context.Context, req *pb.RestoreKeyRequest) (*pb.RestoreKeyResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	if err := s.core.RestoreKey(ctx, req.KeyId, int(req.Version), policy); err != nil {
		return nil, err
	}
	return &pb.RestoreKeyResponse{Restored: true}, nil
}

// === 数据密钥 ===

func (s *Server) GenerateDataKey(ctx context.Context, req *pb.GenerateDataKeyRequest) (*pb.GenerateDataKeyResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	result, err := s.core.GenerateDataKey(ctx, req.KeyId, policy)
	if err != nil {
		return nil, err
	}

	var dekBytes []byte
	if result.PlaintextDEK != nil {
		_ = result.PlaintextDEK.WithKey(func(d []byte) error {
			dekBytes = make([]byte, len(d))
			copy(dekBytes, d)
			return nil
		})
		result.PlaintextDEK.Wipe()
	}

	return &pb.GenerateDataKeyResponse{
		PlaintextDek:  dekBytes,
		CiphertextDek: result.Ciphertext,
	}, nil
}

// === 加解密 ===

func (s *Server) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	result, err := s.core.Encrypt(ctx, req.KeyId, req.Plaintext, policy)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{
		Ciphertext: result.Ciphertext,
		Version:    int32(result.Version),
	}, nil
}

func (s *Server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	policy := auth.PolicyFromContext(ctx)
	result, err := s.core.Decrypt(ctx, req.KeyId, req.Ciphertext, policy)
	if err != nil {
		return nil, err
	}
	defer result.Plaintext.Wipe()

	// Copy 明文到 response（不 defer clear，因为 response 持有引用）。
	var plainBytes []byte
	_ = result.Plaintext.WithKey(func(d []byte) error {
		plainBytes = make([]byte, len(d))
		copy(plainBytes, d)
		return nil
	})

	return &pb.DecryptResponse{
		Plaintext: plainBytes,
		Version:   int32(result.Version),
	}, nil
}

// === BYOK（通过 Core 尚未实现，返回 not implemented）===

func (s *Server) TransitPub(ctx context.Context, req *pb.TransitPubRequest) (*pb.TransitPubResponse, error) {
	return nil, errors.New("grpc: TransitPub not implemented via gRPC (use HTTP)")
}

func (s *Server) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return nil, errors.New("grpc: ImportKey not implemented via gRPC (use HTTP)")
}

// === 审计 ===

func (s *Server) AuditQuery(ctx context.Context, req *pb.AuditQueryRequest) (*pb.AuditQueryResponse, error) {
	return nil, errors.New("grpc: AuditQuery not implemented via gRPC (use HTTP)")
}

// 确保 memguard 引用（避免 import 警告）。
var _ = memguard.NewSecureBuffer
