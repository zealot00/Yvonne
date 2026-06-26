// Package grpc — gRPC 拦截器（认证 + 审计 + Sealed 检查 + rate limit）。
package grpc

import (
	"context"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"yvonne/internal/auth"
	"yvonne/internal/seal"
)

// InterceptorChain 返回 UnaryServerInterceptor 链（从外到内）：
// 1. panic recover + audit
// 2. 认证（从 metadata 取 Bearer Token）
// 3. Sealed 检查（EmergencySeal/Health 豁免）
func InterceptorChain(authenticator auth.Authenticator, s seal.Unsealer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		// 1. panic recover。
		defer func() {
			if r := recover(); r != nil {
				log.Printf("gRPC PANIC in %s: %v", info.FullMethod, r)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()

		// 2. 认证（Health 豁免）。
		if info.FullMethod != "/yvonne.v1.YvonneService/Health" {
			policy, authErr := authenticate(ctx, authenticator)
			if authErr != nil {
				return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", authErr)
			}
			if policy != nil {
				ctx = auth.WithPolicy(ctx, policy)
			}
		}

		// 3. Sealed 检查（Health/EmergencySeal 豁免）。
		if !isSealExempt(info.FullMethod) {
			if s.IsEmergencySealed() {
				return nil, status.Error(codes.Unavailable, "vault is emergency sealed")
			}
			if s.IsSealed() {
				return nil, status.Error(codes.Unavailable, "vault is sealed")
			}
		}

		// 4. 执行 handler。
		startTime := time.Now()
		resp, err = handler(ctx, req)
		duration := time.Since(startTime)

		// 5. 审计（简化：仅 log，完整审计由 Core.recordAudit 负责）。
		method := strings.TrimPrefix(info.FullMethod, "/yvonne.v1.YvonneService/")
		if err != nil {
			log.Printf("gRPC %s: error after %v: %v", method, duration, err)
		}
		return resp, err
	}
}

// authenticate 从 gRPC metadata 提取 Bearer Token 并认证。
// authenticator 为 nil 时（Dev 模式）返回 nil Policy（放行）。
func authenticate(ctx context.Context, authenticator auth.Authenticator) (*auth.Policy, error) {
	if authenticator == nil {
		return nil, nil // Dev 模式
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errNoMetadata
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, errNoToken
	}

	token := authHeaders[0]
	const prefix = "Bearer "
	if len(token) <= len(prefix) || token[:len(prefix)] != prefix {
		return nil, errInvalidTokenFormat
	}
	token = token[len(prefix):]

	policy, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

// isSealExempt 判断方法是否豁免 Sealed 检查。
func isSealExempt(method string) bool {
	switch method {
	case "/yvonne.v1.YvonneService/Health":
		return true
	case "/yvonne.v1.YvonneService/EmergencySeal":
		return true
	default:
		return false
	}
}

var (
	errNoMetadata         = status.Error(codes.Unauthenticated, "no metadata in context")
	errNoToken            = status.Error(codes.Unauthenticated, "no authorization token")
	errInvalidTokenFormat = status.Error(codes.Unauthenticated, "invalid token format")
)
