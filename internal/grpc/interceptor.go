// Package grpc — gRPC 拦截器（认证 + 审计 + Sealed 检查 + rate limit）。
package grpc

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"yvonne/internal/audit"
	"yvonne/internal/auth"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// InterceptorChain 返回 UnaryServerInterceptor 链（从外到内）：
// 1. panic recover + 哈希链审计（audit.Auditor）
// 2. 认证（从 metadata 取 Bearer Token，失败不回显内部错误细节）
// 3. Sealed 检查（EmergencySeal/Health 豁免）
func InterceptorChain(authenticator auth.Authenticator, s seal.Unsealer, auditors ...audit.Auditor) grpc.UnaryServerInterceptor {
	var auditor audit.Auditor
	if len(auditors) > 0 {
		auditor = auditors[0]
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		method := strings.TrimPrefix(info.FullMethod, "/yvonne.v1.YvonneService/")
		clientIP := peerIPFromContext(ctx)
		actor := clientIP
		traceID := generateTraceID()

		recordAudit := func(auditStatus, result string) error {
			if auditor == nil {
				return nil
			}
			entry := audit.LogEntry{
				TraceID:   traceID,
				Timestamp: time.Now().UTC(),
				ClientIP:  clientIP,
				Actor:     actor,
				Action:    method,
				Result:    result,
				Status:    auditStatus,
			}
			if recErr := auditor.Record(entry); recErr != nil {
				log.Printf("CRITICAL: gRPC audit log write failed (method=%s trace_id=%s actor=%s): %v", method, traceID, actor, recErr)
				return recErr
			}
			return nil
		}

		// 1. panic recover。
		defer func() {
			if r := recover(); r != nil {
				log.Printf("gRPC PANIC in %s: %v", info.FullMethod, r)
				_ = recordAudit("failure", "panic")
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()

		// 2. 认证（Health 豁免）。
		if info.FullMethod != "/yvonne.v1.YvonneService/Health" {
			policy, authErr := authenticate(ctx, authenticator)
			if authErr != nil {
				log.Printf("gRPC %s: authentication failed from %s: %v", method, clientIP, authErr)
				_ = recordAudit("unauthorized", "authentication failed")
				// 安全红线：绝不向客户端回显内部认证错误细节（防信息泄露）。
				return nil, status.Error(codes.Unauthenticated, "authentication failed")
			}
			if policy != nil {
				if policy.RoleID != "" {
					actor = policy.RoleID
				}
				ctx = auth.WithPolicy(ctx, policy)
			}
		}

		// 3. Sealed 检查（Health/EmergencySeal 豁免）。
		if !isSealExempt(info.FullMethod) {
			if s.IsEmergencySealed() {
				_ = recordAudit("failure", "vault is emergency sealed")
				return nil, status.Error(codes.Unavailable, "vault is emergency sealed")
			}
			if s.IsSealed() {
				_ = recordAudit("failure", "vault is sealed")
				return nil, status.Error(codes.Unavailable, "vault is sealed")
			}
		}

		// 4. 执行 handler。
		startTime := time.Now()
		resp, err = handler(ctx, req)
		duration := time.Since(startTime)

		// 5. 审计落盘（Health 探活豁免；审计写入失败则 fail-closed 拒绝返回响应）。
		if info.FullMethod != "/yvonne.v1.YvonneService/Health" {
			auditStatus := "success"
			result := "success"
			if err != nil {
				auditStatus = "failure"
				result = "error"
				if status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unauthenticated {
					auditStatus = "unauthorized"
				}
				log.Printf("gRPC %s: error after %v: %v", method, duration, err)
			}
			if recErr := recordAudit(auditStatus, result); recErr != nil {
				return nil, status.Error(codes.Internal, "audit log write failed")
			}
		}
		return resp, err
	}
}

func peerIPFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func generateTraceID() string {
	b, err := memguard.GenerateSecureRandom(16)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
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
