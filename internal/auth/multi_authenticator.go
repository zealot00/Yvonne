// Package auth - 多认证器链。
//
// 按顺序尝试多个 Authenticator，第一个成功即返回。
// 用于同时支持 AppRole + JWT + K8s SA 认证。
package auth

import "context"

// MultiAuthenticator 按顺序尝试多个认证器。
type MultiAuthenticator struct {
	authenticators []Authenticator
}

// NewMultiAuthenticator 创建多认证器链。
func NewMultiAuthenticator(authenticators ...Authenticator) *MultiAuthenticator {
	return &MultiAuthenticator{authenticators: authenticators}
}

// Authenticate 按顺序尝试，第一个成功即返回。
// 全部失败则返回最后一个 error。
func (m *MultiAuthenticator) Authenticate(ctx context.Context, token string) (*Policy, error) {
	var lastErr error = ErrUnauthorized
	for _, a := range m.authenticators {
		if a == nil {
			continue
		}
		policy, err := a.Authenticate(ctx, token)
		if err == nil {
			return policy, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
