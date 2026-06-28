//go:build gmsm

// Package audit - 国密审计链适配（HMAC-SM3）。
//
// 提供 SM3 hash 函数给 hashChain，使审计链在国密模式下使用 HMAC-SM3。
package audit

import (
	"io"

	"github.com/tjfoc/gmsm/sm3"
)

// SM3Sum 计算 SM3 摘要。
func SM3Sum(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

// NewAuditLoggerWithSM3 创建使用 HMAC-SM3 的 AuditLogger（国密模式）。
func NewAuditLoggerWithSM3(writer io.Writer) (*AuditLogger, error) {
	return NewAuditLoggerWithHash(writer, sm3.New, SM3Sum)
}
