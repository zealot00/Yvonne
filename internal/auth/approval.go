// Package auth - Quorum Approval（K-of-N 审批工作流）。
//
// 敏感操作（ShredKey/ExportKey/EmergencySeal）可配置需 K 人审批：
//  1. 请求者创建 approval ticket（pending 状态）
//  2. K 个有权审批者 approve
//  3. 达到 K 票后 ticket 变为 approved，操作执行
//  4. 任一审批者 reject → ticket 变为 rejected
//  5. 超过 TTL → ticket 变为 expired
//
// 安全红线：
//   - 审批者不能审批自己的请求（防自批准）。
//   - 审批操作幂等（同一审批者重复 approve 不计数）。
//   - 所有状态变更记录审计日志。
package auth

import (
	"errors"
	"time"
)

// ApprovalStatus 是审批 ticket 的状态。
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

// ApprovalTicket 是一个审批请求。
type ApprovalTicket struct {
	ID          string         `json:"id"`           // UUID
	Operation   string         `json:"operation"`    // "ShredKey" / "ExportKey" / "EmergencySeal"
	KeyID       string         `json:"key_id"`       // 目标密钥（如有）
	RequestedBy string         `json:"requested_by"` // 请求者 RoleID
	Approvers   []string       `json:"approvers"`    // 已 approve 的 RoleID 列表
	Rejectors   []string       `json:"rejectors"`    // 已 reject 的 RoleID 列表
	Required    int            `json:"required"`     // K（需 K 票通过）
	Status      ApprovalStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`            // TTL（默认 24h）
	ResolvedAt  time.Time      `json:"resolved_at,omitempty"` // approved/rejected/expired 时间
}

// ApprovalStore 是审批存储接口。
type ApprovalStore interface {
	// CreateTicket 创建审批 ticket。
	CreateTicket(ticket *ApprovalTicket) error

	// GetTicket 获取 ticket。
	GetTicket(id string) (*ApprovalTicket, error)

	// UpdateTicket 更新 ticket（状态变更）。
	UpdateTicket(ticket *ApprovalTicket) error

	// ListPending 列出 pending 状态的 ticket。
	ListPending() ([]*ApprovalTicket, error)

	// ListByOperation 列出指定操作的 ticket。
	ListByOperation(operation string) ([]*ApprovalTicket, error)

	// DeleteTicket 删除 ticket（过期清理）。
	DeleteTicket(id string) error
}

// 审批相关错误。
var (
	// ErrApprovalNotFound 表示 ticket 不存在。
	ErrApprovalNotFound = errors.New("auth: approval ticket not found")
	// ErrApprovalExpired 表示 ticket 已过期。
	ErrApprovalExpired = errors.New("auth: approval ticket expired")
	// ErrApprovalAlreadyResolved 表示 ticket 已完成（approved/rejected）。
	ErrApprovalAlreadyResolved = errors.New("auth: approval ticket already resolved")
	// ErrSelfApproval 表示不能审批自己的请求。
	ErrSelfApproval = errors.New("auth: cannot approve own request")
	// ErrNotApprover 表示该角色无权审批。
	ErrNotApprover = errors.New("auth: role not authorized to approve")
	// ErrAlreadyApproved 表示该审批者已 approve（幂等，非错误但不再计数）。
	ErrAlreadyApproved = errors.New("auth: already approved by this role")
	// ErrInsufficientApprovers 表示审批人数不足。
	ErrInsufficientApprovers = errors.New("auth: insufficient approvers to reach quorum")
)

// IsApprovalComplete 检查 ticket 是否已达成 quorum。
func (t *ApprovalTicket) IsApprovalComplete() bool {
	return len(t.Approvers) >= t.Required
}

// IsExpired 检查 ticket 是否过期。
func (t *ApprovalTicket) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// HasApproved 检查某 roleID 是否已 approve（幂等检查）。
func (t *ApprovalTicket) HasApproved(roleID string) bool {
	for _, a := range t.Approvers {
		if a == roleID {
			return true
		}
	}
	return false
}

// HasRejected 检查某 roleID 是否已 reject。
func (t *ApprovalTicket) HasRejected(roleID string) bool {
	for _, r := range t.Rejectors {
		if r == roleID {
			return true
		}
	}
	return false
}
