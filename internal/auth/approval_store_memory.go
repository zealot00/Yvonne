// Package auth - 内存 ApprovalStore 实现（测试 + Dev 模式用）。
package auth

import (
	"fmt"
	"sync"
	"time"
)

// MemoryApprovalStore 是 ApprovalTicket 的内存存储实现。
type MemoryApprovalStore struct {
	mu      sync.RWMutex
	tickets map[string]*ApprovalTicket
}

// NewMemoryApprovalStore 创建内存 ApprovalStore。
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{
		tickets: make(map[string]*ApprovalTicket),
	}
}

// CreateTicket 创建审批 ticket。
func (s *MemoryApprovalStore) CreateTicket(ticket *ApprovalTicket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tickets[ticket.ID]; exists {
		return fmt.Errorf("auth: ticket %q already exists", ticket.ID)
	}
	// 深拷贝 approvers/rejectors 切片避免外部修改。
	ticketCopy := *ticket
	ticketCopy.Approvers = copyStringSlice(ticket.Approvers)
	ticketCopy.Rejectors = copyStringSlice(ticket.Rejectors)
	s.tickets[ticket.ID] = &ticketCopy
	return nil
}

// GetTicket 获取 ticket。
func (s *MemoryApprovalStore) GetTicket(id string) (*ApprovalTicket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ticket, ok := s.tickets[id]
	if !ok {
		return nil, ErrApprovalNotFound
	}
	// 返回拷贝避免外部修改。
	ticketCopy := *ticket
	ticketCopy.Approvers = copyStringSlice(ticket.Approvers)
	ticketCopy.Rejectors = copyStringSlice(ticket.Rejectors)
	return &ticketCopy, nil
}

// UpdateTicket 更新 ticket（状态变更）。
func (s *MemoryApprovalStore) UpdateTicket(ticket *ApprovalTicket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tickets[ticket.ID]; !exists {
		return ErrApprovalNotFound
	}
	ticketCopy := *ticket
	ticketCopy.Approvers = copyStringSlice(ticket.Approvers)
	ticketCopy.Rejectors = copyStringSlice(ticket.Rejectors)
	s.tickets[ticket.ID] = &ticketCopy
	return nil
}

// ListPending 列出 pending 状态的 ticket。
func (s *MemoryApprovalStore) ListPending() ([]*ApprovalTicket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalTicket
	for _, t := range s.tickets {
		if t.Status == ApprovalPending {
			ticketCopy := *t
			ticketCopy.Approvers = copyStringSlice(t.Approvers)
			ticketCopy.Rejectors = copyStringSlice(t.Rejectors)
			result = append(result, &ticketCopy)
		}
	}
	return result, nil
}

// ListByOperation 列出指定操作的 ticket。
func (s *MemoryApprovalStore) ListByOperation(operation string) ([]*ApprovalTicket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalTicket
	for _, t := range s.tickets {
		if t.Operation == operation {
			ticketCopy := *t
			ticketCopy.Approvers = copyStringSlice(t.Approvers)
			ticketCopy.Rejectors = copyStringSlice(t.Rejectors)
			result = append(result, &ticketCopy)
		}
	}
	return result, nil
}

// DeleteTicket 删除 ticket。
func (s *MemoryApprovalStore) DeleteTicket(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tickets, id)
	return nil
}

// CleanupExpired 清理过期 ticket（标记为 expired）。
func (s *MemoryApprovalStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	now := time.Now()
	for _, t := range s.tickets {
		if t.Status == ApprovalPending && now.After(t.ExpiresAt) {
			t.Status = ApprovalExpired
			t.ResolvedAt = now
			count++
		}
	}
	return count
}

// copyStringSlice 复制字符串切片。
func copyStringSlice(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
