// Package auth - 内存 MFAStore 实现（测试 + Dev 模式用）。
package auth

import (
	"fmt"
	"sync"
)

// MemoryMFAStore 是 MFAState 的内存存储实现。
type MemoryMFAStore struct {
	mu     sync.RWMutex
	states map[string]*MFAState
}

// NewMemoryMFAStore 创建内存 MFAStore。
func NewMemoryMFAStore() *MemoryMFAStore {
	return &MemoryMFAStore{
		states: make(map[string]*MFAState),
	}
}

// GetMFAState 获取角色的 MFA 状态。
func (s *MemoryMFAStore) GetMFAState(roleID string) (*MFAState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[roleID]
	if !ok {
		return nil, fmt.Errorf("auth: mfa state not found for role %q", roleID)
	}
	return state, nil
}

// SaveMFAState 保存角色的 MFA 状态。
func (s *MemoryMFAStore) SaveMFAState(state *MFAState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.RoleID] = state
	return nil
}

// DeleteMFAState 删除角色的 MFA 绑定。
func (s *MemoryMFAStore) DeleteMFAState(roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, roleID)
	return nil
}
