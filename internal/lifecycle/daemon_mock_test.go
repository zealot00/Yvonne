package lifecycle

import (
	"context"

	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// mockUnsealer 实现 seal.Unsealer 接口（测试用）。
type mockUnsealer struct {
	masterKey *memguard.SecureBuffer
}

func (m *mockUnsealer) IsSealed() bool                          { return false }
func (m *mockUnsealer) IsEmergencySealed() bool                 { return false }
func (m *mockUnsealer) ProvideShare(share []byte) (bool, error) { return false, nil }
func (m *mockUnsealer) MasterKeyRef(action func(key *memguard.SecureBuffer) error) error {
	return action(m.masterKey)
}
func (m *mockUnsealer) Seal(ctx context.Context)          {}
func (m *mockUnsealer) EmergencySeal(ctx context.Context) {}
func (m *mockUnsealer) State() seal.State                 { return seal.StateUnsealed }
func (m *mockUnsealer) Threshold() int                    { return 0 }
func (m *mockUnsealer) TotalShares() int                  { return 0 }
