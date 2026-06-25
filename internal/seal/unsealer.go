// Package seal - Unsealer 接口抽象。
//
// 蓝图要求内部包间依赖仅限接口抽象。Unsealer 定义封印层的行为契约，
// api/bootstrap 依赖此接口而非 *VaultState 具体类型。
//
// *VaultState 隐式实现此接口。
package seal

import (
	"context"

	"yvonne/internal/memguard"
)

// Unsealer 是封印层的接口抽象。
//
// 实现者：
//   - *VaultState：Shamir 模式与 Dev 模式（DirectUnseal）
//   - *LocalPKIUnsealer：Local PKI 自动解封模式（通过组合 VaultState 实现）
type Unsealer interface {
	// IsSealed 返回是否处于封印状态。
	IsSealed() bool

	// IsEmergencySealed 返回是否已触发紧急封印（不可逆）。
	IsEmergencySealed() bool

	// ProvideShare 提交单份 Shamir 碎片。
	// 非 Shamir 模式返回固定错误。
	ProvideShare(share []byte) (unsealed bool, err error)

	// MasterKeyRef 在闭包内访问 Master Key。
	// Sealed 状态返回 error。
	// Deprecated: 使用 KEKRef 代替。HSM 模式下此方法返回 error。
	MasterKeyRef(action func(key *memguard.SecureBuffer) error) error

	// KEKRef 在闭包内访问 KEK 实例（统一 software CMK 与 HSM backend）。
	// 这是主业务路径（DEK wrap/unwrap）的统一入口，三模式均可用。
	// Sealed 状态返回 error。
	KEKRef(action func(kek KEK) error) error

	// Seal 重新封印，清零 Master Key。
	Seal(ctx context.Context)

	// EmergencySeal 紧急封印（不可逆），清零一切敏感内存。
	// 调用后进程生命周期内拒绝所有操作，必须重启 + Shamir 解封。
	EmergencySeal(ctx context.Context)

	// State 返回当前封印状态。
	State() State

	// Threshold 返回门限值。
	Threshold() int

	// TotalShares 返回总份数。
	TotalShares() int
}
