// Package seal 实现 Yvonne 的封印与唤醒状态机。
//
// 状态：
//   - Sealed:   启动默认状态，所有加解密 API 拒绝；Master Key 不在内存。
//   - Unsealed: 已重组 Master Key，可对外提供加解密服务。
//   - Sealing:  正在执行重新封印（清理敏感内存）。
//
// 红线：
//   - Master Key 明文仅在 Unsealed 状态下存在于 SecureBuffer 中。
//   - 重新封印必须立即 Wipe Master Key 的 SecureBuffer。
//   - ProvideShare 修改状态时必须加写锁；IsSealed 查询用读锁。
//   - 任何重组尝试（无论成败）后必须立即 Wipe collectedShares，防内存快照泄露。
//   - Master Key 本身的对比必须用 subtle.ConstantTimeCompare。
package seal

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"yvonne/internal/memguard"
)

// State 表示系统当前的封印状态。
type State int32

const (
	StateSealed State = iota
	StateUnsealed
	StateSealing
)

func (s State) String() string {
	switch s {
	case StateSealed:
		return "sealed"
	case StateUnsealed:
		return "unsealed"
	case StateSealing:
		return "sealing"
	default:
		return "unknown"
	}
}

// VaultState 是 Yvonne 的封印状态机核心结构。
type VaultState struct {
	state atomic.Int32 // State，用于无锁快速查询

	mu              sync.RWMutex
	masterKey       *memguard.SecureBuffer // 仅在 Unsealed 时非 nil
	collectedShares [][]byte               // 已收集的碎片池
	threshold       int
	total           int

	autoResealAfter time.Duration
	cancelReseal    context.CancelFunc // 取消自动重新封印定时器

	// emergencySealed 标记是否已触发紧急封印。
	// 一旦为 true，进程生命周期内不可逆，拒绝一切 API 请求（包括 unseal）。
	emergencySealed atomic.Bool

	// onEmergencySeal 是紧急封印时的回调（如清空 lifecycle DEK 缓存）。
	// 可为 nil。通过 SetEmergencySealCallback 注入。
	onEmergencySeal func()
}

// NewVaultState 创建 VaultState，初始状态为 Sealed。
// total=总份数，threshold=门限，autoResealAfter=Unsealed 后超时自动重新封印（0=禁用）。
func NewVaultState(total, threshold int, autoResealAfter time.Duration) *VaultState {
	v := &VaultState{
		threshold:       threshold,
		total:           total,
		autoResealAfter: autoResealAfter,
	}
	v.state.Store(int32(StateSealed))
	return v
}

// State 返回当前状态（原子读，无需锁）。
func (v *VaultState) State() State {
	return State(v.state.Load())
}

// IsUnsealed 便捷方法（读锁，保持与 ProvideShare 的可见性）。
func (v *VaultState) IsUnsealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.state.Load() == int32(StateUnsealed)
}

// IsSealed 便捷方法（读锁）。
func (v *VaultState) IsSealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.state.Load() == int32(StateSealed)
}

// DirectUnseal 直接注入 Master Key 并进入 Unsealed 状态，跳过 Shamir 流程。
//
// 仅供 Dev 模式使用：开发者模式不需要 Shamir 门限，直接用临时 Master Key 启动。
//
// 安全契约：
//   - Cluster 模式绝不调用此方法（bootstrap 通过模式隔离保证）。
//   - 调用后 masterKey 所有权转移给 VaultState，调用方不得再持有引用。
//   - 已 Unsealed 时返回 error。
func (v *VaultState) DirectUnseal(masterKey *memguard.SecureBuffer) error {
	if masterKey == nil {
		return errors.New("seal: direct unseal with nil master key")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// 紧急封印状态：拒绝解封。
	if v.emergencySealed.Load() {
		return errors.New("seal: vault is emergency sealed, unseal refused until process restart")
	}

	if v.state.Load() == int32(StateUnsealed) {
		return errors.New("seal: already unsealed")
	}

	v.masterKey = masterKey
	v.state.Store(int32(StateUnsealed))

	// 启动自动重新封印定时器。
	if v.autoResealAfter > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		v.cancelReseal = cancel
		go v.autoResealLoop(ctx)
	}
	return nil
}

// Threshold 返回门限值（读锁）。
func (v *VaultState) Threshold() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.threshold
}

// TotalShares 返回总份数（读锁）。
func (v *VaultState) TotalShares() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.total
}

// CollectedCount 返回当前已收集的碎片数量（读锁）。
// 仅供管理页面展示进度，不暴露任何 share 内容。
func (v *VaultState) CollectedCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.collectedShares)
}

// MasterKeyEqual 用 subtle.ConstantTimeCompare 安全比较 Master Key。
//
// 调用方传入的 expected 应为 *memguard.SecureBuffer。
// 已 Sealed 或任一为 nil 时返回 false（不泄露状态信息）。
//
// 注意：本方法仅在内部模块（如密钥轮转校验）使用，不对 API 层暴露。
func (v *VaultState) MasterKeyEqual(expected *memguard.SecureBuffer) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state.Load() != int32(StateUnsealed) || v.masterKey == nil || expected == nil {
		return false
	}

	var match bool
	errA := v.masterKey.WithKey(func(a []byte) error {
		return expected.WithKey(func(b []byte) error {
			// subtle.ConstantTimeCompare 要求等长；不等则直接判 false。
			if len(a) != len(b) {
				match = false
				return nil
			}
			match = subtle.ConstantTimeCompare(a, b) == 1
			return nil
		})
	})
	if errA != nil {
		return false
	}
	return match
}

// ProvideShare 提交一份碎片，尝试推进 Unseal 流程。
//
// 返回值：
//   - unsealed: 是否已成功进入 Unsealed 状态（本次调用触发或之前已触发）。
//   - err: 碎片格式非法、Combine 失败、或已 Unsealed 时多余碎片被拒绝等。
//
// 致命安全契约（强制）：
//   - 无论本次是否触发 Combine、Combine 成败，本次持有的 collectedShares
//     副本必须被 Wipe（一旦达阈值尝试过即清空整个池子）。
//   - 已 Unsealed 后再调用直接拒绝，避免重复触发。
func (v *VaultState) ProvideShare(share []byte) (unsealed bool, err error) {
	if len(share) == 0 {
		return false, errors.New("seal: empty share")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// 紧急封印状态：拒绝一切操作，包括解封。
	if v.emergencySealed.Load() {
		return false, errors.New("seal: vault is emergency sealed, all operations refused until process restart")
	}

	// 已 Unsealed：拒绝多余碎片。
	if v.state.Load() == int32(StateUnsealed) {
		return true, errors.New("seal: already unsealed, reject extra share")
	}

	// 拷贝 share 入池（不持有调用方切片引用，避免外部篡改）。
	cp := make([]byte, len(share))
	copy(cp, share)
	v.collectedShares = append(v.collectedShares, cp)

	// 未达阈值：等待更多碎片。注意：本路径不清空池子（尚未尝试 Combine）。
	if len(v.collectedShares) < v.threshold {
		return false, nil
	}

	// 达阈值：触发 Combine。无论成败，立即清空 collectedShares。
	defer v.wipeCollectedShares()

	combined, err := CombineWithThreshold(v.collectedShares, v.threshold)
	if err != nil {
		return false, fmt.Errorf("seal: combine shares: %w", err)
	}

	// Combine 成功：设置 masterKey，切状态。
	v.masterKey = combined
	v.state.Store(int32(StateUnsealed))

	// 启动自动重新封印定时器。
	if v.autoResealAfter > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		v.cancelReseal = cancel
		go v.autoResealLoop(ctx)
	}

	return true, nil
}

// wipeCollectedShares 强制覆写所有已收集碎片并清空池子。
// 调用方必须已持写锁。
func (v *VaultState) wipeCollectedShares() {
	for i := range v.collectedShares {
		if v.collectedShares[i] != nil {
			clear(v.collectedShares[i])
			runtime.KeepAlive(v.collectedShares[i])
		}
	}
	v.collectedShares = nil
}

// Seal 立即重新封印：Wipe Master Key 与 collectedShares，回到 Sealed 状态。
func (v *VaultState) Seal(ctx context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state.Load() == int32(StateSealed) {
		return
	}
	v.state.Store(int32(StateSealing))

	if v.cancelReseal != nil {
		v.cancelReseal()
		v.cancelReseal = nil
	}
	if v.masterKey != nil {
		v.masterKey.Wipe()
		v.masterKey = nil
	}
	v.wipeCollectedShares()
	v.state.Store(int32(StateSealed))
}

// EmergencySeal 紧急封印：不可逆的深度冰冻。
//
// 致命执行序列：
//  1. 获取全局写锁。
//  2. 标记 emergencySealed = true（进程生命周期内不可逆）。
//  3. Wipe masterKey + Wipe collectedShares。
//  4. 取消 autoReseal 定时器。
//  5. 状态标记为 Sealed。
//
// 调用后：
//   - 拒绝一切 API 请求（包括 unseal）。
//   - 必须 kill 进程 + 重新冷启动 + Shamir 解封才能恢复。
//   - IsEmergencySealed() 返回 true 供中间件拦截。
func (v *VaultState) EmergencySeal(ctx context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// 标记不可逆——必须在第一步执行，防止并发请求在 Wipe 完成前进入。
	v.emergencySealed.Store(true)
	v.state.Store(int32(StateSealing))

	// 取消自动重新封印定时器。
	if v.cancelReseal != nil {
		v.cancelReseal()
		v.cancelReseal = nil
	}

	// 强制内存粉碎。
	if v.masterKey != nil {
		v.masterKey.Wipe()
		v.masterKey = nil
	}
	v.wipeCollectedShares()

	// 联动清空外部缓存（如 lifecycle DEK 缓存）。
	if v.onEmergencySeal != nil {
		v.onEmergencySeal()
	}

	v.state.Store(int32(StateSealed))
}

// SetEmergencySealCallback 注入紧急封印时的回调。
// 用于联动清空 lifecycle Manager 的 DEK 缓存，防止 EmergencySeal 后缓存仍可用。
func (v *VaultState) SetEmergencySealCallback(fn func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onEmergencySeal = fn
}

// IsEmergencySealed 返回是否已触发紧急封印。
// 一旦返回 true，进程生命周期内不会回到 false。
func (v *VaultState) IsEmergencySealed() bool {
	return v.emergencySealed.Load()
}

// autoResealLoop 在超时后自动重新封印。
func (v *VaultState) autoResealLoop(ctx context.Context) {
	timer := time.NewTimer(v.autoResealAfter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		v.Seal(context.Background())
	}
}

// MasterKeyRef 在闭包内访问 Master Key。
//
// 仅在 Unsealed 状态下可用；Sealed 状态返回 error。
// 调用方通过 action 闭包临时使用明文，不得保留引用。
// 这是内部模块（crypto engine 等）访问 Master Key 的唯一入口。
func (v *VaultState) MasterKeyRef(action func(key *memguard.SecureBuffer) error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state.Load() != int32(StateUnsealed) || v.masterKey == nil {
		return errors.New("seal: vault is sealed, master key unavailable")
	}
	return action(v.masterKey)
}

// KEKRef 在闭包内访问 KEK 实例（softwareKEK 包装 masterKey）。
// Sealed 状态返回 error。
func (v *VaultState) KEKRef(action func(kek KEK) error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state.Load() != int32(StateUnsealed) || v.masterKey == nil {
		return errors.New("seal: vault is sealed, kek unavailable")
	}
	return action(NewSoftwareKEK(v.masterKey))
}
