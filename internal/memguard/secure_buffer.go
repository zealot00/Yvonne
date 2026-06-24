// Package memguard - SecureBuffer：明文密钥材料的唯一内存容器。
package memguard

import (
	"runtime"
	"sync/atomic"
)

// SecureBuffer 是 Yvonne 中所有明文密钥材料（Master Key、DEK 等）的唯一容器。
//
// 安全契约：
//   - data 字段私有，外部无法获取可逃逸到 GC 堆的切片引用。
//   - 唯一访问途径是 WithKey 闭包；闭包结束后调用方不应保留对 secret 的引用。
//   - Wipe 后任何 WithKey 调用都会 panic——use-after-free 视为不可恢复的致命错误。
//   - Wipe 使用 clear() + runtime.KeepAlive() 覆写内存并阻止编译器死代码消除 (DCE)。
//
// 非目标（当前版本刻意保持极简）：
//   - 不做 mlock / mmap；防 swap 由更上层的平台封装负责。
//   - 不内置并发互斥；调用方需保证 Wipe 与 WithKey 不并发执行。
type SecureBuffer struct {
	data      []byte
	destroyed atomic.Bool
}

// NewSecureBuffer 从已有切片构造 SecureBuffer，并立即清零入参 src，
// 避免双份明文同时驻留在不同栈帧/堆上。
func NewSecureBuffer(src []byte) *SecureBuffer {
	s := &SecureBuffer{
		data: make([]byte, len(src)),
	}
	copy(s.data, src)
	// 清零源切片，防止明文在调用方栈帧上残留。
	clear(src)
	runtime.KeepAlive(src)
	return s
}

// NewSecureBufferFromRandom 直接从 CSPRNG 生成 size 字节并封装为 SecureBuffer。
// 相比"先 GenerateSecureRandom 再 NewSecureBuffer"，此构造器减少一次内存拷贝
// 和明文暴露窗口，是构造 Master Key / DEK 的推荐入口。
func NewSecureBufferFromRandom(size int) (*SecureBuffer, error) {
	raw, err := GenerateSecureRandom(size)
	if err != nil {
		return nil, err
	}
	// raw 即明文，直接接管所有权，不再拷贝。
	return &SecureBuffer{data: raw}, nil
}

// Wipe 覆写底层内存并标记为已销毁。幂等，可安全多次调用。
//
// 实现要点（红线，不得改动顺序）：
//  1. clear(s.data) 将每个字节置 0。
//  2. runtime.KeepAlive(s.data) 阻止编译器以 DCE 移除 clear。
//  3. destroyed 标志置 true，后续 WithKey 将 panic。
func (s *SecureBuffer) Wipe() {
	if s.destroyed.Load() {
		return
	}
	if s.data != nil {
		clear(s.data)
		runtime.KeepAlive(s.data) // 关键：防 DCE，必须紧跟在 clear 之后
	}
	s.destroyed.Store(true)
}

// WithKey 在闭包作用域内暴露明文密钥供使用。
//
// 若 SecureBuffer 已被 Wipe，立即 panic（use-after-free 是不可恢复的致命错误）。
//
// 调用方约束：闭包内严禁保存 secret 引用（如赋值给外部变量、启动 goroutine 异步使用），
// 否则会破坏 SecureBuffer 的内存隔离保证——一旦 Wipe，外部持有的引用将指向被清零的内存，
// 造成难以追踪的数据损坏。
func (s *SecureBuffer) WithKey(action func(secret []byte) error) error {
	if s.destroyed.Load() {
		panic("FATAL: Use after free in SecureBuffer")
	}
	return action(s.data)
}

// IsDestroyed 返回 SecureBuffer 是否已被 Wipe。
// 仅供状态查询/调试，不暴露任何内容。
func (s *SecureBuffer) IsDestroyed() bool {
	return s.destroyed.Load()
}

// Len 返回底层缓冲长度；已销毁返回 0。
// 仅返回长度（int），不暴露明文内容，可安全对外提供。
func (s *SecureBuffer) Len() int {
	if s.destroyed.Load() {
		return 0
	}
	return len(s.data)
}
