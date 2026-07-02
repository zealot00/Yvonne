//go:build !kae

// KAE 硬件加速 stub（无 kae 构建标签时）。
//
// 不启用 KAE 时，NewSuite 不会调用 NewKAESuite。
// 本文件仅提供占位，确保非 KAE 编译不引用 CGO。
package crypto

import "errors"

// errKAERequiresTag 无 kae 标签时返回。
var errKAERequiresTag = errors.New("crypto: KAE acceleration requires -tags kae and Kunpeng 920 hardware")

// kaeSuiteStub 实现 CryptoSuite 接口的占位（返回 error 的 NewKAESuite 不会被调用）。
type kaeSuiteStub struct{}

func (kaeSuiteStub) Cipher() Cipher { return nil }
func (kaeSuiteStub) Hash() Hash     { return nil }
func (kaeSuiteStub) Name() string   { return "kae-unavailable" }

// KAESuite 占位类型（无 kae 标签时不可用）。
type KAESuite = kaeSuiteStub

// NewKAESuite stub：无 kae 标签返回 error。
func NewKAESuite(baseSuite Suite) (*kaeSuiteStub, error) {
	return nil, errKAERequiresTag
}

// EnsureKAAvailable stub。
func EnsureKAAvailable() error {
	return errKAERequiresTag
}
