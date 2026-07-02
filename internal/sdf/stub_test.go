//go:build !gmsm

// SDF stub 测试（无 gmsm 标签时验证回退行为）。
package sdf

import (
	"testing"
)

// TestSDF_Stub_Unavailable 无 gmsm 标签时 NewSoftwareDevice 返回 error。
func TestSDF_Stub_Unavailable(t *testing.T) {
	_, err := NewSoftwareDevice()
	if err == nil {
		t.Fatal("NewSoftwareDevice should error without -tags gmsm")
	}
	t.Logf("✅ SDF stub correctly errors: %v", err)
}
