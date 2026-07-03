//go:build !gmsm

// OCSP stub 错误路径验证（无 gmsm 标签）。
//
// 验证在未启用 gmsm 时，SM2 OCSP API 返回正确的错误信息。
package crypto

import (
	"strings"
	"testing"
	"time"
)

// TestCreateSM2OCSPResponse_RequiresGMSM 验证 SM2 OCSP 在 !gmsm 下报错。
func TestCreateSM2OCSPResponse_RequiresGMSM(t *testing.T) {
	_, err := CreateSM2OCSPResponse(
		[]byte{1, 2, 3}, // 任意 DER
		[]byte{4, 5, 6},
		nil,
		OCSPStatusGood,
		time.Time{},
		0,
		time.Time{},
		time.Time{},
	)
	if err == nil {
		t.Fatal("SM2 OCSP without gmsm tag should error")
	}
	if !strings.Contains(err.Error(), "gmsm") {
		t.Fatalf("error should mention 'gmsm' tag, got: %v", err)
	}
	t.Logf("✅ SM2 OCSP stub error: %v", err)
}