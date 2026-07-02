// PKI service 层覆盖率补充测试（错误路径 + 边界场景）。
package service

import (
	"context"
	"testing"

	"yvonne/internal/lifecycle"
)

// TestCore_PKI_Coverage_VerifyCert_NoCertManager 无 CertManager 时 VerifyCert 报错。
func TestCore_PKI_Coverage_VerifyCert_NoCertManager(t *testing.T) {
	core, _, _ := newTestCore(t) // 不设置 certManager
	ctx := context.Background()

	_, err := core.VerifyCert(ctx, []byte("cert"), []byte("ca"), nil)
	if err == nil {
		t.Fatal("VerifyCert should error without certManager")
	}
	t.Logf("✅ VerifyCert no certManager: %v", err)
}

// TestCore_PKI_Coverage_GetCRL_NoCertManager 无 CertManager 时 GetCRL 报错。
func TestCore_PKI_Coverage_GetCRL_NoCertManager(t *testing.T) {
	core, _, _ := newTestCore(t)
	ctx := context.Background()

	_, err := core.GetCRL(ctx, "ca-key", nil)
	if err == nil {
		t.Fatal("GetCRL should error without certManager")
	}
	t.Logf("✅ GetCRL no certManager: %v", err)
}

// TestCore_PKI_Coverage_GetCert_NotFound 证书不存在。
func TestCore_PKI_Coverage_GetCert_NotFound(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	_, err := core.GetCert(ctx, "nonexistent-cert-id", nil)
	if err == nil {
		t.Fatal("GetCert should error for nonexistent cert")
	}
	t.Logf("✅ GetCert not found: %v", err)
}

// TestCore_PKI_Coverage_GetCRL_NoCRL CA 无 CRL。
func TestCore_PKI_Coverage_GetCRL_NoCRL(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// 创建 CA 但不吊销任何证书（无 CRL）。
	_, err := core.CreateCA(ctx, "ca-no-crl", "rsa", "CN=Test CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	_, err = core.GetCRL(ctx, "ca-no-crl", nil)
	// 无 CRL 应返回 error 或空（取决于实现）。
	t.Logf("✅ GetCRL no CRL: err=%v", err)
}

// TestCore_PKI_Coverage_GetCert_Success 创建 CA 后 GetCert 成功。
func TestCore_PKI_Coverage_GetCert_Success(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	result, err := core.CreateCA(ctx, "ca-getcert", "rsa", "CN=Test CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	meta, err := core.GetCert(ctx, result.CertID, nil)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if meta == nil {
		t.Fatal("meta should not be nil")
	}
	if meta.CertID != result.CertID {
		t.Fatalf("CertID = %q, want %q", meta.CertID, result.CertID)
	}
	t.Logf("✅ GetCert success: cert_id=%s", meta.CertID)
}

// TestCore_PKI_Coverage_VerifyCert_InvalidPEM 无效证书 PEM。
func TestCore_PKI_Coverage_VerifyCert_InvalidPEM(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	_, err := core.VerifyCert(ctx, []byte("not a cert"), nil, nil)
	if err == nil {
		t.Fatal("VerifyCert should error for invalid PEM")
	}
	t.Logf("✅ VerifyCert invalid PEM: %v", err)
}

// TestCore_PKI_Coverage_RevokeCert_NotFound 吊销不存在的证书。
func TestCore_PKI_Coverage_RevokeCert_NotFound(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	err := core.RevokeCert(ctx, "ca-nonexistent", "cert-nonexistent", "key_compromise", nil)
	if err == nil {
		t.Fatal("RevokeCert should error for nonexistent cert")
	}
	t.Logf("✅ RevokeCert not found: %v", err)
}

// TestCore_PKI_Coverage_GetCACertPEM_NotFound CA 证书不存在。
func TestCore_PKI_Coverage_GetCACertPEM_NotFound(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// getCACertPEM 是内部方法，通过 IssueCert 间接调用。
	// IssueCert 用不存在的 CA keyID 应失败。
	_, err := core.IssueCert(ctx, "ca-nonexistent", "CN=test", "rsa", []byte("pub"), "sign", 90, nil)
	if err == nil {
		t.Fatal("IssueCert should error for nonexistent CA")
	}
	t.Logf("✅ getCACertPEM not found (via IssueCert): %v", err)
}

// TestCore_PKI_Coverage_CreateCA_InvalidAlgo 无效算法。
func TestCore_PKI_Coverage_CreateCA_InvalidAlgo(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	_, err := core.CreateCA(ctx, "ca-bad", "invalid-algo", "CN=Bad", 10, nil)
	if err == nil {
		t.Fatal("CreateCA should error for invalid algo")
	}
	t.Logf("✅ CreateCA invalid algo: %v", err)
}

// TestCore_PKI_Coverage_ListByCA_Empty 空 CA 列表。
func TestCore_PKI_Coverage_ListByCA_Empty(t *testing.T) {
	_, mgr, _ := newPKITestCore(t)
	ctx := context.Background()

	// 直接调 certManager.ListByCA 查空。
	certMgr := lifecycle.NewCertManager(mgr.Store())
	certs, err := certMgr.ListByCA(ctx, "ca-empty")
	if err != nil {
		t.Fatalf("ListByCA empty: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs, got %d", len(certs))
	}
	t.Logf("✅ ListByCA empty: 0 certs")
}
