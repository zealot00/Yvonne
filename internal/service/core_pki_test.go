// PKI service 层单元测试（RSA/ECDSA 路径，无 gmsm 标签）。
package service

import (
	"context"
	"testing"

	"yvonne/internal/crypto"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
)

// newPKITestCore 创建带 CertManager 的测试 Core。
func newPKITestCore(t *testing.T) (*Core, *lifecycle.Manager, *memguard.SecureBuffer) {
	t.Helper()
	core, mgr, mk := newTestCore(t)
	certMgr := lifecycle.NewCertManager(mgr.Store())
	core.SetCertManager(certMgr)
	return core, mgr, mk
}

// TestCore_CreateCA_RSA 创建 RSA CA（自签根证书）。
func TestCore_CreateCA_RSA(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	result, err := core.CreateCA(ctx, "rsa-ca", "rsa", "CN=Test RSA CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA RSA: %v", err)
	}
	if result.CertID == "" {
		t.Fatal("CertID should not be empty")
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}
	if result.Serial == "" {
		t.Fatal("Serial should not be empty")
	}
	t.Logf("✅ CreateCA RSA: cert_id=%s, serial=%s, pem=%d bytes", result.CertID, result.Serial, len(result.PEM))
}

// TestCore_CreateCA_ECDSA 创建 ECDSA CA。
func TestCore_CreateCA_ECDSA(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	result, err := core.CreateCA(ctx, "ecdsa-ca", "ecdsa", "CN=Test ECDSA CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA ECDSA: %v", err)
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}
	t.Logf("✅ CreateCA ECDSA: cert_id=%s", result.CertID)
}

// TestCore_IssueCert_RSA RSA CA 签发终端证书。
func TestCore_IssueCert_RSA(t *testing.T) {
	core, _, mk := newPKITestCore(t)
	ctx := context.Background()

	// 1. 创建 CA。
	caResult, err := core.CreateCA(ctx, "rsa-ca-1", "rsa", "CN=Issue RSA CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	// 2. 生成终端密钥对（用 lifecycle.CreateAsymmetricKey）。
	// 需要通过 manager 创建一个独立的非对称密钥作为终端实体。
	endKeyID := "rsa-end-1"
	err = core.seal.KEKRef(func(kek seal.KEK) error {
		_, e := core.manager.CreateAsymmetricKey(ctx, endKeyID, "rsa", kek)
		return e
	})
	if err != nil {
		t.Fatalf("CreateAsymmetricKey end: %v", err)
	}

	// 3. 获取终端公钥。
	endMeta, err := core.manager.GetActiveKey(ctx, endKeyID)
	if err != nil {
		t.Fatalf("GetActiveKey end: %v", err)
	}

	// 4. 用 CA 签发终端证书。
	certResult, err := core.IssueCert(ctx, caResult.KeyID, "CN=End RSA", "rsa", endMeta.PublicKey, "sign", 90, nil)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if len(certResult.PEM) == 0 {
		t.Fatal("issued cert PEM should not be empty")
	}
	t.Logf("✅ IssueCert RSA: cert_id=%s, serial=%s", certResult.CertID, certResult.Serial)

	_ = mk // avoid unused
}

// TestCore_VerifyCert_RSA_Valid 验证 RSA 证书链。
func TestCore_VerifyCert_RSA_Valid(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// 1. 创建 CA + 终端证书。
	caResult, _ := core.CreateCA(ctx, "rsa-ca-v", "rsa", "CN=Verify RSA CA", 10, nil)

	endKeyID := "rsa-end-v"
	core.seal.KEKRef(func(kek seal.KEK) error {
		_, e := core.manager.CreateAsymmetricKey(ctx, endKeyID, "rsa", kek)
		return e
	})
	endMeta, _ := core.manager.GetActiveKey(ctx, endKeyID)

	certResult, err := core.IssueCert(ctx, caResult.KeyID, "CN=End RSA V", "rsa", endMeta.PublicKey, "sign", 90, nil)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// 2. 验证证书链。
	result, err := core.VerifyCert(ctx, certResult.PEM, caResult.PEM, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if !result.Valid {
		t.Fatalf("cert should be valid, error: %s", result.Error)
	}
	t.Logf("✅ VerifyCert RSA: valid=%v", result.Valid)
}

// TestCore_RevokeCert_RSA 吊销证书 + CRL 生成。
func TestCore_RevokeCert_RSA(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// 1. 创建 CA + 终端证书。
	caResult, _ := core.CreateCA(ctx, "rsa-ca-r", "rsa", "CN=Revoke RSA CA", 10, nil)

	endKeyID := "rsa-end-r"
	core.seal.KEKRef(func(kek seal.KEK) error {
		_, e := core.manager.CreateAsymmetricKey(ctx, endKeyID, "rsa", kek)
		return e
	})
	endMeta, _ := core.manager.GetActiveKey(ctx, endKeyID)

	certResult, err := core.IssueCert(ctx, caResult.KeyID, "CN=End RSA R", "rsa", endMeta.PublicKey, "sign", 90, nil)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// 2. 吊销证书。
	err = core.RevokeCert(ctx, caResult.KeyID, certResult.CertID, "keyCompromise", nil)
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	// 3. 获取 CRL。
	crl, err := core.GetCRL(ctx, caResult.KeyID, nil)
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	if len(crl) == 0 {
		t.Fatal("CRL should not be empty after revoke")
	}

	// 4. 解析 CRL 确认吊销列表非空。
	parsed, err := crypto.ParseCRL(crl)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}
	if len(parsed.RevokedCertificates) == 0 {
		t.Fatal("CRL should contain at least one revoked cert")
	}
	t.Logf("✅ RevokeCert RSA: CRL has %d revoked certs", len(parsed.RevokedCertificates))
}

// TestCore_GetCert_RSA 获取证书元数据。
func TestCore_GetCert_RSA(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	caResult, _ := core.CreateCA(ctx, "rsa-ca-g", "rsa", "CN=Get RSA CA", 10, nil)

	meta, err := core.GetCert(ctx, caResult.CertID, nil)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if meta.CertID != caResult.CertID {
		t.Fatalf("cert_id mismatch: got %s, want %s", meta.CertID, caResult.CertID)
	}
	if meta.Subject != "CN=Get RSA CA" {
		t.Fatalf("subject mismatch: %s", meta.Subject)
	}
	t.Logf("✅ GetCert RSA: subject=%s", meta.Subject)
}

// TestCore_CreateCA_NoCertManager 未配置 CertManager 时报错。
func TestCore_CreateCA_NoCertManager(t *testing.T) {
	core, _, _ := newTestCore(t) // 不注入 certManager
	ctx := context.Background()

	_, err := core.CreateCA(ctx, "test-ca", "rsa", "CN=Test", 10, nil)
	if err == nil {
		t.Fatal("should error when certManager is nil")
	}
	t.Logf("✅ CreateCA without CertManager correctly errored: %v", err)
}
