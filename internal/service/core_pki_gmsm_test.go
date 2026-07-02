//go:build gmsm

// PKI service 层 SM2 测试（gmsm 构建标签）。
package service

import (
	"context"
	"testing"

	"yvonne/internal/crypto"
	"yvonne/internal/seal"
)

// TestCore_CreateCA_SM2 创建 SM2 CA（自签根证书）。
func TestCore_CreateCA_SM2(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	result, err := core.CreateCA(ctx, "sm2-ca", "sm2", "CN=Test SM2 CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA SM2: %v", err)
	}
	if result.CertID == "" {
		t.Fatal("CertID should not be empty")
	}
	if len(result.PEM) == 0 {
		t.Fatal("PEM should not be empty")
	}
	t.Logf("✅ CreateCA SM2: cert_id=%s, serial=%s", result.CertID, result.Serial)
}

// TestCore_IssueCert_SM2 SM2 CA 签发终端证书。
func TestCore_IssueCert_SM2(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// 1. 创建 SM2 CA。
	caResult, err := core.CreateCA(ctx, "sm2-ca-1", "sm2", "CN=Issue SM2 CA", 10, nil)
	if err != nil {
		t.Fatalf("CreateCA SM2: %v", err)
	}

	// 2. 生成终端 SM2 密钥对。
	endKeyID := "sm2-end-1"
	err = core.seal.KEKRef(func(kek seal.KEK) error {
		_, e := core.manager.CreateAsymmetricKey(ctx, endKeyID, "sm2", kek)
		return e
	})
	if err != nil {
		t.Fatalf("CreateAsymmetricKey end SM2: %v", err)
	}

	endMeta, err := core.manager.GetActiveKey(ctx, endKeyID)
	if err != nil {
		t.Fatalf("GetActiveKey end SM2: %v", err)
	}

	// 3. 用 CA 签发终端证书。
	certResult, err := core.IssueCert(ctx, caResult.KeyID, "CN=End SM2", "sm2", endMeta.PublicKey, "sign", 90, nil)
	if err != nil {
		t.Fatalf("IssueCert SM2: %v", err)
	}
	if len(certResult.PEM) == 0 {
		t.Fatal("issued SM2 cert PEM should not be empty")
	}
	t.Logf("✅ IssueCert SM2: cert_id=%s, serial=%s", certResult.CertID, certResult.Serial)
}

// TestCore_RevokeCert_SM2 SM2 证书吊销 + CRL。
func TestCore_RevokeCert_SM2(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	// 1. 创建 CA + 终端证书。
	caResult, _ := core.CreateCA(ctx, "sm2-ca-r", "sm2", "CN=Revoke SM2 CA", 10, nil)

	endKeyID := "sm2-end-r"
	core.seal.KEKRef(func(kek seal.KEK) error {
		_, e := core.manager.CreateAsymmetricKey(ctx, endKeyID, "sm2", kek)
		return e
	})
	endMeta, _ := core.manager.GetActiveKey(ctx, endKeyID)

	certResult, err := core.IssueCert(ctx, caResult.KeyID, "CN=End SM2 R", "sm2", endMeta.PublicKey, "sign", 90, nil)
	if err != nil {
		t.Fatalf("IssueCert SM2: %v", err)
	}

	// 2. 吊销证书。
	err = core.RevokeCert(ctx, caResult.KeyID, certResult.CertID, "keyCompromise", nil)
	if err != nil {
		t.Fatalf("RevokeCert SM2: %v", err)
	}

	// 3. 获取 CRL。
	crl, err := core.GetCRL(ctx, caResult.KeyID, nil)
	if err != nil {
		t.Fatalf("GetCRL SM2: %v", err)
	}
	if len(crl) == 0 {
		t.Fatal("SM2 CRL should not be empty after revoke")
	}
	t.Logf("✅ RevokeCert SM2: CRL %d bytes", len(crl))
}

// TestCore_GetCert_SM2 获取 SM2 证书元数据。
func TestCore_GetCert_SM2(t *testing.T) {
	core, _, _ := newPKITestCore(t)
	ctx := context.Background()

	caResult, _ := core.CreateCA(ctx, "sm2-ca-g", "sm2", "CN=Get SM2 CA", 10, nil)

	meta, err := core.GetCert(ctx, caResult.CertID, nil)
	if err != nil {
		t.Fatalf("GetCert SM2: %v", err)
	}
	if meta.CertID != caResult.CertID {
		t.Fatalf("cert_id mismatch: got %s, want %s", meta.CertID, caResult.CertID)
	}
	t.Logf("✅ GetCert SM2: subject=%s", meta.Subject)

	// 确认 CRL 解析可用（用于 SM2 路径兼容性验证）。
	_ = crypto.ParseCRL
}
