package lifecycle

import (
	"context"
	"math/big"
	"testing"
	"time"

	"yvonne/internal/storage"
)

// newTestCertManager 创建测试用 CertManager。
func newTestCertManager(t *testing.T) *CertManager {
	t.Helper()
	store := storage.NewMemoryStore()
	return NewCertManager(store)
}

// TestCertManager_SaveAndGet 保存 + 读取证书元数据。
func TestCertManager_SaveAndGet(t *testing.T) {
	cm := newTestCertManager(t)
	ctx := context.Background()

	meta := &CertMetadata{
		CertID:       "cert-001",
		CAKeyID:      "ca-key-001",
		SerialNumber: "12345",
		Subject:      "CN=test.example.com",
		PEM:          []byte("fake PEM"),
		State:        CertStateActive,
		CertType:     "sign",
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().Add(90 * 24 * time.Hour),
	}

	if err := cm.SaveCert(ctx, meta); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}

	got, err := cm.GetCert(ctx, "cert-001")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got.CertID != "cert-001" {
		t.Fatalf("CertID = %q", got.CertID)
	}
	if got.Subject != "CN=test.example.com" {
		t.Fatalf("Subject = %q", got.Subject)
	}
	if got.State != CertStateActive {
		t.Fatalf("State = %q", got.State)
	}
	t.Log("✅ CertManager save + get")
}

// TestCertManager_RevokeCert 吊销证书。
func TestCertManager_RevokeCert(t *testing.T) {
	cm := newTestCertManager(t)
	ctx := context.Background()

	meta := &CertMetadata{
		CertID:       "cert-revoke",
		CAKeyID:      "ca-001",
		SerialNumber: "67890",
		Subject:      "CN=revoked.example.com",
		PEM:          []byte("PEM"),
		State:        CertStateActive,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().Add(90 * 24 * time.Hour),
	}
	cm.SaveCert(ctx, meta)

	// 吊销。
	if err := cm.RevokeCert(ctx, "cert-revoke", "keyCompromise"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	got, _ := cm.GetCert(ctx, "cert-revoke")
	if got.State != CertStateRevoked {
		t.Fatalf("State = %q, want Revoked", got.State)
	}
	if got.RevokedReason != "keyCompromise" {
		t.Fatalf("RevokedReason = %q", got.RevokedReason)
	}

	// 幂等：再次吊销不应报错。
	if err := cm.RevokeCert(ctx, "cert-revoke", "keyCompromise"); err != nil {
		t.Fatalf("RevokeCert idempotent: %v", err)
	}
	t.Log("✅ CertManager revoke (idempotent)")
}

// TestCertManager_SaveAndGetCRL CRL 保存 + 读取。
func TestCertManager_SaveAndGetCRL(t *testing.T) {
	cm := newTestCertManager(t)
	ctx := context.Background()

	crlDER := []byte("fake CRL DER")
	if err := cm.SaveCRL(ctx, "ca-001", crlDER); err != nil {
		t.Fatalf("SaveCRL: %v", err)
	}

	got, err := cm.GetCRL(ctx, "ca-001")
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	if string(got) != "fake CRL DER" {
		t.Fatalf("CRL = %q", string(got))
	}

	// 覆盖更新。
	crlDER2 := []byte("updated CRL DER")
	cm.SaveCRL(ctx, "ca-001", crlDER2)
	got2, _ := cm.GetCRL(ctx, "ca-001")
	if string(got2) != "updated CRL DER" {
		t.Fatalf("CRL after update = %q", string(got2))
	}
	t.Log("✅ CertManager CRL save + get + overwrite")
}

// TestCertManager_FindBySerial 按序列号查询证书。
func TestCertManager_FindBySerial(t *testing.T) {
	cm := newTestCertManager(t)
	ctx := context.Background()

	meta := &CertMetadata{
		CertID:       "cert-serial",
		CAKeyID:      "ca-find",
		SerialNumber: "11111",
		Subject:      "CN=find.example.com",
		PEM:          []byte("PEM"),
		State:        CertStateActive,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().Add(90 * 24 * time.Hour),
	}
	cm.SaveCert(ctx, meta)

	got, err := cm.FindBySerial(ctx, "ca-find", big.NewInt(11111))
	if err != nil {
		t.Fatalf("FindBySerial: %v", err)
	}
	if got.CertID != "cert-serial" {
		t.Fatalf("CertID = %q", got.CertID)
	}
	t.Log("✅ CertManager FindBySerial")
}
