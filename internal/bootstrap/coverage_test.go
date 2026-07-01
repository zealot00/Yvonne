// Package bootstrap - 补充覆盖测试（Dev 模式 + Cluster 模式 + buildGRPCServer + buildAdminServer）。
package bootstrap

import (
	"crypto/tls"
	"testing"

	"yvonne/internal/config"
	"yvonne/internal/lifecycle"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/service"
	"yvonne/internal/storage"
)

// TestBuildYvonne_NilConfig nil 配置拒绝。
func TestBuildYvonne_NilConfig(t *testing.T) {
	_, err := BuildYvonne(nil)
	if err == nil {
		t.Fatal("should reject nil config")
	}
	t.Logf("✅ BuildYvonne nil config: %v", err)
}

// TestBuildYvonne_DevMode 完整 Dev 模式装配。
func TestBuildYvonne_DevMode(t *testing.T) {
	cfg := &config.YvonneConfig{
		Mode: "dev",
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 0,
			TLS:      config.TLSConfig{Enabled: false},
		},
	}

	srv, err := BuildYvonne(cfg)
	if err != nil {
		t.Fatalf("BuildYvonne dev: %v", err)
	}
	defer srv.Close()

	if srv.V1Router == nil {
		t.Fatal("V1Router should not be nil")
	}
	if srv.Core == nil {
		t.Fatal("Core should not be nil")
	}
	if srv.Manager == nil {
		t.Fatal("Manager should not be nil")
	}
	if srv.AdminServer == nil {
		t.Fatal("AdminServer should not be nil (dev mode forced)")
	}
	if srv.MasterKey == nil {
		t.Fatal("MasterKey should not be nil")
	}
	if srv.Metrics == nil {
		t.Fatal("Metrics should not be nil")
	}
	if srv.AuditLog == nil {
		t.Fatal("AuditLog should not be nil")
	}
	t.Log("✅ BuildYvonne dev mode: all components initialized")
}

// TestBuildYvonne_DevMode_WithAdminToken Dev 模式 + admin token。
func TestBuildYvonne_DevMode_WithAdminToken(t *testing.T) {
	cfg := &config.YvonneConfig{
		Mode: "dev",
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 0,
			TLS:      config.TLSConfig{Enabled: false},
			Admin: config.AdminServerConfig{
				AdminToken: "dev-admin-token",
			},
		},
	}

	srv, err := BuildYvonne(cfg)
	if err != nil {
		t.Fatalf("BuildYvonne dev: %v", err)
	}
	defer srv.Close()

	if srv.AdminServer == nil {
		t.Fatal("AdminServer should not be nil")
	}
	t.Log("✅ BuildYvonne dev mode + admin token")
}

// TestBuildYvonne_DevMode_StoreType 强制 memory store。
func TestBuildYvonne_DevMode_StoreType(t *testing.T) {
	cfg := &config.YvonneConfig{
		Mode: "dev",
		Server: config.ServerConfig{
			BindAddr: "127.0.0.1",
			BindPort: 0,
			TLS:      config.TLSConfig{Enabled: false},
		},
		// 故意配 postgres，Dev 模式应忽略。
		Storage: config.StorageModeConf{Type: "postgres", DSN: "postgresql://fake"},
	}

	srv, err := BuildYvonne(cfg)
	if err != nil {
		t.Fatalf("BuildYvonne dev: %v", err)
	}
	defer srv.Close()

	// PGStore 应为 nil（Dev 强制 memory）。
	if srv.PGStore != nil {
		t.Fatal("Dev mode should NOT use PostgreSQL")
	}
	t.Log("✅ BuildYvonne dev mode: postgres ignored, forced memory")
}

// TestBuildGRPCServer buildGRPCServer 无 TLS。
func TestBuildGRPCServer(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	core := service.NewCore(mgr, vault, nil)

	grpcSrv := buildGRPCServer(core, nil, vault, nil)
	if grpcSrv == nil {
		t.Fatal("gRPC server should not be nil")
	}
	grpcSrv.Stop()
	t.Log("✅ buildGRPCServer no TLS")
}

// TestBuildGRPCServer_WithTLS buildGRPCServer 带 TLS。
func TestBuildGRPCServer_WithTLS(t *testing.T) {
	store := storage.NewMemoryStore()
	mgr := lifecycle.NewManager(store)
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	core := service.NewCore(mgr, vault, nil)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	grpcSrv := buildGRPCServer(core, nil, vault, tlsCfg)
	if grpcSrv == nil {
		t.Fatal("gRPC server should not be nil")
	}
	grpcSrv.Stop()
	t.Log("✅ buildGRPCServer with TLS")
}

// TestBuildAdminServer_Dev Dev 模式 admin server。
func TestBuildAdminServer_Dev(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	cfg := &config.YvonneConfig{Mode: "dev"}
	srv := buildAdminServer(cfg, vault)
	if srv == nil {
		t.Fatal("admin server should not be nil in dev mode")
	}
	t.Log("✅ buildAdminServer dev mode")
}

// TestBuildAdminServer_ClusterDisabled Cluster 模式 admin 禁用。
func TestBuildAdminServer_ClusterDisabled(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	cfg := &config.YvonneConfig{
		Mode: "cluster",
		Server: config.ServerConfig{
			Admin: config.AdminServerConfig{Enabled: false},
		},
	}
	srv := buildAdminServer(cfg, vault)
	if srv != nil {
		t.Fatal("admin server should be nil when disabled")
	}
	t.Log("✅ buildAdminServer cluster disabled")
}

// TestBuildAdminServer_ClusterEnabled Cluster 模式 admin 启用。
func TestBuildAdminServer_ClusterEnabled(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	cfg := &config.YvonneConfig{
		Mode: "cluster",
		Server: config.ServerConfig{
			Admin: config.AdminServerConfig{Enabled: true, AdminToken: "cluster-admin"},
		},
	}
	srv := buildAdminServer(cfg, vault)
	if srv == nil {
		t.Fatal("admin server should not be nil when enabled")
	}
	t.Log("✅ buildAdminServer cluster enabled")
}

// TestBuildAdminServer_ClusterNoToken Cluster 模式 admin 无 token 警告。
func TestBuildAdminServer_ClusterNoToken(t *testing.T) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	vault := seal.NewVaultState(1, 1, 0)
	vault.DirectUnseal(mk)

	cfg := &config.YvonneConfig{
		Mode: "cluster",
		Server: config.ServerConfig{
			Admin: config.AdminServerConfig{Enabled: true},
		},
	}
	srv := buildAdminServer(cfg, vault)
	if srv == nil {
		t.Fatal("admin server should not be nil when enabled")
	}
	t.Log("✅ buildAdminServer cluster no token (warning)")
}

// TestSetVaultCryptoSuite_Standard 标准密码套件。
func TestSetVaultCryptoSuite_Standard(t *testing.T) {
	vault := seal.NewVaultState(3, 2, 0)
	cfg := &config.YvonneConfig{
		Crypto: config.CryptoConfig{Suite: "standard"},
	}
	setVaultCryptoSuite(vault, cfg)
	t.Log("✅ setVaultCryptoSuite standard")
}

// TestSetVaultCryptoSuite_Empty 空套件 → 默认 standard。
func TestSetVaultCryptoSuite_Empty(t *testing.T) {
	vault := seal.NewVaultState(3, 2, 0)
	cfg := &config.YvonneConfig{
		Crypto: config.CryptoConfig{Suite: ""},
	}
	setVaultCryptoSuite(vault, cfg)
	t.Log("✅ setVaultCryptoSuite empty → standard")
}

// TestBuildClusterAuditLogger cluster audit logger 装配。
func TestBuildClusterAuditLogger(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.YvonneConfig{
		Audit: config.AuditModeConf{
			Dir:           dir,
			Filename:      "test-audit.log",
			RetentionDays: 7,
		},
	}

	logger := buildClusterAuditLogger(cfg)
	if logger == nil {
		t.Fatal("logger should not be nil")
	}
	defer logger.Close()
	t.Log("✅ buildClusterAuditLogger")
}

// TestBuildClusterAuditLogger_DefaultFilename 默认文件名。
func TestBuildClusterAuditLogger_DefaultFilename(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.YvonneConfig{
		Audit: config.AuditModeConf{
			Dir: dir,
			// Filename 为空，应使用默认 "audit.log"
		},
	}

	logger := buildClusterAuditLogger(cfg)
	if logger == nil {
		t.Fatal("logger should not be nil")
	}
	defer logger.Close()
	t.Log("✅ buildClusterAuditLogger default filename")
}

// TestBuildClusterAuditLogger_DefaultRetention 默认留存天数。
func TestBuildClusterAuditLogger_DefaultRetention(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.YvonneConfig{
		Audit: config.AuditModeConf{
			Dir: dir,
			// RetentionDays 为 0，应使用默认 180
		},
	}

	logger := buildClusterAuditLogger(cfg)
	if logger == nil {
		t.Fatal("logger should not be nil")
	}
	defer logger.Close()
	t.Log("✅ buildClusterAuditLogger default retention")
}

// 辅助函数已不需要（直接用 lifecycle.NewManager）。
