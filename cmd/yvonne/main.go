// Package main 是 Yvonne KMS 的统一入口。
//
// 用法：
//
//	yvonne server --config config.json   # 按配置文件启动（dev 或 cluster 模式）
//	yvonne dev                           # 快捷开发模式（等价于 mode=dev，零配置）
//
// 优雅停机：
//   - 监听 SIGINT/SIGTERM。
//   - 收到信号后关闭 HTTP Server（10s 超时）。
//   - 释放数据库连接池、Wipe Master Key、Close audit logger。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"yvonne/internal/audit"
	"yvonne/internal/bootstrap"
	"yvonne/internal/config"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

func main() {
	// 子命令：server / dev。
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServerCmd(os.Args[2:])
	case "dev":
		runDevCmd(os.Args[2:])
	case "unseal-keygen":
		runUnsealKeygenCmd(os.Args[2:])
	case "init":
		runInitCmd(os.Args[2:])
	case "backup-split":
		runBackupSplitCmd(os.Args[2:])
	case "backup-restore":
		runBackupRestoreCmd(os.Args[2:])
	case "audit-verify":
		runAuditVerifyCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Yvonne KMS - Production-Grade Key Management System

Usage:
  yvonne server --config <path>      Start with config file (dev or cluster mode)
  yvonne dev                         Quick dev mode (zero config, in-memory only)
  yvonne unseal-keygen --out <path>  Generate RSA-4096 key pair for local_pki unseal
  yvonne init --config <path> [--pub-key <path>] [--wrapped-out <path>]
                                     Initialize: generate CMK, encrypt with public key,
                                     write to DB. Optionally copy wrapped CMK to USB drive.
  yvonne backup-split --config <path> --out-dir <dir> [--total 5] [--threshold 3]
                                     Split wrapped CMK into Shamir shares on USB drives.
  yvonne backup-restore --out <path> <share1> <share2> <share3>...
                                     Restore wrapped CMK from Shamir share files.
  yvonne audit-verify --dir <dir>    Verify audit log hash chain integrity.

Examples:
  yvonne server --config config.json
  yvonne dev --port 9000
  yvonne unseal-keygen --out /var/run/yvonne/unseal.pem
  yvonne init --config config.json --pub-key /tmp/unseal_pub.pem
  yvonne init --config config.json --pub-key /tmp/unseal_pub.pem --wrapped-out /mnt/usb/yvonne-cmk-backup.bin

Flags for 'server':
  --config string   Path to JSON config file (required)

Flags for 'dev':
  --port int        Override bind port (default 8200)
  --addr string     Override bind address (default 127.0.0.1)

Flags for 'unseal-keygen':
  --out string      Output path for private key PEM file (required)

Flags for 'init':
  --config string    Path to JSON config file with PostgreSQL DSN (required)
  --pub-key string   Path to RSA public key PEM (from unseal-keygen stdout, required)
  --wrapped-out string  Optional: copy wrapped CMK to this path (e.g. USB drive mount point)`)
}

// runServerCmd 处理 `yvonne server --config <path>`。
func runServerCmd(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "", "path to JSON config file (required)")
	_ = fs.Parse(args)

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required for 'server' command")
		os.Exit(1)
	}

	cfg, err := config.LoadYvonneConfig(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	startYvonne(cfg)
}

// runDevCmd 处理 `yvonne dev`（快捷开发模式）。
func runDevCmd(args []string) {
	fs := flag.NewFlagSet("dev", flag.ExitOnError)
	port := fs.Int("port", 8200, "bind port")
	addr := fs.String("addr", "127.0.0.1", "bind address")
	_ = fs.Parse(args)

	// 构造 Dev 模式配置（零配置文件）。
	cfg := &config.YvonneConfig{
		Mode: config.ModeDev,
		Server: config.ServerConfig{
			BindAddr: *addr,
			BindPort: *port,
			Admin: config.AdminServerConfig{
				Enabled:  true,
				BindAddr: "127.0.0.1",
				BindPort: 8250,
			},
		},
		Storage: config.StorageModeConf{
			Type: "memory",
		},
		Unseal: config.UnsealModeConf{
			Type:        "auto",
			TotalShares: 1,
			Threshold:   1,
		},
		Logging: config.LoggingConfig{
			Level:         "info",
			Format:        "json",
			Output:        "stdout",
			RedactSecrets: true,
		},
	}

	if err := config.ValidateYvonneConfig(cfg); err != nil {
		log.Fatalf("dev config validation failed: %v", err)
	}

	startYvonne(cfg)
}

// startYvonne 装配并启动 Yvonne 实例。
func startYvonne(cfg *config.YvonneConfig) {
	// 装配。
	srv, err := bootstrap.BuildYvonne(cfg)
	if err != nil {
		log.Fatalf("build yvonne failed: %v", err)
	}
	defer srv.Close()

	// Cluster 模式 TLS 未启用时打印醒目警告（审计留痕）。
	if cfg.Mode == config.ModeCluster && !cfg.Server.TLS.Enabled {
		const red = "\033[31m"
		const bold = "\033[1m"
		const reset = "\033[0m"
		log.Printf("%s%sWARNING: Cluster mode running without TLS. Transport layer is NOT encrypted!%s",
			red, bold, reset)
		log.Printf("WARNING: Ensure API is behind mTLS service mesh or reverse proxy with TLS termination.")
		_ = srv.AuditLog.Record(audit.LogEntry{
			Timestamp: time.Now().UTC(),
			Actor:     "SYSTEM_BOOTSTRAP",
			Action:    "TLSWarning",
			Resource:  "transport",
			Result:    "warning: tls disabled in cluster mode",
		})
	}

	// 创建主 HTTP Server（业务 API）。
	httpSrv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.BindAddr, cfg.Server.BindPort),
		Handler:      srv.V1Router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 创建 Admin HTTP Server（Web UI）。
	var adminHTTPSrv *http.Server
	if srv.AdminServer != nil {
		adminAddr := "127.0.0.1:8250"
		if cfg.Server.Admin.BindAddr != "" && cfg.Server.Admin.BindPort != 0 {
			adminAddr = fmt.Sprintf("%s:%d", cfg.Server.Admin.BindAddr, cfg.Server.Admin.BindPort)
		}
		adminHTTPSrv = &http.Server{
			Addr:         adminAddr,
			Handler:      srv.AdminServer,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
	}

	// 创建全局 context（支持优雅停机，传递给 RotationDaemon）。
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// 启动 RotationDaemon（Cluster 模式）。
	if srv.RotationDaemon != nil {
		srv.RotationDaemon.Start(rootCtx)
		log.Printf("rotation daemon started (hourly scan)")
	}

	// 启动监听。
	errCh := make(chan error, 2)
	go func() {
		log.Printf("yvonne API listening on %s", httpSrv.Addr)
		if cfg.Server.TLS.Enabled {
			log.Printf("TLS enabled: cert=%s", cfg.Server.TLS.CertFile)
			if err := httpSrv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		} else {
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}
	}()
	if adminHTTPSrv != nil {
		go func() {
			log.Printf("yvonne admin UI listening on %s", adminHTTPSrv.Addr)
			if err := adminHTTPSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	// 监听信号。
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		log.Printf("received signal %s, shutting down gracefully...", sig)
	case err := <-errCh:
		log.Printf("server error: %v", err)
	}

	// 优雅停机顺序（防 in-flight panic）：
	// 1. 取消全局 context（通知 Daemon 退出 + 停止后台任务）
	// 2. HTTP Shutdown（拒绝新请求，等待 in-flight 完成，10s 超时）
	// 3. srv.Close() 由 defer 触发（Wipe masterKey + Close audit + Close DB）
	//
	// 关键：HTTP Shutdown 必须在 Wipe 之前完成，防止 in-flight 请求读到已清零密钥。
	rootCancel() // 先通知 Daemon 退出

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("WARNING: http shutdown timeout/error: %v (in-flight requests may be interrupted)", err)
	}
	if adminHTTPSrv != nil {
		if err := adminHTTPSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("WARNING: admin http shutdown error: %v", err)
		}
	}

	// HTTP 完全停止后，srv.Close() 由 defer 触发：Wipe masterKey + Close audit + Close DB。
	log.Printf("yvonne stopped")
}

// runUnsealKeygenCmd 处理 `yvonne unseal-keygen --out <path>`。
// 生成 RSA-4096 密钥对，私钥写入 --out 文件，公钥输出到 stdout。
func runUnsealKeygenCmd(args []string) {
	fs := flag.NewFlagSet("unseal-keygen", flag.ExitOnError)
	outPath := fs.String("out", "", "output path for private key PEM file (required)")
	_ = fs.Parse(args)

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required for 'unseal-keygen' command")
		os.Exit(1)
	}

	log.Println("generating RSA-4096 key pair (this may take a moment)...")
	privPEM, pubPEM, err := seal.GenerateUnsealKeyPair()
	if err != nil {
		log.Fatalf("generate key pair failed: %v", err)
	}

	// 写入私钥 PEM 文件（权限 0600，仅 owner 可读）。
	if err := os.WriteFile(*outPath, privPEM, 0o600); err != nil {
		log.Fatalf("write private key file failed: %v", err)
	}
	log.Printf("private key written to %s (mode 0600)", *outPath)

	// 输出公钥到 stdout（供初始化加密 Master Key 用）。
	fmt.Println("# Public key (use this to encrypt the Master Key for initial setup):")
	os.Stdout.Write(pubPEM)

	// 安全清理内存中的 PEM 数据（虽然 GC 会回收，但保持纪律性）。
	for i := range privPEM {
		privPEM[i] = 0
	}
	for i := range pubPEM {
		pubPEM[i] = 0
	}
}

// runInitCmd 处理 `yvonne init`。
//
// 流程：
//  1. 加载配置（获取 PostgreSQL DSN）
//  2. 读取 RSA 公钥 PEM（来自 unseal-keygen 的 stdout 输出）
//  3. 生成 32 字节随机 CMK
//  4. 用公钥 RSA-OAEP 加密 CMK → Wrapped CMK
//  5. 写入 DB（key: "master-key-wrapped"）
//  6. 可选：复制 Wrapped CMK 到 --wrapped-out 路径（USB 盘冷备份）
//  7. 阅后即焚：CMK 明文 Wipe
func runInitCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "", "path to JSON config file with PostgreSQL DSN (required)")
	pubKeyPath := fs.String("pub-key", "", "path to RSA public key PEM (required)")
	wrappedOut := fs.String("wrapped-out", "", "optional: copy wrapped CMK to this path (USB drive)")
	_ = fs.Parse(args)

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required for 'init' command")
		os.Exit(1)
	}
	if *pubKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --pub-key is required for 'init' command")
		os.Exit(1)
	}

	// 1. 加载配置。
	cfg, err := config.LoadYvonneConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Storage.Type != "postgres" {
		log.Fatal("init: storage.type must be 'postgres' for cluster mode initialization")
	}

	// 2. 读取 RSA 公钥 PEM。
	pubKeyPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		log.Fatalf("read public key: %v", err)
	}

	// 3. 连接 PostgreSQL。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pgStore, err := storage.NewPostgresKVStore(ctx, cfg.Storage.DSN)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pgStore.Close(ctx)

	// 4. 检查是否已初始化（防止覆盖现有 CMK）。
	existing, err := pgStore.Get(ctx, seal.WrappedMasterKeyKey)
	if err == nil && len(existing) > 0 {
		log.Fatalf("FATAL: master-key-wrapped already exists in DB. Aborting to prevent overwrite. " +
			"If you need to re-initialize, manually delete the 'master-key-wrapped' key first.")
	}

	// 5. 生成 32 字节随机 CMK。
	cmk, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		log.Fatalf("generate CMK: %v", err)
	}
	defer cmk.Wipe()

	// 6. 用公钥 RSA-OAEP 加密 CMK → Wrapped CMK。
	wrappedCMK, err := seal.EncryptMasterKeyWithPublicKey(pubKeyPEM, cmk)
	if err != nil {
		log.Fatalf("encrypt CMK with public key: %v", err)
	}

	// 7. 写入 DB。
	if err := pgStore.Put(ctx, seal.WrappedMasterKeyKey, wrappedCMK); err != nil {
		log.Fatalf("write wrapped CMK to DB: %v", err)
	}
	log.Printf("wrapped CMK written to DB (key: %s, %d bytes)", seal.WrappedMasterKeyKey, len(wrappedCMK))

	// 8. 可选：复制到 USB 盘（冷备份）。
	if *wrappedOut != "" {
		if err := os.WriteFile(*wrappedOut, wrappedCMK, 0o400); err != nil {
			log.Fatalf("write wrapped CMK to USB: %v", err)
		}
		log.Printf("wrapped CMK copied to %s (mode 0400, read-only)", *wrappedOut)
		log.Printf("NOTE: Safely eject the USB drive and store it in a physically secure offsite location.")
	}

	// 9. 验证：从 DB 读回并确认长度一致。
	verify, err := pgStore.Get(ctx, seal.WrappedMasterKeyKey)
	if err != nil {
		log.Fatalf("verification read failed: %v", err)
	}
	if len(verify) != len(wrappedCMK) {
		log.Fatalf("verification failed: DB length %d != written %d", len(verify), len(wrappedCMK))
	}

	log.Printf("init complete. CMK generated and wrapped with RSA-4096 OAEP.")
	log.Printf("next steps:")
	log.Printf("  1. Run 'yvonne server --config %s' to start with local_pki auto-unseal", *configPath)
	log.Printf("  2. Ensure the PEM private key is accessible at the configured pki_key_path")
	if *wrappedOut == "" {
		log.Printf("  3. (Optional) Re-run with --wrapped-out to create a USB cold backup")
	}
}

// runBackupSplitCmd 处理 `yvonne backup-split`。
// 从 DB 读取 Wrapped CMK，Shamir 分片后写入多个 USB 盘文件。
func runBackupSplitCmd(args []string) {
	fs := flag.NewFlagSet("backup-split", flag.ExitOnError)
	configPath := fs.String("config", "", "path to JSON config file (required)")
	outDir := fs.String("out-dir", "", "output directory for share files (required, e.g. /mnt/usb)")
	total := fs.Int("total", 5, "total number of shares (USB drives)")
	threshold := fs.Int("threshold", 3, "threshold for recovery (minimum shares needed)")
	_ = fs.Parse(args)

	if *configPath == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "error: --config and --out-dir are required")
		os.Exit(1)
	}

	cfg, err := config.LoadYvonneConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pgStore, err := storage.NewPostgresKVStore(ctx, cfg.Storage.DSN)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pgStore.Close(ctx)

	// 从 DB 读取 Wrapped CMK。
	wrappedCMK, err := pgStore.Get(ctx, seal.WrappedMasterKeyKey)
	if err != nil {
		log.Fatalf("read wrapped CMK from DB: %v", err)
	}

	// Shamir 分片写入文件。
	paths, err := seal.SplitWrappedCMKToFiles(wrappedCMK, *total, *threshold, *outDir)
	if err != nil {
		log.Fatalf("split: %v", err)
	}

	log.Printf("split complete: %d shares written to %s (threshold=%d)", len(paths), *outDir, *threshold)
	for _, p := range paths {
		log.Printf("  %s", p)
	}
	log.Printf("distribute each file to a separate USB drive and store in different physical locations.")
}

// runBackupRestoreCmd 处理 `yvonne backup-restore`。
// 从多个分片文件重组 Wrapped CMK，写入指定路径。
func runBackupRestoreCmd(args []string) {
	fs := flag.NewFlagSet("backup-restore", flag.ExitOnError)
	outPath := fs.String("out", "", "output path for restored wrapped CMK (required)")
	_ = fs.Parse(args)

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: --out is required")
		os.Exit(1)
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "error: need at least 2 share files")
		os.Exit(1)
	}

	sharePaths := fs.Args()
	wrappedCMK, err := seal.CombineWrappedCMKFromFiles(sharePaths)
	if err != nil {
		log.Fatalf("restore: %v", err)
	}

	if err := os.WriteFile(*outPath, wrappedCMK, 0o400); err != nil {
		log.Fatalf("write: %v", err)
	}

	log.Printf("restored wrapped CMK (%d bytes) to %s", len(wrappedCMK), *outPath)
	log.Printf("to restore DB: yvonne init --config <path> --pub-key <path> (after manually putting this file back into DB)")
}

// runAuditVerifyCmd 处理 `yvonne audit-verify --dir <dir>`。
// 验证审计日志哈希链完整性，报告篡改/损坏的条目。
func runAuditVerifyCmd(args []string) {
	fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
	dir := fs.String("dir", "", "audit log directory (required)")
	_ = fs.Parse(args)

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required for 'audit-verify' command")
		os.Exit(1)
	}

	// 创建临时 logger 仅用于 Query（不需要写入能力）。
	logger, err := audit.NewAuditLogger(nil)
	if err != nil {
		log.Fatalf("create audit logger: %v", err)
	}
	defer logger.Close()

	results, err := logger.Query(*dir, audit.QueryFilter{Limit: -1})
	if err != nil {
		log.Fatalf("audit query failed: %v", err)
	}

	if len(results) == 0 {
		log.Printf("no audit entries found in %s", *dir)
		return
	}

	total := len(results)
	valid := 0
	tampered := 0
	var brokenEntries []string

	for _, r := range results {
		if r.Valid {
			valid++
		} else {
			tampered++
			brokenEntries = append(brokenEntries, fmt.Sprintf("  chain_seq=%d timestamp=%s actor=%s action=%s",
				r.Envelope.ChainSeq, r.Entry.Timestamp, r.Entry.Actor, r.Entry.Action))
		}
	}

	log.Printf("audit chain verification complete:")
	log.Printf("  total entries: %d", total)
	log.Printf("  valid:         %d", valid)
	log.Printf("  tampered:      %d", tampered)

	if tampered > 0 {
		log.Printf("BROKEN ENTRIES:")
		for _, e := range brokenEntries {
			log.Print(e)
		}
		os.Exit(1) // 篡改发现，退出码 1
	}

	log.Printf("✓ audit chain integrity verified")
}
