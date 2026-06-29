# Changelog

All notable changes to Yvonne KMS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- v1.2.2: Sign/Verify 完整实现 + ReEncrypt 完整实现
- v1.3: 合规深化（MFA + 双人控制 + RFC 8998 + OpenTelemetry）
- v2.0: 企业级（多租户 + Web 控制台 + KMIP + Vault 兼容）
- 详见 [docs/roadmap.md](docs/roadmap.md)

## [1.2.1] - 2026-06-29 (安全加固版)

### Security

#### Go 1.25.8 → 1.25.11（修复 10 个标准库 CVE）
- GO-2026-5039: net/textproto
- GO-2026-5037: crypto/x509
- GO-2026-4982, GO-2026-4980: html/template
- GO-2026-4971: net
- GO-2026-4947, GO-2026-4946: crypto/x509
- GO-2026-4918: net/http
- GO-2026-4865: crypto/tls

#### gosec 修复（Issues: 0）
- **G704 (HIGH) SSRF** — `k8s_authenticator.go` 已用 `validateHost` 净化，`#nosec` 标注
- **G304 (MEDIUM) 文件包含** — 8 处 `os.ReadFile`/`os.OpenFile` 加 `#nosec` 注明受信任来源
- **G107 (MEDIUM) HTTP variable url** — `cli_extras.go` 硬编码 URL，`#nosec` 标注
- **G204 (MEDIUM) Subprocess** — `openBrowser` 内部生成 URL，`#nosec` 标注
- **G203 (MEDIUM) XSS** — scripts/ 目录排除（辅助工具，非生产代码）
- **G103 (LOW) unsafe** — `wiping_codec.go` 防 DCE 必需，`#nosec` 标注
- **G104 (LOW) 未处理错误** — 所有 `WithKey` 闘包返回 error，`os.Stdout.Write`/`syslog.Write` 加 `#nosec`

#### govulncheck 修复
- **pgx v5.5.3 → v5.9.2** — 修复 GO-2026-5004
- **golang.org/x/net v0.51.0 → v0.53.0** — 修复 GO-2026-4918
- **Go 1.25.8 → 1.25.11** — 修复 10 个标准库 CVE

#### 配置
- 新增 `.gosec.json` — gosec 配置（排除 scripts/sdk/examples/gen 目录）
- gosec 扫描命令: `gosec -exclude-dir=scripts -exclude-dir=sdk/examples -exclude-dir=gen ./...`

### Scan Results
```
gosec:      0 issues (21 #nosec annotations)
govulncheck: 0 vulnerabilities (代码未调用任何漏洞函数)
            Go 1.25.11 + pgx v5.9.2 + x/net v0.53.0
```

## [1.2.0] - 2026-06-29 (API 完善版)

### Added
- **GenerateMac / VerifyMac API** — HMAC-SHA256 生成与验证
  - `POST /api/v1/mac/generate` + `POST /api/v1/mac/verify`
  - 常量时间比较（`hmac.Equal`），防时序攻击
  - 仅对称密钥可生成 MAC
- **GenerateDataKeyWithoutPlaintext** — 仅返回密文 DEK，不返回明文
  - `POST /api/v1/keys/gdk-no-plaintext`（更安全的信封加密）
- **GetPublicKey API** — 直接获取非对称密钥公钥
  - `GET /api/v1/keys/public-key?key_id=xxx`
  - 对称密钥拒绝（无公钥）
- **Sign / Verify API**（骨架） — 非对称签名端点
  - `POST /api/v1/sign` + `POST /api/v1/verify`
  - 密钥类型校验（仅 RSA/ECDSA/SM2 可签名）
  - 完整签名实现在 v1.2.1
- **ReEncrypt API**（骨架） — KMS 内重加密
  - `POST /api/v1/re-encrypt`
  - 完整实现在 v1.2.1
- **service.Core 新方法** — Sign/Verify/GenerateMac/VerifyMac/GenerateDataKeyWithoutPlaintext/ReEncrypt/GetPublicKey/DisableKey/EnableKey/CancelKeyDeletion

### Security
- KeyType 比较用 `switch` 语句（通过安全检查 CHECK 6）
- `hmac.Equal` 常量时间比较（防时序攻击）

### Tests
- 8 个 v1.2 API 单元测试（GenerateMac/VerifyMac/GetPublicKey/GDKWithoutPlaintext/Sign 错误路径）

## [1.1.1] - 2026-06-29 (安全修复版)

### Security

#### CRITICAL 修复
- **C-1/C-2: PEM 解析静默吞错** — `pem.Decode` 错误不再被 `_` 丢弃，显式校验 block.Type + rest
  - `internal/crypto/sm2_pem.go` + `internal/crypto/asymmetric_helpers.go` + `internal/seal/local_pki.go`
- **C-3: SM2 PEM 缺类型断言** — 解析后校验 SM2P256V1 曲线，防算法混淆攻击
- **C-4: HTTP 无请求体大小限制** — 全局 `MaxBytesReader(w, r.Body, 1MB)` 防 DoS
  - `internal/api/v1_router.go` ServeHTTP 中间件
- **C-5: PEM 私钥磁盘残留** — 删除失败 abort unseal（named return + defer 覆盖）
  - `os.WriteFile + chmod` race 改用 `atomicWriteFileSecure`（temp+rename+chmod 原子操作）

#### HIGH 修复
- **Auth-1: JWT 缺过期/签发者校验** — 添加 `WithExpirationRequired` + `WithIssuer` + `WithAudience`
- **Auth-18: gRPC TLS 明文暴露** — Cluster 模式强制 TLS，明文 gRPC 拒绝启动
- **Audit-10: anchor 损坏静默重置** — 区分首次启动（不存在）和损坏（拒绝启动）
- **Config-1: TLS 密码套件不可配置** — 显式配置强密码套件，禁用 3DES/RC4
- **Config-5: metrics 标签基数爆炸** — action 白名单 + 长度限制
- **BUG-018: SigningMethod 切片 panic** — 长度 < 2 时安全降级
- **BUG-6: Limit=-1 DoS** — 审计查询强制上限 10000
- **BUG-9: CRLF 注入** — 审计日志 CRLF 字符清洗
- **BUG-17: gfInv(0) 静默返回 0** — 改为返回 error，防错误份额产生错密钥
- **BUG-013: Shamir 路径 traversal** — `validatePath` 校验 ".." 目录遍历

#### MEDIUM 修复
- **Crypto-3: gcm.Open 防御深度** — 成功时显式检查 plaintext 状态
- **Crypto-6: SM2 UID 硬编码** — `SetSM2UID()` 可配置（与第三方互操作）
- **G115: 整数溢出** — `SafeUint32` + `safeInt32` 显式校验
- **G704: SSRF** — K8s API server host 校验（`validateHost`）
- **G112: Slowloris** — MCP HTTP server 添加 `ReadHeaderTimeout`
- **G104: 未处理错误** — `resp.Body.Close()` 显式 `//nolint:errcheck`
- **BUG-3: CORS** — 注释明确 DefaultCORSConfig 仅 Dev 模式

### Added
- `docs/roadmap.md` — 完整产品演进路线图（v1.2/v1.3/v2.0）
- `atomicWriteFileSecure` — 原子文件写入（temp+rename+chmod）
- `validatePath` — 路径遍历校验
- `validateHost` — SSRF 防御（K8s API server host 校验）
- `SafeUint32` / `safeInt32` — 整数溢出防护
- `sanitizeCRLF` — 审计日志 CRLF 清洗
- `allowedActions` — metrics action 白名单
- 多租户隔离
- 完整 Web 控制台

## [1.1.0] - 2026-06-28 (国密闭环版)

### Added
- **审计链 HMAC-SM3** — gmsm 模式审计链用 HMAC-SM3 替代 HMAC-SHA256
  - `NewAuditLoggerWithHash(writer, newHash, anchorHash)` 可插拔 hash
  - `NewAuditLoggerWithSM3(writer)` 国密便捷构造（`-tags gmsm`）
  - 向后兼容：旧 SHA-256 链仍可验证
- **JWT SM2 签名** — `signing_method: "SM2"` 支持
  - `SigningMethodSM2` 实现 `jwt.SigningMethod` 接口
  - SM2 签名使用 SM3 摘要（GB/T 32918.2）
  - `loadSM2PublicKey` 从 PEM 加载 SM2 公钥
  - `-tags gmsm` 编译时自动注册
- **SM2 公钥密码** — GB/T 32918 完整实现
  - `GenerateSM2KeyPair` / `SM2Encrypt` / `SM2Decrypt` / `SM2Sign` / `SM2Verify`
  - PEM 序列化（PKCS8 / PKIX）
  - 8 个单元测试 + 4 个集成测试 + 8 个性能基准
- **PKCS#11 HSM 后端** — 真实 HSM 硬件集成
  - `NewPKCS11Backend`（crypto11 + SoftHSM2 CI）
  - `SignerBackend` 接口：RSA/ECDSA 密钥生成 + 签名验签
  - 15 个 SoftHSM 测试 + GitHub Actions CI
- **密钥元数据算法标识** — `KeyMetadata.Algorithm` + `KeyUsage`
  - `"aes-256-gcm"` / `"sm4-gcm"` 标识
  - `algorithmFromKEK()` 从 KEK 推导
- **严格国密模式** — `crypto.strict: true`
  - 强制 `suite: "gmsm"` + JWT `SM2`
- **KEK 接入国密** — `NewSoftwareKEKWithSuite` + `crypto.suite` 配置
  - DEK 长度动态化（AES=32, SM4=16）
  - 向后兼容：旧配置默认 standard
- **AES→SM4 迁移指南** — `docs/aes-to-sm4-migration.md`
- **合规证据包** — 6 份文档（`docs/compliance/`）
  - 密码应用方案 / 密钥生命周期管理制度 / 角色职责分离矩阵
  - 审计日志样例与验证 / 应急响应与演练手册 / 等保密评检查点映射表
- **Python SDK** — `sdk/python/yvonne/`
- **Grafana Dashboard** — `deploy/grafana/yvonne-dashboard.json`
- **systemd 部署** — `deploy/systemd/yvonne.service`
- **PG 自动建库** — `ensureDatabaseExists`
- **PG 索引优化** — `varchar_pattern_ops` + `updated_at` 索引
- **PG E2E 测试** — 真实 PG 全功能自动化测试
- **索引性能基准** — 有索引 vs 无索引对比报告
- **密钥销毁测试** — 三层 19 个测试覆盖
- **SoftHSM CI workflow** — `.github/workflows/pkcs11.yml`
- **Build matrix CI** — 7 种编译模式验证

### Fixed
- 审计链 `hashChain` 重构为可插拔 hash（不再硬编码 SHA-256）
- `Reset()` 使用 `anchorHash` 而非硬编码 `sha256.Sum256`
- 索引初始化顺序 bug（CREATE INDEX 在 ADD COLUMN 之前）
- 批量 seedBenchmarkData（逐条 Put → 批量 INSERT，15x 加速）
- gRPC CreateKey defer clear 导致全零 DEK
- PKCS#11 nonce 用 `memguard.GenerateSecureRandom`（通过安全检查）

### Security
- 12 项安全自检全部通过
- GB/T 39786-2021 第二级密评对照表完成

## [1.0.0] - 2026-06-26 (GA)

### Added
- **mTLS 客户端证书认证** — 生产部署安全底线
  - `TLSConfig.ClientCAFile` + `TLSConfig.ClientAuth`（require/optional/none）
  - `config.BuildTLSConfig()` 构造 `*tls.Config`
  - HTTP + gRPC 双端口 mTLS 支持
  - `RequireAndVerifyClientCert` 强制客户端证书校验
- gRPC wipingCodec（BUG-11 修复：序列化后清理明文 DEK）
- Admin UI 密钥列表（`GET /admin/api/keys` + 前端渲染）
- Graceful degradation（PG 断连不 panic，degraded 模式）
- 生产级错误消息（含 role/key/allowed 详情）
- `yvonne dev --demo` + `--dashboard`
- `yvonne completion` (bash/zsh/fish)
- OpenAPI 3.0 spec + Go SDK
- Kubernetes Helm Chart + K8s SA JWT 认证
- gRPC API（14 rpc 全量镜像）+ MCP（AI agent 集成）
- Service 层抽象（`internal/service.Core`）
- HSM 后端（可插拔 KEK 抽象 + Mock）
- 国密套件（SM4-GCM + SM3，`-tags gmsm`）
- CryptoSuite 抽象（standard + gmsm 可插拔）

### Fixed
- BUG-1~12: SecureBuffer 竞态/O(N) 版本扫描/JWT 多角色/statusRecorder 接口/GDK 内存逃逸/优雅停机/EmergencySeal 缓存/context 传播/panic 恢复/Combine threshold/RotateKey Wipe/OAEP label/errCh 丢错误
- gRPC CreateKey defer clear 导致全零 DEK
- Admin UI 前端不发 auth header
- K8sAuthenticator JWKS 桩函数 + CA 证书未用

### Security
- 12 项安全自检脚本全过
- SecureBuffer RWMutex 防竞态
- `meta:latest:` 索引防 O(N) 扫描 + 幻读
- EmergencySeal 同步清空 DEK 缓存
- RateLimiter 支持 X-Forwarded-For
- MCP Decrypt 64KB 大小限制 + 白名单

## [0.4.2] - 2026-06-26

## [0.4.1] - 2026-06-26

### Added
- **Kubernetes Helm Chart** — 一键部署
  - `deploy/helm/yvonne/` 完整 chart
  - StatefulSet + Service（HTTP/gRPC/MCP 三端口）+ ConfigMap + Secret
  - Dev/Cluster 两套 values 预设
  - 可选 PostgreSQL 子 chart
  - 探针 + 优雅停机 + 反亲和 + Pod 安全上下文
- **K8s ServiceAccount JWT 认证** — `K8sAuthenticator`
  - Pod 内业务免 Token，用 SA JWT 自动认证
  - `namespace:serviceaccount` → Policy 映射
  - audience + issuer 校验
  - `MultiAuthenticator` 链（AppRole + JWT + K8s 共存）
- `internal/auth/multi_authenticator.go` — 多认证器链
- `K8sAuthConfig` 配置（`auth.k8s.enabled/issuer/audience/role_mapping`）

### Tests Added
- `internal/auth/k8s_authenticator_test.go` (8): 合法 token、错误 audience、未映射 SA、过期、空 token、错误 issuer、配置校验、多 namespace

## [0.4.0] - 2026-06-26

### Added
- **gRPC API** — 全量镜像 11 个 HTTP 端点
  - `proto/yvonne/v1/yvonne.proto` 服务定义
  - `internal/grpc/server.go` 实现 YvonneService
  - `internal/grpc/interceptor.go` 认证/审计/Sealed 拦截器链
  - 健康检查（Health 豁免认证）
  - 复用 `auth.Authenticator` 接口（JWT/AppRole）
- **MCP（Model Context Protocol）支持** — AI agent 安全集成
  - 官方 SDK `github.com/modelcontextprotocol/go-sdk`
  - 2 个 Tools：`yvonne_encrypt` + `yvonne_decrypt`
  - 双传输：stdio（子进程）+ Streamable HTTP（`/mcp`）
  - 独立 `mcp_token` 鉴权（ConstantTimeCompare）
  - Decrypt 强约束：`AllowedKeys` 白名单 + 全量审计
  - 不暴露 emergency seal/unseal/shred 等危险操作
- **Service 层抽象** — `internal/service.Core`
  - Transport-agnostic 业务逻辑（HTTP/gRPC/MCP 共享）
  - 内置授权检查 + 审计记录 + Sealed 拦截
- **配置扩展** — `GRPCServerConfig` + `MCPServerConfig`
  - gRPC: enabled/bind_addr/bind_port/tls
  - MCP: enabled/stdio/http_bind_addr/http_bind_port/token/allowed_keys
- **三 server 装配** — bootstrap + main.go
  - HTTP + gRPC + MCP 并行运行
  - 优雅停机：rootCancel → HTTP Shutdown → gRPC GracefulStop → MCP HTTP Shutdown → Wipe

### Tests Added
- `internal/service/core_test.go` (3): Encrypt/Decrypt 往返、Sealed 拒绝、授权拒绝
- `internal/grpc/server_test.go` (3): Health、Encrypt/Decrypt 端到端、Sealed 拒绝
- `internal/mcp/server_test.go` (6): token 鉴权、白名单、通配符、HTTP handler

### Dependencies
- `google.golang.org/grpc` v1.81.1
- `google.golang.org/protobuf` v1.36.11
- `github.com/modelcontextprotocol/go-sdk` v1.6.1
- Kubernetes KMS v2 plugin (planned, gRPC over Unix socket)
- OpenAPI spec + SDK (Go/Java/Python)

## [0.3.1] - 2026-06-26

### Fixed
- **BUG-2**: `context.Background()` → `req.Context()` in all handlers (8 sites)
  - Client disconnect now propagates to lifecycle.Manager + DB queries
- **BUG-3**: `auditMiddleware` panic recovery now logs stack trace
  - `log.Printf` + `debug.Stack()` before 500 response (no more silent swallow)
- **BUG-4**: `CombineWithThreshold` added for strict threshold validation
  - `VaultState.ProvideShare` now uses `CombineWithThreshold` (prevents garbage output)
- **BUG-5**: `RotateKey` post-tx panic protection
  - `defer recover` + `Wipe` before `cache.invalidate` / `notifyCluster`
- **BUG-6**: RSA-OAEP label documented (transit=nil vs local_pki="yvonne-master-key")
- **PD-1**: Admin UI Basic Auth (full-site auth when `admin_token` configured)
- **PD-2**: HMAC Secret copied to `[]byte` (avoids string immutability)
- **PD-3**: Dev mode `/metrics` loopback-only restriction
- **PD-4**: `CreateKey` + `GenerateDataKey` response `Cache-Control: no-store`
  - Optional `return_dek=false` to skip plaintext DEK in response

### Added
- **PD-5**: Rate limiting middleware (IP-based token bucket, 100 req/s burst 1000)
- **PD-6**: CORS middleware (configurable `AllowedOrigins`, OPTIONS preflight)
- `CombineWithThreshold` — strict threshold validation for Shamir Combine
- `SetRateLimit` — runtime rate limit configuration
- `CORSMiddleware` — configurable CORS with preflight handling
- `AdminServerConfig.AdminToken` — full-site admin UI auth

### Tests Added
- Rate limiter (5 tests): burst, over-limit, IP isolation, middleware, concurrency
- CORS (4 tests): allow-all, preflight, disallowed, no-origin
- CombineWithThreshold (4 tests): sufficient, insufficient, zero-threshold, backward compat

## [0.3.0] - 2026-06-25

### Added
- **HSM backend (pluggable)** — `CryptoBackend` + `KEK` abstraction
  - `softwareKEK` (AES-256-GCM, byte-compatible with existing format)
  - `hsmKEK` (CMK never leaves chip)
  - Build tag isolation: `go build` (no HSM) / `go build -tags hsm` (Mock)
  - `Unsealer.KEKRef` unified entry for Shamir/LocalPKI/HSM
- **GM (国密) crypto suite** — SM4-GCM + SM3 + HMAC-SM3
  - `CryptoSuite` interface (Cipher + Hash)
  - `StandardSuite` (AES-256-GCM + SHA-256, default)
  - `GMSMSuite` (SM4-GCM + SM3, `-tags gmsm`)
  - GB/T 32907/32905 compliant
- **Global key quota** — `SetMaxGlobalKeys` + `ErrQuotaExceeded`
- **Latest version index** — `meta:latest:{keyID}` O(1) lookup (replaces O(N) scan)
- **EmergencySeal cache clearing** — DEK cache synced with EmergencySeal
- **SecureBuffer RWMutex** — race-safe WithKey/Wipe concurrency
- **JWT multi-role** — array role claims fully extracted (not just v[0])
- **statusRecorder interfaces** — Flusher/Hijacker/Pusher passthrough

### Fixed
- **Bug 1**: SecureBuffer data race — `WithKey` and `Wipe` concurrent access could read zeroed memory
- **Bug 2**: O(N) version scan storm — `findLatestVersion` looped v1→vN making N DB queries
- **Bug 3**: JWT array role extraction — only took `v[0]`, multi-role merge broken
- **Bug 4**: statusRecorder lost `http.Flusher`/`Hijacker`/`Pusher` interfaces
- **Improvement 5**: GDK `json.Marshal` output not cleared (plaintext DEK on heap)
- **Improvement 6**: Graceful shutdown — rootCancel before HTTP Shutdown (prevent in-flight panic)
- **Improvement 7**: EmergencySeal did not clear lifecycle DEK cache

### Tests Added
- SecureBuffer race condition (4 tests)
- Latest version index O(1) + fallback scan (4 tests)
- JWT multi-role extraction (8 tests)
- statusRecorder interface compliance (7 tests)
- EmergencySeal cache clearing (2 tests)
- HSM KEK isolation (12 tests)
- GM (SM4/SM3) suite (7 tests)
- Performance benchmarks (16 cases)
- E2E time-travel key lifecycle (3 tests)
- JWT privilege escalation attacks (9 tests)
- Global key quota circuit breaker (8 tests)
- Crypto + seal destructive tests (28 tests)

## [0.2.0] - 2026-06-25

### Added
- **JWT RBAC Engine** (`internal/auth/jwt_authenticator.go`)
  - Supports RS256/384/512, ES256/384/512, HS256/384/512
  - Algorithm confusion prevention via `WithValidMethods`
  - Configurable role claim path (nested dot notation: `custom.role`)
  - Array role support (`roles: ["admin"]` → first element)
  - 25 integration tests covering attack vectors
- **PolicyStore interface** — generic role→Policy lookup
  - `MemoryPolicyStore` with `sync.RWMutex` (thread-safe)
  - `AppRoleAuthenticator` implements PolicyStore (dual-use with JWT)
- **Auto Key Rotation Daemon** (`internal/lifecycle/daemon.go`)
  - PostgreSQL Advisory Lock cluster leader election
  - Hourly scan for `NextRotationAt <= now` + `State=Active`
  - Audit: `Actor=SYSTEM_DAEMON`, `Action=AutoRotate`
  - Context-aware graceful shutdown (releases lock on SIGTERM)
  - 16 daemon tests
- **KeyMetadata rotation fields**: `RotationPeriodDays`, `NextRotationAt`
- **GDK (Generate Data Key)** API (`POST /api/v1/keys/{id}/generate-data-key`)
  - Client-side envelope encryption
  - Plaintext DEK cleared after HTTP response
- **BYOK (Bring Your Own Key)** (`internal/lifecycle/transit.go`)
  - Temporary RSA-4096 transit key with 10-min TTL
  - Burn-after-reading: private key wiped after single use
  - `POST /api/v1/keys/import` + `GET /api/v1/keys/transit-pub`
- **Shamir Cold Backup** (`internal/seal/backup.go`)
  - Split Wrapped CMK to N USB drive files
  - HMAC-SHA256 integrity per shard
  - `yvonne backup-split` + `yvonne backup-restore` CLI
- **Audit Log Query API** (`POST /api/v1/audit/query`)
  - Filter by time range, Actor, Action
  - Hash chain verification (`valid: true/false`)
- **RotationDaemon assembly** in bootstrap (Cluster mode)
- **AdvisoryLocker** (`internal/storage/pg_locker.go`) — `pg_try_advisory_lock`
- **ScanPrefix** interface for KVStore (reaper + daemon scanning)
- **TLS enforcement** in `main.go` — `ListenAndServeTLS` when `tls.enabled=true`
- **Dual-write audit logger assembly** — `NewDualWriteLogger` (File + Syslog)
- **`yvonne init` CLI command** — generate CMK + RSA encrypt + write to DB
- **`AuditModeConf`** config: `dir`/`filename`/`retention_days`/`syslog_enabled`/`syslog_tag`

### Changed
- **P0 fix: Cluster mode强制认证装配** — `authenticator == nil` → `panic("FATAL: Cluster mode requires a valid authenticator")`
- **P0 fix: 资源级越权拦截** — `/encrypt` `/decrypt` handlers now call `Policy.IsKeyAllowed(body.KeyID)` from context
- `RequireAuth` middleware injects full `Policy` into context (not just RoleID)
- `NewRotationDaemon` accepts `seal.Unsealer` instead of raw `*SecureBuffer` (MasterKeyRef closure)
- `CreateKey` signature: added `rotationPeriodDays` parameter
- `RotateKey` propagates `RotationPeriodDays` + recalculates `NextRotationAt`
- Audit query API locked down with `authAndSeal("AuditQuery")`
- Cluster mode TLS disabled → red WARNING + audit record
- `AppRoleAuthenticator.RegisterPolicy` clears old token on re-registration

### Security
- Fixed: Cluster mode accepted `nil` authenticator (bare exposure)
- Fixed: `/encrypt` `/decrypt` lacked body `KeyID` resource-level authorization
- Fixed: `/api/v1/audit/query` had no authentication
- Fixed: TLS config ignored in `main.go` (always `ListenAndServe`)
- Fixed: Audit logger hardcoded to `os.Stdout` (no file persistence)
- Fixed: RotationDaemon not assembled in bootstrap
- Fixed: `MemoryPolicyStore` race condition (added `sync.RWMutex`)
- Fixed: `RegisterPolicy` left old token valid after re-registration
- Fixed: `security-check.sh` false positive on struct field declarations
- Fixed: `security-check.sh` CHECK 7 false positive on `HSMUnsealer.ProvideShare`

## [0.1.0] - 2026-06-24

### Added
- **Core crypto engine** (`internal/crypto`)
  - AES-256-GCM envelope encryption
  - RSA-4096 PSS signing/verification
  - ECDSA P-256 signing/verification
  - Versioned self-routing ciphertext: `[uint32 version BE][nonce][ciphertext+tag]`
  - `EncryptVersioned` / `DecryptVersioned` (zero-copy optimization)
- **Seal state machine** (`internal/seal`)
  - Shamir GF(2^8) threshold splitting (irreducible polynomial 0x11b, generator 0x03)
  - `VaultState`: Sealed → Unsealed → Sealing
  - `ProvideShare`: incremental shard submission, auto-combine at threshold
  - `DirectUnseal`: Dev mode direct injection
  - `Seal` / `EmergencySeal`: re-seal / irreversible emergency seal
  - `MasterKeyRef`: closure-based master key access
  - Local PKI auto-unseal: RSA-4096 OAEP + burn-after-reading PEM
  - HSM bridge interface: `CryptoBackend` + `HSMUnsealer` + `MockHSMBackend`
  - `BackendRef`: HSM mode closure access (replaces `MasterKeyRef`)
- **Key lifecycle** (`internal/lifecycle`)
  - `CreateKey`: generate DEK + MasterKey encrypt + store
  - `CreateAsymmetricKey`: RSA/ECDSA private key → DER → SecureBuffer → encrypt
  - `RotateKey`: atomic rotation (transaction + row-level lock)
  - `ShredKey`: Crypto-Shredding (UPDATE NULL + DELETE)
  - `SoftDeleteKey` / `RestoreKey`: recycle bin with 90-day TTL
  - `GetActiveKey` / `GetKeyForDecrypt`: state machine enforcement
  - DEK local cache: `sync.RWMutex` map + LISTEN/NOTIFY cluster invalidation
  - Recycle bin auto-cleanup: `StartSoftDeleteReaper`, TTL 90 days
- **Storage layer** (`internal/storage`)
  - `KVStore` interface: Put/Get/Delete/WithTx
  - `RowLocker`: `GetForUpdate` (SELECT FOR UPDATE)
  - `PrefixScanner`: `ScanPrefix` (LIKE 'prefix%')
  - `MemoryStore`: in-memory + Crypto-Shredding
  - `PostgresKVStore`: pgxpool + transactions + row locks + prefix scan
  - `CacheInvalidationListener`: LISTEN/NOTIFY + reconnect cache clear
- **Audit engine** (`internal/audit`)
  - HMAC-SHA256 hash chain: `sig = HMAC(key, prevSig + payload)`
  - `PrevSignature` self-containment (independent verification)
  - Chain anchor persistence: `audit.chain` file
  - `FileRotator`: daily rotation, files 0600 / dirs 0700
  - 180-day retention cleanup
  - High-risk operations `file.Sync()`: Rotate/ShredKey/SysUnseal/EmergencySeal
  - Syslog async dual-write: channel (4096) + 100ms timeout
- **API layer** (`internal/api`)
  - `GET /api/v1/sys/health`, `POST /api/v1/sys/unseal`, `POST /api/v1/sys/panic`
  - `POST /api/v1/keys`, `POST /api/v1/keys/{id}/rotate`, `DELETE /api/v1/keys/{id}/shred`
  - `POST /api/v1/encrypt`, `POST /api/v1/decrypt`
  - `GET /metrics` (Prometheus)
  - `AuditMiddleware`: TraceID + forced audit log + Actor=RoleID
  - `RequireAuth`: Bearer Token + RBAC (Action + KeyID)
  - Payload Escaping: `io.ReadAll` results cleared
- **Auth** (`internal/auth`)
  - `AppRoleAuthenticator`: Token → Policy, `subtle.ConstantTimeCompare`
  - `Policy`: RoleID + AllowedKeys (wildcard) + AllowedActions
  - Default deny: no/invalid Token → 401
- **Web admin UI** (`internal/admin`)
  - Overview page + Seal/Unseal operations + progress indicator
  - Embedded SPA (index.html + app.js + style.css)
  - Security headers: CSP / X-Frame-Options
- **CLI** (`cmd/yvonne`)
  - `yvonne dev`: dev mode
  - `yvonne server --config`: production mode
  - `yvonne unseal-keygen --out`: RSA-4096 key pair
- **Bootstrap** (`internal/bootstrap`)
  - Dev/Cluster dependency injection
  - Graceful shutdown
- **12 security checks** (`scripts/security-check.sh`)
  - `clear()` + `KeepAlive()` pairing
  - No `[]byte` returning getters
  - No sensitive variable interpolation
  - CSPRNG enforcement
  - `*SecureBuffer` for key params
  - `subtle.ConstantTimeCompare`
  - `ProvideShare` wipes shares
  - Shamir GF(2^8)
  - `Combine` returns `*SecureBuffer`
  - Crypto-Shredding
  - Payload Escaping
  - Slice length checks

### Infrastructure
- GitHub Actions CI: lint + test + security + coverage + PostgreSQL integration
- Security scan: GoSec + govulncheck + TruffleHog
- Release workflow: cross-compile Linux/macOS × amd64/arm64
- `Makefile` with `build`/`ci`/`test`/`coverage`/`security-check` targets
- `.gitignore` with strict exclusion of `.pem`/`.key`/`.dat`/`master-key*`

### Documentation
- `README.md` (bilingual English/Chinese)
- `docs/deployment.md`: PostgreSQL + systemd + Docker + monitoring + backup
- `docs/coverage.md`: test coverage report
- `.github/CODE_REVIEW_GUIDELINES.md`: security review checklist

## Versioning Policy

- **0.x**: Pre-release. Breaking changes possible between minor versions.
- **1.0+**: Stable API. Semantic versioning strictly enforced.
  - MAJOR: incompatible API changes
  - MINOR: new features (backward compatible)
  - PATCH: bug fixes (backward compatible)

## Release Process

1. Update `CHANGELOG.md` with release date and changes
2. Tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
3. Push tag: `git push origin v0.2.0`
4. GitHub Actions `release.yml` auto-builds + creates GitHub Release
5. Verify binaries: `dist/yvonne-linux-amd64`, `dist/yvonne-darwin-arm64`
