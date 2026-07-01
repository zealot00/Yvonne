# 🧊 Yvonne KMS

[English](#english) | [中文](#中文)

---

<a id="english"></a>

## English

A self-hosted KMS built for teams who refuse to surrender key control to cloud vendors.

### Three Promises

1. **Your plaintext keys never leave the process.** Pinned in `memguard.SecureBuffer`, wiped with `clear()` + `runtime.KeepAlive()`. Not the network, not the database, not even Go's GC can leak them.
2. **Every key operation is provably auditable.** HMAC-SHA256/SM3 hash chain + file rotation + async syslog dual-write. Tamper and the chain breaks loudly.
3. **Your keys, your hardware, your sovereignty.** Shamir-split master key, HSM-backed CMK, self-hosted end to end. No vendor lock-in, no cloud call-home.

### Quick Start

```bash
# Dev mode (zero config, in-memory)
./bin/yvonne dev

# Full cluster setup
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

### Capabilities

#### Foundation — what a KMS must have

- **Envelope Encryption**: `Encrypt` / `Decrypt` / `GenerateDataKey` / `GenerateDataKeyWithoutPlaintext` (ciphertext-only DEK, safer).
- **Key Lifecycle**: create / rotate / disable / enable / soft-delete (90-day recycle bin) / restore / crypto-shred.
- **Multi-Protocol API**: HTTP REST + gRPC (full mirror) + MCP (AI agent integration).
- **JWT RBAC Engine**: RS256/384/512, ES256/384/512, HS256/384/512, SM2. Algorithm confusion prevention. Configurable role claim paths.
- **Resource-Level Authorization**: body `KeyID` checked against `Policy.AllowedKeys` (wildcard + prefix match). Default deny.
- **Storage**: PostgreSQL (cluster) or BoltDB (single-node). Pluggable backend.
- **BYOK**: temporary RSA-4096 transit key, burn-after-reading, external DEK import without plaintext transmission.
- **Multi-Tenant Isolation**: keyID prefix scoping (`tenant-a:key1`). Transparent to storage. Backward compatible.
- **Web Console**: pure native JS SPA (Dashboard + Keys + Crypto + Audit + MFA/Quorum). go:embed. Admin REST API. Strict CSP `script-src 'self'`.
- **SDK**: Go / Python / Java with retry, circuit breaker, and trace_id propagation.
- **Metrics**: Prometheus `/metrics` endpoint.

#### Security Engineering — what serious teams demand

- **Absolute Memory Discipline**: `clear()` + `runtime.KeepAlive()` defeats DCE. Memory dumps yield nothing but ghosts.
- **Versioned Self-Routing Ciphertext**: `[uint32 version BE][nonce][ciphertext+tag]` — decrypt auto-routes to correct DEK version.
- **Shamir's Secret Sharing**: master key shattered into N shards across GF(2^8). K shards to resurrect.
- **Dual-Write Audit Chain**: HMAC hash chain + daily file rotation + async syslog dual-write.
- **MFA TOTP (RFC 6238)**: sensitive operations (ShredKey/EmergencySeal) require `X-MFA-Code`. ±30s skew, replay protection.
- **K-of-N Quorum Approval**: anti-self-approve + idempotent + expiry cleanup + state machine.
- **Emergency Seal**: one API call wipes everything. Deep freeze until manual restart + Shamir unseal.
- **Cold Storage Backup**: Shamir-split Wrapped CMK to N USB drives. HMAC integrity per shard.
- **OpenTelemetry Tracing**: OTLP gRPC exporter + otelhttp auto-instrumentation + TraceID propagation to audit log.
- **Config Hot-Reload**: SIGHUP reloads logging/audit/observability without restart.
- **Alerting Webhook**: Slack / DingTalk / PagerDuty auto-detection. High-risk operation alerts.
- **Security Hygiene**: gosec 0 issues, govulncheck 0 vulns, 12-check `scripts/security-check.sh` enforced on every commit.

#### Things No One Else Has — Yvonne's differentiators

- **Strict GM Mode**: `crypto.strict: true` enforces SM2/SM3/SM4 only, disables AES/RSA/ECDSA. End-to-end 国密 compliance.
- **RFC 8998 GM TLS**: SM2 dual certificates + SM4/SM3 cipher suites via tjfoc/gmsm/gmtls.
- **HSM KEK Abstraction**: `softwareKEK` / `hsmKEK` unified interface. CMK never leaves chip. PKCS#11 via crypto11 + SoftHSM CI.
- **Auto Key Rotation**: PostgreSQL Advisory Lock elects cluster leader. Hourly scan. Actor=`SYSTEM_DAEMON`.
- **Anti-Algorithm-Confusion JWT**: strict per-algorithm key type allowlist. RS/ES/HS/SM2 cross-use rejected at parse time.
- **Browser-Verified E2E**: 37/37 tests passed — 17 HTTP API + 5 Admin API + 15 Selenium browser (headless Chrome, full UX flow). Release gate script: `scripts/release_gate_e2e.py`.

### API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | Health check |
| POST | `/api/v1/sys/unseal` | Submit Shamir shard |
| POST | `/api/v1/sys/panic` | Emergency seal (irreversible) |
| POST | `/api/v1/keys` | Create key (AES/RSA/ECDSA/SM2/SM4) |
| GET | `/api/v1/keys/transit-pub` | Get BYOK transit public key |
| POST | `/api/v1/keys/import` | Import external key (BYOK) |
| POST | `/api/v1/keys/{id}/rotate` | Rotate key |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred |
| PATCH | `/api/v1/keys/{id}/soft-delete` | Soft delete (recycle bin) |
| POST | `/api/v1/keys/{id}/restore` | Restore from recycle bin |
| POST | `/api/v1/keys/{id}/generate-data-key` | Generate data key (GDK) |
| POST | `/api/v1/encrypt` | Envelope encrypt |
| POST | `/api/v1/decrypt` | Envelope decrypt |
| POST | `/api/v1/sign` | Asymmetric sign (RSA-PSS/ECDSA/SM2) |
| POST | `/api/v1/verify` | Asymmetric verify |
| POST | `/api/v1/generate-mac` | HMAC generate |
| POST | `/api/v1/verify-mac` | HMAC verify |
| POST | `/api/v1/re-encrypt` | Re-encrypt under new DEK version |
| GET | `/api/v1/keys/{id}/public` | Get public key |
| POST | `/api/v1/mfa/setup` | Setup MFA TOTP |
| POST | `/api/v1/mfa/verify` | Verify MFA code |
| POST | `/api/v1/approvals` | Create quorum approval ticket |
| POST | `/api/v1/approvals/{id}/approve` | Approve ticket |
| POST | `/api/v1/approvals/{id}/reject` | Reject ticket |
| POST | `/api/v1/audit/query` | Query audit log |
| GET | `/metrics` | Prometheus metrics |

### Build & Test

```bash
make build          # compile
make ci             # local CI (vet + fmt + security + tests)
make coverage       # coverage report
bash scripts/security-check.sh  # 12 security checks
```

**Latest E2E verification (v1.3.2 binary):**

| Suite | Result |
|---|---|
| HTTP API (Encrypt/Decrypt/Sign/Verify/MAC/GDK/Rotate/SoftDelete/Restore/ReEncrypt/GetPublicKey) | 17/17 ✅ |
| Admin API (Dashboard/Keys/Crypto/Audit) | 5/5 ✅ |
| Selenium Browser (Page load/CSS/JS/CSP/Nav/Encrypt/Decrypt/Audit/MFA) | 15/15 ✅ |
| **Total** | **37/37 ✅** (3 skipped: MFA/Quorum need cluster mode) |

Release gate script: `scripts/release_gate_e2e.py` (run before every tag)

### Documentation

- **[用户手册 / User Manual](docs/manual/README.md)** — 19 章完整手册（中英双语），含 7 个使用场景
- [HTTP API Guide](docs/api.md)
- [gRPC API Guide](docs/grpc-api.md)
- [MCP (AI Agent) Guide](docs/mcp-api.md)
- [PKCS#11 HSM Guide](docs/pkcs11-hsm.md)
- [国密合规路线图](docs/gmsm-roadmap.md)
- [产品演进路线图](docs/roadmap.md)
- [v1.3 合规功能指南](docs/v1.3-compliance.md)
- [AES→SM4 迁移指南](docs/aes-to-sm4-migration.md)
- [合规证据包](docs/compliance/README.md)
- [升级指南](docs/upgrade-guide.md)
- [Benchmark Report](docs/benchmark-report.html)
- [Deployment Guide](docs/deployment.md)
- [Test Coverage Report](docs/coverage.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)

### Roadmap

**Shipped**

- v1.0 — mTLS, JWT RBAC, Shamir unseal, HTTP+gRPC API, Go/Python SDK
- v1.1 — PKCS#11 HSM, SM2/SM3/SM4 国密闭环, JWT SM2, HMAC-SM3 audit chain
- v1.2 — HMAC API, GenerateDataKeyWithoutPlaintext, Sign/Verify, GetPublicKey, ReEncrypt
- v1.2.1 — CORS, gosec/govulncheck clean, Go 1.25.11 CVE fix
- v1.2.2 — Sign/Verify 完整实现 (RSA-PSS/ECDSA/SM2), asymmetric key creation API
- v1.3.0 — MFA TOTP, Quorum Approval, RFC 8998 GM TLS, OpenTelemetry, Config Reload, Alerting
- v1.3.1 — Multi-Tenant Isolation, Web Console (pure JS, strict CSP)

**Next**

- TPM 2.0 support — hardware-bound CMK unseal
- Kubernetes KMS v2 plugin (gRPC over Unix socket)
- KMIP 1.4/2.1 + Vault compatibility

Full roadmap: [docs/roadmap.md](docs/roadmap.md)

### License

Apache License 2.0. See [LICENSE](LICENSE).

### Compliance Disclaimer

> **⚠️ IMPORTANT: This project has NOT passed FIPS 140-3 or PCI-DSS formal audit certification.**
>
> Yvonne provides foundational cryptographic security and compliance audit mechanisms, but it is **not** a FIPS-validated cryptographic module. It is suitable as:
> - An internal infrastructure hardening prototype
> - A self-hosted KMS for non-strongly-regulated scenarios
> - A reference implementation for security engineering teams
>
> For strongly regulated environments (financial payments, healthcare, government), you MUST:
> 1. Complete formal third-party security audit
> 2. Integrate FIPS-validated HSM (PKCS#11/TPM) via `CryptoBackend` interface
> 3. Establish operational procedures (key custody, break-glass, recovery drills)
> 4. Obtain relevant compliance certifications before production deployment

---

<a id="中文"></a>

## 中文

一个为不愿向云厂商交出密钥控制权的团队而构建的自托管 KMS。

### 三个承诺

1. **明文密钥绝不离开进程。** 锁定在 `memguard.SecureBuffer` 中，用 `clear()` + `runtime.KeepAlive()` 擦除。网络、数据库、甚至 Go 的 GC 都无法泄露。
2. **每次密钥操作都可证明可审计。** HMAC-SHA256/SM3 哈希链 + 文件轮转 + 异步 Syslog 双写。篡改即断链，且响亮报警。
3. **你的密钥、你的硬件、你的主权。** Shamir 分片主密钥，HSM 托管 CMK，全链路自托管。无厂商锁定，无云回调。

### 快速开始

```bash
# 开发模式（零配置，内存存储）
./bin/yvonne dev

# 完整集群部署
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

### 能力清单

#### 基础能力 — KMS 必须有的

- **信封加密**：`Encrypt` / `Decrypt` / `GenerateDataKey` / `GenerateDataKeyWithoutPlaintext`（仅返回密文 DEK，更安全）。
- **密钥生命周期**：创建 / 轮转 / 禁用 / 启用 / 软删除（90 天回收站）/ 恢复 / Crypto-Shred。
- **多协议 API**：HTTP REST + gRPC（全镜像）+ MCP（AI Agent 集成）。
- **JWT RBAC 引擎**：RS256/384/512、ES256/384/512、HS256/384/512、SM2。防算法混淆。可配置角色 claim 路径。
- **资源级授权**：body 中的 `KeyID` 校验 `Policy.AllowedKeys`（通配符 + 前缀匹配）。默认拒绝。
- **存储后端**：PostgreSQL（集群）或 BoltDB（单节点）。可插拔。
- **BYOK（自带密钥）**：临时 RSA-4096 传输密钥，阅后即焚，外部 DEK 导入无需明文传输。
- **多租户隔离**：keyID 前缀隔离（`tenant-a:key1`）。对存储层透明。向后兼容。
- **Web 控制台**：纯原生 JS SPA（仪表盘 + 密钥管理 + 密码运算 + 审计日志 + MFA/Quorum 管理）。go:embed 内嵌。Admin REST API。严格 CSP `script-src 'self'`。
- **SDK**：Go / Python / Java，含重试、熔断、trace_id 透传。
- **指标**：Prometheus `/metrics` 端点。

#### 安全工程 — 严肃团队的硬要求

- **绝对内存纪律**：`clear()` + `runtime.KeepAlive()` 击败 DCE 优化。内存转储只能看到幽灵。
- **版本化自路由密文**：`[uint32 版本号 BE][nonce][密文+tag]` — 解密自动路由到正确的 DEK 版本。
- **Shamir 秘密分割**：主密钥在 GF(2^8) 有限域中被击碎为 N 份。K 份才能复活。
- **双写哈希链审计**：HMAC 哈希链 + 按天文件轮转 + 异步 Syslog 双写。
- **MFA TOTP（RFC 6238）**：敏感操作（ShredKey/EmergencySeal）要求 `X-MFA-Code`。±30s 容差，防重放。
- **K-of-N Quorum 审批**：防自批准 + 幂等 + 过期清理 + 状态机。
- **紧急封印**：一个 API 调用擦除一切。深度冰冻直到手动重启 + Shamir 解封。
- **冷存储备份**：Shamir 分片 Wrapped CMK 到 N 个 U 盘。每片 HMAC 完整性校验。
- **OpenTelemetry 链路追踪**：OTLP gRPC exporter + otelhttp 自动 instrumentation + TraceID 传播到审计日志。
- **配置热更新**：SIGHUP 无重启热配置（logging/audit/observability）。
- **告警 Webhook**：Slack / 钉钉 / PagerDuty 自动检测格式。高危操作触发告警。
- **安全卫生**：gosec 0 issues，govulncheck 0 vulns，每次提交强制 12 项 `scripts/security-check.sh`。

#### 独家特性 — Yvonne 的差异化

- **严格国密模式**：`crypto.strict: true` 强制仅 SM2/SM3/SM4，禁用 AES/RSA/ECDSA。端到端国密合规。
- **RFC 8998 国密 TLS**：SM2 双证书 + SM4/SM3 密码套件，基于 tjfoc/gmsm/gmtls。
- **HSM KEK 抽象**：`softwareKEK` / `hsmKEK` 统一接口。CMK 永不离开芯片。PKCS#11 via crypto11 + SoftHSM CI。
- **自动密钥轮转**：PostgreSQL Advisory Lock 集群选主。每小时扫描。Actor=`SYSTEM_DAEMON`。
- **防算法混淆 JWT**：严格的 per-algorithm 密钥类型白名单。RS/ES/HS/SM2 跨用例在 parse 阶段被拒。
- **浏览器级 E2E 验证**：37/37 测试通过 — 17 HTTP API + 5 Admin API + 15 Selenium 浏览器（无头 Chrome，完整 UX 流程）。Release gate 脚本：`scripts/release_gate_e2e.py`。

### API 端点

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | 健康检查 |
| POST | `/api/v1/sys/unseal` | 提交 Shamir 分片 |
| POST | `/api/v1/sys/panic` | 紧急封印（不可逆） |
| POST | `/api/v1/keys` | 创建密钥（AES/RSA/ECDSA/SM2/SM4） |
| GET | `/api/v1/keys/transit-pub` | 获取 BYOK 传输公钥 |
| POST | `/api/v1/keys/import` | 导入外部密钥（BYOK） |
| POST | `/api/v1/keys/{id}/rotate` | 轮转密钥 |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred |
| PATCH | `/api/v1/keys/{id}/soft-delete` | 软删除（回收站） |
| POST | `/api/v1/keys/{id}/restore` | 从回收站恢复 |
| POST | `/api/v1/keys/{id}/generate-data-key` | 生成数据密钥（GDK） |
| POST | `/api/v1/encrypt` | 信封加密 |
| POST | `/api/v1/decrypt` | 信封解密 |
| POST | `/api/v1/sign` | 非对称签名（RSA-PSS/ECDSA/SM2） |
| POST | `/api/v1/verify` | 非对称验签 |
| POST | `/api/v1/generate-mac` | HMAC 生成 |
| POST | `/api/v1/verify-mac` | HMAC 验证 |
| POST | `/api/v1/re-encrypt` | 在新 DEK 版本下重加密 |
| GET | `/api/v1/keys/{id}/public` | 获取公钥 |
| POST | `/api/v1/mfa/setup` | 配置 MFA TOTP |
| POST | `/api/v1/mfa/verify` | 验证 MFA 验证码 |
| POST | `/api/v1/approvals` | 创建 Quorum 审批工单 |
| POST | `/api/v1/approvals/{id}/approve` | 批准工单 |
| POST | `/api/v1/approvals/{id}/reject` | 拒绝工单 |
| POST | `/api/v1/audit/query` | 查询审计日志 |
| GET | `/metrics` | Prometheus 指标 |

### 编译与测试

```bash
make build          # 编译
make ci             # 本地 CI（vet + fmt + 安全 + 测试）
make coverage       # 覆盖率报告
bash scripts/security-check.sh  # 12 项安全检查
```

**最新 E2E 验证（v1.3.2 二进制包）：**

| 测试套件 | 结果 |
|---|---|
| HTTP API（Encrypt/Decrypt/Sign/Verify/MAC/GDK/Rotate/SoftDelete/Restore/ReEncrypt/GetPublicKey） | 17/17 ✅ |
| Admin API（Dashboard/Keys/Crypto/Audit） | 5/5 ✅ |
| Selenium 浏览器（页面加载/CSS/JS/CSP/导航/加密/解密/审计/MFA） | 15/15 ✅ |
| **合计** | **37/37 ✅**（3 跳过：MFA/Quorum 需 cluster 模式） |

Release gate 脚本：`scripts/release_gate_e2e.py`（每次打 tag 前运行）

### 文档

- **[用户手册 / User Manual](docs/manual/README.md)** — 19 章完整手册（中英双语），含 7 个使用场景
- [部署指南](docs/deployment.md)
- [HTTP API 指南](docs/api.md)
- [gRPC API 指南](docs/grpc-api.md)
- [MCP（AI Agent）指南](docs/mcp-api.md)
- [PKCS#11 HSM 指南](docs/pkcs11-hsm.md)
- [国密合规路线图](docs/gmsm-roadmap.md)
- [产品演进路线图](docs/roadmap.md)
- [v1.3 合规功能指南](docs/v1.3-compliance.md)
- [AES→SM4 迁移指南](docs/aes-to-sm4-migration.md)
- [合规证据包](docs/compliance/README.md)
- [升级指南](docs/upgrade-guide.md)
- [测试覆盖率报告](docs/coverage.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

### 路线图

**已发布**

- v1.0 — mTLS、JWT RBAC、Shamir 解封、HTTP+gRPC API、Go/Python SDK
- v1.1 — PKCS#11 HSM、SM2/SM3/SM4 国密闭环、JWT SM2、HMAC-SM3 审计链
- v1.2 — HMAC API、GenerateDataKeyWithoutPlaintext、Sign/Verify、GetPublicKey、ReEncrypt
- v1.2.1 — CORS、gosec/govulncheck 清零、Go 1.25.11 CVE 修复
- v1.2.2 — Sign/Verify 完整实现（RSA-PSS/ECDSA/SM2）、非对称密钥创建 API
- v1.3.0 — MFA TOTP、Quorum 审批、RFC 8998 国密 TLS、OpenTelemetry、配置热更新、告警
- v1.3.1 — 多租户隔离、Web 控制台（纯 JS、严格 CSP）

**下一步**

- TPM 2.0 支持 — 硬件绑定 CMK 解封
- Kubernetes KMS v2 插件（gRPC over Unix socket）
- KMIP 1.4/2.1 + Vault 兼容

完整路线图：[docs/roadmap.md](docs/roadmap.md)

### 许可证

Apache License 2.0。见 [LICENSE](LICENSE)。

### 合规免责声明

> **⚠️ 重要：本项目未通过 FIPS 140-3 或 PCI-DSS 的正式审计认证。**
>
> Yvonne 提供底层的密码学安全与合规审计机制，但其本身**不是** FIPS 验证的密码模块。它适合作为：
> - 内部基础设施加固原型
> - 非强监管场景的自托管 KMS
> - 安全工程团队的参考实现
>
> 对于强监管环境（金融支付、医疗、政府），您必须：
> 1. 完成正式的第三方安全审计
> 2. 通过 `CryptoBackend` 接口集成 FIPS 验证的 HSM（PKCS#11/TPM）
> 3. 建立运维制度（密钥托管、应急访问、恢复演练）
> 4. 在生产部署前取得相关合规认证
