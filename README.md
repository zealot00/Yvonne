# 🧊 Yvonne KMS

[English](#english) | [中文](#中文)

---

<a id="english"></a>

## English

A self-hosted KMS focused on envelope encryption, auditable key lifecycle, absolute memory discipline, and JWT-based RBAC.

### Why Yvonne?

Yvonne is built for teams who need centralized key management without surrendering control to cloud vendors. She doesn't trust the network, the database, or Go's Garbage Collector. Every plaintext key is pinned in `memguard.SecureBuffer`, wiped with `clear()` + `runtime.KeepAlive()`, and never leaves the process boundary in plaintext form.

### Core Features

- **Absolute Memory Discipline**: `clear()` + `runtime.KeepAlive()` defeats DCE. Memory dumps yield nothing but ghosts.
- **Versioned Self-Routing Ciphertext**: `[uint32 version BE][nonce][ciphertext+tag]` — decrypt auto-routes to correct DEK version.
- **Shamir's Secret Sharing**: Master Key shattered into N shards across GF(2^8). K shards to resurrect.
- **Dual-Write Audit Chain**: HMAC-SHA256 or HMAC-SM3 hash chain + daily file rotation + async syslog dual-write. Tamper = chain breaks.
- **JWT RBAC Engine**: RS256/384/512, ES256/384/512, HS256/384/512, SM2 (国密). Algorithm confusion prevention. Configurable role claim paths.
- **Resource-Level Authorization**: Body `KeyID` checked against `Policy.AllowedKeys` (wildcard + prefix match). Default deny.
- **Auto Key Rotation**: PostgreSQL Advisory Lock elects cluster leader. Hourly scan for expired keys. Actor=`SYSTEM_DAEMON`.
- **Soft Delete + Recycle Bin**: 90-day TTL with auto-shred reaper. Restorable. Crypto-shredding for permanent destruction.
- **BYOK (Bring Your Own Key)**: Temporary RSA-4096 transit key. Burn-after-reading. External DEK import without plaintext transmission.
- **GDK (Generate Data Key)**: Client-side envelope encryption. KMS never sees business plaintext.
- **Cold Storage Backup**: Shamir-split Wrapped CMK to N USB drives. HMAC integrity per shard.
- **Emergency Seal**: One API call wipes everything. Deep freeze until manual restart + Shamir unseal.
- **Multi-Protocol API**: HTTP REST + gRPC (full mirror) + MCP (AI agent integration, encrypt + restricted decrypt).
- **Pluggable Crypto Suite**: AES-256-GCM + SHA-256 (default) or SM4-GCM + SM3 (国密, `-tags gmsm`). SM2 public key crypto + JWT SM2 signing.
- **HSM Support**: Pluggable KEK abstraction (`softwareKEK` / `hsmKEK`), CMK never leaves chip. PKCS#11 backend via crypto11 + SoftHSM CI.
- **Strict GM Mode**: `crypto.strict: true` enforces SM2/SM3/SM4 only, disables AES/RSA/ECDSA.

### Quick Start

```bash
# Dev mode (zero config, in-memory)
./bin/yvonne dev

# Full cluster setup
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

### Documentation

- [HTTP API Guide](docs/api.md)
- [gRPC API Guide](docs/grpc-api.md)
- [MCP (AI Agent) Guide](docs/mcp-api.md)
- [PKCS#11 HSM Guide](docs/pkcs11-hsm.md)
- [国密合规路线图](docs/gmsm-roadmap.md)
- [AES→SM4 迁移指南](docs/aes-to-sm4-migration.md)
- [合规证据包](docs/compliance/README.md)
- [升级指南](docs/upgrade-guide.md)
- [Benchmark Report](docs/benchmark-report.html)
- [Deployment Guide](docs/deployment.md)
- [Test Coverage Report](docs/coverage.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)

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

### Build & Test

```bash
make build          # compile
make ci             # local CI (vet + fmt + security + tests)
make coverage       # coverage report
bash scripts/security-check.sh  # 12 security checks
```

### API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | Health check |
| POST | `/api/v1/sys/unseal` | Submit Shamir shard |
| POST | `/api/v1/sys/panic` | Emergency seal (irreversible) |
| POST | `/api/v1/keys` | Create key (AES/RSA/ECDSA) |
| GET | `/api/v1/keys/transit-pub` | Get BYOK transit public key |
| POST | `/api/v1/keys/import` | Import external key (BYOK) |
| POST | `/api/v1/keys/{id}/rotate` | Rotate key |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred |
| PATCH | `/api/v1/keys/{id}/soft-delete` | Soft delete (recycle bin) |
| POST | `/api/v1/keys/{id}/restore` | Restore from recycle bin |
| POST | `/api/v1/keys/{id}/generate-data-key` | Generate data key (GDK) |
| POST | `/api/v1/encrypt` | Envelope encrypt |
| POST | `/api/v1/decrypt` | Envelope decrypt |
| POST | `/api/v1/audit/query` | Query audit log (requires AuditQuery action) |
| GET | `/metrics` | Prometheus metrics |

### Roadmap

- [ ] TPM 2.0 support — hardware-bound CMK unseal
- [ ] PKCS#11 HSM integration (CryptoBackend interface ready)
- [] Kubernetes KMS v2 plugin (gRPC over Unix socket)
- [] mTLS client certificate authentication
- [ ] OpenAPI spec + SDK (Go/Java/Python)

### License

Apache License 2.0. See [LICENSE](LICENSE).

---

<a id="中文"></a>

## 中文

一个自托管 KMS，专注于信封加密、可审计的密钥生命周期、绝对内存纪律和基于 JWT 的 RBAC 鉴权。

### 为什么选择 Yvonne？

Yvonne 为需要集中化密钥管理但不愿向云厂商交出控制权的团队而构建。她不信任网络、不信任数据库、也不信任 Go 的垃圾回收器。每个明文密钥都锁定在 `memguard.SecureBuffer` 中，用 `clear()` + `runtime.KeepAlive()` 擦除，绝不以明文形式离开进程边界。

### 核心特性

- **绝对内存纪律**：`clear()` + `runtime.KeepAlive()` 击败 DCE 优化。内存转储只能看到幽灵。
- **版本化自路由密文**：`[uint32 版本号 BE][nonce][密文+tag]` — 解密自动路由到正确的 DEK 版本。
- **Shamir 秘密分割**：主密钥在 GF(2^8) 有限域中被击碎为 N 份。K 份才能复活。
- **双写哈希链审计**：HMAC-SHA256 哈希链 + 按天文件轮转 + 异步 Syslog 双写。篡改即断链。
- **JWT RBAC 引擎**：RS256/384/512、ES256/384/512、HS256/384/512。防算法混淆攻击。可配置角色 claim 路径。
- **资源级授权**：body 中的 `KeyID` 校验 `Policy.AllowedKeys`（通配符 + 前缀匹配）。默认拒绝。
- **自动密钥轮转**：PostgreSQL Advisory Lock 集群选主。每小时扫描过期密钥。Actor=`SYSTEM_DAEMON`。
- **软删除 + 回收站**：90 天 TTL 自动粉碎。可恢复。永久销毁用 Crypto-Shredding。
- **BYOK（自带密钥）**：临时 RSA-4096 传输密钥。阅后即焚。外部 DEK 导入无需明文传输。
- **GDK（生成数据密钥）**：客户端信封加密。KMS 永不接触业务明文。
- **冷存储备份**：Shamir 分片 Wrapped CMK 到 N 个 U 盘。每片 HMAC 完整性校验。
- **紧急封印**：一个 API 调用擦除一切。深度冰冻直到手动重启 + Shamir 解封。

### 快速开始

```bash
# 开发模式（零配置，内存存储）
./bin/yvonne dev

# 完整集群部署
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

### 文档

- [部署指南](docs/deployment.md)
- [测试覆盖率报告](docs/coverage.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)

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

### 编译与测试

```bash
make build          # 编译
make ci             # 本地 CI（vet + fmt + 安全 + 测试）
make coverage       # 覆盖率报告
bash scripts/security-check.sh  # 12 项安全检查
```

### 路线图

- [ ] TPM 2.0 支持 — 硬件绑定 CMK 解封
- [ ] PKCS#11 HSM 集成（CryptoBackend 接口已就绪）
- [ ] Kubernetes KMS v2 插件（gRPC over Unix socket）
- [ ] mTLS 客户端证书认证
- [ ] OpenAPI spec + SDK（Go/Java/Python）

### 许可证

Apache License 2.0。见 [LICENSE](LICENSE)。
