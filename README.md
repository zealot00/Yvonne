# 🧊 Yvonne KMS

A self-hosted KMS. 13MB. Memory-safe. Auditor-ready.

[English](#english) | [中文](#中文)

---

<a id="english"></a>

## Why Yvonne?

Three promises that no other KMS makes:

1. **Your plaintext keys never touch Go's garbage collector.**
   Every secret lives in `memguard.SecureBuffer`. Wiped with `clear()` + `runtime.KeepAlive()`. A memory dump reveals nothing — we verified this.

2. **You can prove every key operation to an auditor.**
   HMAC hash chain audit log. File rotation + syslog dual-write. Tamper with one entry and the entire chain breaks — verifiably.

3. **You don't need a dedicated team to run it.**
   Single 13MB binary. No plugins, no script engines, no reflection. `./bin/yvonne dev` and you're encrypting in 30 seconds.

## Quick Start

```bash
./bin/yvonne dev --demo       # 30s: keys created, curl examples printed
./bin/yvonne dev --dashboard  # opens browser to Web Console (port 8250)
```

## Capabilities

### Foundation
- AES-256-GCM & SM4-GCM envelope encryption with versioned self-routing ciphertext
- RSA-4096 / ECDSA P-256 / SM2 asymmetric crypto (Sign / Verify / ReEncrypt)
- HMAC generate / verify (constant-time comparison)
- Create / Rotate / Shred / Soft-Delete / Restore key lifecycle
- BYOK (Bring Your Own Key) with burn-after-reading transit key
- GDK (Generate Data Key) with optional no-plaintext mode
- JWT RBAC (RS/ES/HS/SM2), AppRole tokens, K8s SA auth
- PostgreSQL-backed cluster with Advisory Lock leader election
- Cold storage backup via Shamir secret splitting to USB drives
- Emergency seal — one API call wipes everything
- HTTP REST + gRPC (full mirror) + MCP (AI agent) three-protocol support
- Web Console (Dashboard / Keys / Crypto / Audit / MFA & Quorum)

### Security engineering
- Multi-tenant key isolation (prefix-scoped, backward compatible)
- MFA TOTP (RFC 6238) for Shred / EmergencySeal
- K-of-N Quorum approval workflow (anti-self-approve, idempotent, expiry)
- Pluggable KEK abstraction (`softwareKEK` / `hsmKEK`), PKCS#11 HSM support
- Strict GM mode: `crypto.strict: true` disables AES/RSA/ECDSA
- RFC 8998 GM TLS (SM2 dual certificates + SM4/SM3)
- OpenTelemetry tracing (OTLP + TraceID propagation to audit log)
- Alerting webhook (Slack / DingTalk / PagerDuty auto-detection)
- Config hot-reload via SIGHUP
- gosec 0 issues + govulncheck 0 vulnerabilities (12 internal security checks)
- 300+ tests: unit / integration (PG) / gRPC / browser Selenium E2E (39/39 pass)

### Things no one else has
- **MCP (AI Agent) integration** — Claude/GPT can call Yvonne natively (encrypt + restricted decrypt)
- **国密全栈 (GM/T)** — SM2/SM3/SM4 + JWT SM2 + HMAC-SM3 audit chain + RFC 8998 TLS + strict mode
- **13MB single binary** — no runtime deps, runs on Raspberry Pi and industrial gateways
- **Three-language SDK** — Go / Python / Java with retry, circuit breaker, trace_id propagation

## Documentation

- [产品演进路线图](docs/roadmap.md) — v1.0 → v1.3.1 → v2.0
- [v1.3 合规功能指南](docs/v1.3-compliance.md) — MFA / Quorum / GM TLS / OTel
- [国密合规指南](docs/gmsm-compliance.md) — 编译配置 + 密评二级对照表
- [密评二级自评报告](docs/compliance/self-assessment-level2.md) — 24 项逐项评估
- [交付物清单](docs/deliverables.md) — 25 项文档 + 版本历史
- [覆盖率审计报告](docs/coverage-audit.md) — 各包覆盖率 + 提升计划
- [部署指南](docs/deployment.md)
- [gRPC API Guide](docs/grpc-api.md)
- [MCP (AI Agent) Guide](docs/mcp-api.md)
- [PKCS#11 HSM Guide](docs/pkcs11-hsm.md)
- [AES→SM4 迁移指南](docs/aes-to-sm4-migration.md)
- [升级指南](docs/upgrade-guide.md)
- [合规证据包](docs/compliance/README.md)
- [Changelog](CHANGELOG.md) | [Security Policy](SECURITY.md) | [Contributing Guide](CONTRIBUTING.md)

## Build & Test

```bash
make build                     # compile
make ci                        # vet + fmt + security + tests
go test -tags=integration ./...  # PG integration tests
gosec ./...                    # 0 issues
govulncheck ./...              # 0 vulnerabilities
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | Health check |
| POST | `/api/v1/sys/unseal` | Submit Shamir shard |
| POST | `/api/v1/sys/panic` | Emergency seal (irreversible) |
| POST | `/api/v1/keys` | Create symmetric key |
| POST | `/api/v1/keys/asymmetric` | Create RSA/ECDSA/SM2 key |
| POST | `/api/v1/keys/{id}/rotate` | Rotate key |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred (MFA required) |
| POST | `/api/v1/encrypt` | Envelope encrypt |
| POST | `/api/v1/decrypt` | Envelope decrypt |
| POST | `/api/v1/sign` | Asymmetric sign |
| POST | `/api/v1/verify` | Verify signature |
| POST | `/api/v1/mac/generate` | Generate HMAC |
| POST | `/api/v1/mac/verify` | Verify HMAC |
| POST | `/api/v1/re-encrypt` | Re-encrypt with different key |
| POST | `/api/v1/auth/mfa/setup` | MFA TOTP setup |
| POST | `/api/v1/auth/mfa/verify` | MFA verify + enable |
| POST | `/api/v1/approvals` | Create Quorum approval |
| POST | `/api/v1/approvals/approve` | Approve ticket |
| GET | `/admin/api/dashboard` | Web Console dashboard |
| GET | `/admin/api/keys` | Web Console key list |
| GET | `/metrics` | Prometheus metrics |

Full OpenAPI spec: [docs/openapi.yaml](docs/openapi.yaml) (31 endpoints)

## Roadmap

- [x] mTLS + PKCS#11 HSM + OpenAPI SDK (v1.0-v1.1)
- [x] SM2/SM3/SM4 国密闭环 + JWT SM2 + strict GM mode (v1.1)
- [x] HMAC + Sign/Verify + ReEncrypt + 非对称密钥 API (v1.2)
- [x] MFA + Quorum + RFC 8998 GM TLS + OTel + Config Reload + Alerting (v1.3.0)
- [x] Multi-tenant isolation + Web Console (v1.3.1)
- [ ] KMIP 1.4/2.1 + Vault compatibility + HSM cluster (v2.0)
- [ ] TPM 2.0 + K8s KMS v2 plugin (v2.0)

Full roadmap: [docs/roadmap.md](docs/roadmap.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

> **⚠️ Compliance Disclaimer:** This project has NOT passed FIPS 140-3 or PCI-DSS formal audit. It provides cryptographic security and audit mechanisms, but is not a FIPS-validated module. For strongly regulated environments, complete third-party audit + FIPS HSM integration + compliance certification before production deployment.

---

<a id="中文"></a>

## 为什么选择 Yvonne？

三个其他 KMS 做不到的承诺：

1. **你的明文密钥永远不会被 Go 垃圾回收器触碰。**
   每个密钥锁定在 `memguard.SecureBuffer` 中，用 `clear()` + `runtime.KeepAlive()` 擦除。内存转储什么都看不到——我们验证过。

2. **你可以向审计员证明每一次密钥操作。**
   HMAC 哈希链审计日志。文件轮转 + Syslog 双写。篡改一条记录，整条链断裂——可验证。

3. **你不需要专门的团队来运行它。**
   单个 13MB 二进制。无插件、无脚本引擎、无反射。`./bin/yvonne dev` 30 秒开始加密。

## 快速开始

```bash
./bin/yvonne dev --demo       # 30秒：自动创建密钥，打印 curl 示例
./bin/yvonne dev --dashboard  # 打开浏览器访问 Web 控制台（端口 8250）
```

## 功能

### 基础能力
- AES-256-GCM / SM4-GCM 信封加密 + 版本化自路由密文
- RSA-4096 / ECDSA P-256 / SM2 非对称密码（签名 / 验签 / 重加密）
- HMAC 生成 / 验证（常量时间比较）
- 创建 / 轮转 / 粉碎 / 软删除 / 恢复 密钥全生命周期
- BYOK 自带密钥（阅后即焚传输密钥）
- GDK 生成数据密钥（支持无明文模式）
- JWT RBAC（RS/ES/HS/SM2）+ AppRole + K8s SA 认证
- PostgreSQL 集群 + Advisory Lock 选主
- Shamir 分片冷存储备份
- 紧急封印（一个 API 擦除一切）
- HTTP REST + gRPC + MCP（AI Agent）三协议
- Web 控制台（仪表盘 / 密钥 / 密码运算 / 审计 / MFA & Quorum）

### 安全工程
- 多租户密钥隔离（前缀作用域，向后兼容）
- MFA TOTP（RFC 6238）敏感操作二次确认
- K-of-N Quorum 审批工作流（防自批准 + 幂等 + 过期清理）
- 可插拔 KEK 抽象（软件 / HSM），PKCS#11 支持
- 严格国密模式：禁用 AES/RSA/ECDSA
- RFC 8998 国密 TLS（SM2 双证书 + SM4/SM3）
- OpenTelemetry 链路追踪（TraceID 传播到审计日志）
- 告警 Webhook（Slack / 钉钉 / PagerDuty 自动检测）
- SIGHUP 配置热更新
- gosec 0 issues + govulncheck 0 漏洞（12 项安全自检）
- 300+ 测试：单元 / 集成（PG）/ gRPC / 浏览器 Selenium E2E（39/39 通过）

### 独有能力
- **MCP（AI Agent）集成** — Claude/GPT 原生调用 Yvonne（加密 + 受限解密）
- **国密全栈（GM/T）** — SM2/SM3/SM4 + JWT SM2 + HMAC-SM3 审计链 + RFC 8998 TLS + 严格模式
- **13MB 单二进制** — 无运行时依赖，可跑在树莓派和工业网关上
- **三语言 SDK** — Go / Python / Java，含重试、熔断、trace_id 透传

## 文档

- [产品演进路线图](docs/roadmap.md) | [交付物清单](docs/deliverables.md)
- [国密合规指南](docs/gmsm-compliance.md) | [密评二级自评报告](docs/compliance/self-assessment-level2.md)
- [v1.3 合规功能指南](docs/v1.3-compliance.md) | [覆盖率审计报告](docs/coverage-audit.md)
- [部署指南](docs/deployment.md) | [升级指南](docs/upgrade-guide.md)
- [gRPC API](docs/grpc-api.md) | [MCP API](docs/mcp-api.md) | [PKCS#11 HSM](docs/pkcs11-hsm.md)
- [AES→SM4 迁移](docs/aes-to-sm4-migration.md) | [合规证据包](docs/compliance/README.md)
- [Changelog](CHANGELOG.md) | [Security Policy](SECURITY.md)

## 编译与测试

```bash
make build                     # 编译
make ci                        # vet + fmt + 安全 + 测试
go test -tags=integration ./...  # PG 集成测试
```

## 路线图

- [x] mTLS + PKCS#11 HSM + 国密闭环 + Sign/Verify (v1.0-v1.2)
- [x] MFA + Quorum + RFC 8998 + OTel + 多租户 + Web 控制台 (v1.3)
- [ ] KMIP + Vault 兼容 + HSM 集群 + TPM 2.0 (v2.0)

完整路线图：[docs/roadmap.md](docs/roadmap.md)

## 许可证

Apache License 2.0。见 [LICENSE](LICENSE)。

---

> **⚠️ 合规免责声明：** 本项目未通过 FIPS 140-3 或 PCI-DSS 正式审计。对于强监管环境（金融、医疗、政府），需完成第三方审计 + FIPS HSM 集成 + 合规认证后方可生产部署。
