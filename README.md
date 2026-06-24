# 🧊 Yvonne KMS

[English](#english) | [中文](#中文)

---

<a id="english"></a>

## English

Because paying a cloud vendor $500/month just to hold your secrets hostage is institutional extortion.

Yvonne is a production-grade, paranoia-driven Key Management System (KMS) written in Go. She is cold, unforgiving, and explicitly designed for teams who trust absolutely no one—especially not their infrastructure providers, their garbage collector, or themselves.

If you are tired of storing your database credentials as Base64 strings in a "secure" config map, or if your compliance auditor is breathing down your neck and you refuse to pay the "Cloud Mafia" tax, you've come to the right place.

### 💀 Why Yvonne?

Most enterprise KMS solutions are either bloated black boxes that cost more than your engineering team's combined salary, or they are "managed services" that require you to blindly trust that some hyperscaler isn't keeping a backdoor copy of your master key.

Yvonne was built from the ground up with **Absolute Zero Trust**. She doesn't trust the network, she doesn't trust the database, and she certainly doesn't trust Go's Garbage Collector.

### 🔪 Core Features

- **Alzheimer's for Secrets (Absolute Memory Guard)**: `clear()` + `runtime.KeepAlive()` defeats DCE. Memory dumps yield nothing but ghosts.
- **Horcrux-Level Master Keys (Shamir's Secret Sharing)**: Master Key shattered into 5 shards across GF(2^8). 3 shards to resurrect.
- **The Poor Man's Auto-Unseal (Local PKI)**: Zero-cost RSA-4096 unseal. Burn-after-reading: PEM file physically deleted after use.
- **Digital Cremation (True Crypto-Shredding)**: `SELECT FOR UPDATE` → overwrite with NULL → DELETE row. Not an `is_deleted` flag.
- **The Alibi Engine (Immutable Audit Chains)**: HMAC-SHA256 hash chain + daily file rotation + async syslog dual-write. Tamper = chain breaks.
- **Cold Storage Shamir Backup**: Split Wrapped CMK to N USB drives. Lose some? No problem. Lose all? See disclaimer.
- **Emergency Seal**: One API call wipes everything. Deep freeze until manual restart + Shamir unseal.
- **Versioned Self-Routing Ciphertext**: `[uint32 version][nonce][ciphertext+tag]` — decrypt auto-routes to correct DEK version.
- **RBAC + Policy Engine**: AppRole token + wildcard key matching + action allowlist. Default deny.
- **Cluster Cache Sync**: Postgres LISTEN/NOTIFY for multi-node DEK cache invalidation.

### ⚠️ Disclaimer

Cryptography is a loaded gun. Yvonne provides the safety mechanism, but if you point it at your foot and pull the trigger, she will not stop the bullet.

- **Lose the Shamir shards?** Your data is gone.
- **Delete the PostgreSQL database without a backup?** Your data is gone.
- **Trigger the Emergency Seal?** Yvonne plays dead until manually resurrected.

Yvonne does not forgive, and she does not have a "Forgot Password" link.

### 🚀 Quick Start

```bash
# Dev mode (zero config, in-memory)
./bin/yvonne dev

# Full cluster setup
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

Web UI: `http://127.0.0.1:8250` | API: `http://127.0.0.1:8200`

### 📚 Documentation

- [Deployment Guide](docs/deployment.md)
- [Test Coverage Report](docs/coverage.md)
- [Security Checklist](.github/CODE_REVIEW_GUIDELINES.md)

### 🔧 Build & Test

```bash
make build          # compile
make ci             # local CI (vet + fmt + security + tests)
make coverage       # coverage report
bash scripts/security-check.sh  # 12 security checks
```

### 📋 API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | Health check |
| POST | `/api/v1/sys/unseal` | Submit Shamir shard |
| POST | `/api/v1/sys/panic` | Emergency seal (irreversible) |
| POST | `/api/v1/keys` | Create key (AES/RSA/ECDSA) |
| POST | `/api/v1/keys/{id}/rotate` | Rotate key |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred |
| PATCH | `/api/v1/keys/{id}/soft-delete` | Soft delete (recycle bin) |
| POST | `/api/v1/keys/{id}/restore` | Restore from recycle bin |
| POST | `/api/v1/encrypt` | Envelope encrypt |
| POST | `/api/v1/decrypt` | Envelope decrypt |
| GET | `/metrics` | Prometheus metrics |

### 🗺️ Roadmap

- [ ] TPM 2.0 support — hardware-bound CMK unseal
- [ ] PKCS#11 HSM integration
- [ ] mTLS client certificate authentication
- [ ] Audit chain verification API endpoint

---

<a id="中文"></a>

## 中文

因为每月向云厂商支付 500 美元仅为了让对方扣留你的密钥，这本质上是制度性勒索。

Yvonne 是一个生产级、偏执驱动的密钥管理系统（KMS），用 Go 编写。她冷酷、不可饶恕，专门为那些谁都不信任的团队设计——尤其不信任他们的基础设施供应商、垃圾回收器、以及他们自己。

如果你已经厌倦了把数据库凭证以 Base64 字符串存在所谓的"安全"配置映射里，或者合规审计员正在你脖子上吹气而你拒绝支付"云黑手党"保护费，那你来对地方了。

### 💀 为什么选择 Yvonne？

大多数企业级 KMS 解决方案要么是臃肿的黑盒，成本比整个工程团队的薪水加起来还高；要么是"托管服务"，要求你盲目相信某个超大规模云厂商没有偷偷留一份主密钥的后门副本。

Yvonne 从零开始以**绝对零信任**构建。她不信任网络，不信任数据库，当然也不信任 Go 的垃圾回收器。

### 🔪 核心特性

- **密钥阿尔茨海默症（绝对内存防御）**：`clear()` + `runtime.KeepAlive()` 击败 DCE 优化。内存转储只能看到幽灵。
- **魂器级主密钥（Shamir 秘密分割）**：主密钥在 GF(2^8) 有限域中被击碎为 5 份。3 份才能复活。
- **穷人的自动解封（Local PKI）**：零成本 RSA-4096 解封。阅后即焚：PEM 文件用完物理删除。
- **数字火化（真正的 Crypto-Shredding）**：`SELECT FOR UPDATE` → 覆写为 NULL → DELETE 删除行。不是 `is_deleted` 标志位。
- **不在场证明引擎（不可篡改审计链）**：HMAC-SHA256 哈希链 + 按天文件轮转 + 异步 Syslog 双写。篡改即断链。
- **冷存储 Shamir 备份**：将封装主密钥分片到 N 个 U 盘。丢几个？没问题。全丢？看免责声明。
- **紧急封印**：一个 API 调用擦除一切。深度冰冻直到手动重启 + Shamir 解封。
- **版本化自路由密文**：`[uint32 版本号][nonce][密文+tag]` — 解密自动路由到正确的 DEK 版本。
- **RBAC + 策略引擎**：AppRole 令牌 + 通配符密钥匹配 + 操作白名单。默认拒绝。
- **集群缓存同步**：Postgres LISTEN/NOTIFY 实现多节点 DEK 缓存失效。

### ⚠️ 免责声明

密码学是一把上了膛的枪。Yvonne 提供安全机制，但如果你把枪对准自己的脚扣动扳机，她不会替你挡子弹。

- **弄丢了 Shamir 碎片？** 你的数据没了。
- **没备份就删了 PostgreSQL 数据库？** 你的数据没了。
- **触发了紧急封印？** Yvonne 会装死直到被手动复活。

Yvonne 不原谅人，也没有"忘记密码"链接。

### 🚀 快速开始

```bash
# 开发模式（零配置，内存存储）
./bin/yvonne dev

# 完整集群部署
./bin/yvonne unseal-keygen --out /secure/unseal.pem
./bin/yvonne init --config config.json --pub-key /tmp/pub.pem
./bin/yvonne server --config config.json
```

Web 管理界面：`http://127.0.0.1:8250` | API：`http://127.0.0.1:8200`

### 📚 文档

- [部署指南](docs/deployment.md)
- [测试覆盖率报告](docs/coverage.md)
- [安全检查清单](.github/CODE_REVIEW_GUIDELINES.md)

### 🔧 编译与测试

```bash
make build          # 编译
make ci             # 本地 CI（vet + fmt + 安全 + 测试）
make coverage       # 覆盖率报告
bash scripts/security-check.sh  # 12 项安全检查
```

### 📋 API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/sys/health` | 健康检查 |
| POST | `/api/v1/sys/unseal` | 提交 Shamir 碎片 |
| POST | `/api/v1/sys/panic` | 紧急封印（不可逆） |
| POST | `/api/v1/keys` | 创建密钥（AES/RSA/ECDSA） |
| POST | `/api/v1/keys/{id}/rotate` | 轮转密钥 |
| DELETE | `/api/v1/keys/{id}/shred` | 物理粉碎 |
| PATCH | `/api/v1/keys/{id}/soft-delete` | 软删除（回收站） |
| POST | `/api/v1/keys/{id}/restore` | 从回收站恢复 |
| POST | `/api/v1/encrypt` | 信封加密 |
| POST | `/api/v1/decrypt` | 信封解密 |
| GET | `/metrics` | Prometheus 指标 |

### 🗺️ 路线图

- [ ] TPM 2.0 支持 — 硬件绑定 CMK 解封
- [ ] PKCS#11 HSM 集成
- [ ] mTLS 客户端证书认证
- [ ] 审计链验证 API 端点

---

## License

Private. All rights reserved.
