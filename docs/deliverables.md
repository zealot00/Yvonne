# Yvonne KMS 交付物文档

> 版本：v1.3.0 | 日期：2026-06-30 | 状态：GA

本文档记录 Yvonne KMS 从 v1.0 GA 到 v1.3.0 的完整交付物清单。

## 一、版本发布历史

| 版本 | 日期 | 主题 | Tag | Release |
|---|---|---|---|---|
| v1.0.0 | 2026-06-26 | GA 稳定版 | `v1.0.0` | ✅ |
| v1.1.0 | 2026-06-28 | 国密闭环版 | `v1.1.0` | ✅ |
| v1.1.1 | 2026-06-29 | 安全修复版（17 bugs） | `v1.1.1` | ✅ |
| v1.2.0 | 2026-06-29 | API 完善版 | `v1.2.0` | ✅ |
| v1.2.1 | 2026-06-29 | 安全加固版（CORS + gosec + Go 1.25.11） | `v1.2.1` | ✅ |
| v1.2.2 | 2026-06-30 | Sign/Verify + ReEncrypt 完整实现 | `v1.2.2` | ✅ |
| v1.3.0 | 2026-06-30 | 合规深化版（MFA + Quorum + 国密 TLS + OTel） | `v1.3.0` | ✅ |

## 二、各版本交付物清单

### v1.0.0 — GA 稳定版

**核心功能**：
- 信封加密（Encrypt/Decrypt）+ 版本化自路由密文
- 密钥生命周期（CreateKey/RotateKey/ShredKey/SoftDeleteKey/RestoreKey）
- GenerateDataKey（GDK）
- Shamir 秘密分割解封（K-of-N）
- BYOK（Bring Your Own Key）— TransitPub + ImportKey
- 双写哈希链审计（HMAC-SHA256 + 文件轮转 + Syslog）
- JWT RBAC 引擎（RS256/384/512, ES256/384/512, HS256/384/512）
- 资源级授权（AllowedKeys 通配符 + 前缀匹配）
- 自动密钥轮转（PostgreSQL Advisory Lock 集群选主）
- 冷存储备份（Shamir 分片 USB 备份）
- 紧急封印（Emergency Seal）
- HTTP REST + gRPC + MCP（AI Agent）三协议
- HSM 支持（PKCS#11 + SoftHSM CI）
- Admin Web UI

**API 端点**：
```
GET  /api/v1/sys/health
POST /api/v1/sys/unseal
POST /api/v1/sys/panic
POST /api/v1/keys
POST /api/v1/keys/{id}/rotate
DELETE /api/v1/keys/{id}/shred
PATCH /api/v1/keys/{id}/soft-delete
POST /api/v1/keys/{id}/restore
POST /api/v1/keys/{id}/generate-data-key
POST /api/v1/keys/transit-pub
POST /api/v1/keys/import
POST /api/v1/encrypt
POST /api/v1/decrypt
POST /api/v1/audit/query
GET  /metrics
gRPC: 全镜像（15 个 RPC 方法）
MCP: yvonne_encrypt + yvonne_decrypt
```

### v1.1.0 — 国密闭环版

**新增功能**：
- SM2 公钥密码（密钥对生成/加密/解密/签名/验签）
- SM3 密码杂凑（HMAC-SM3 审计链）
- SM4 分组密码（GCM 模式）
- JWT SM2 签名（`-tags gmsm`）
- 严格国密模式（`crypto.strict: true`）
- 国密密码套件（`crypto.suite: gmsm`）
- AES→SM4 迁移指南

### v1.1.1 — 安全修复版

**Bug 修复（17 个）**：
- PEM 解析静默吞错（C-1/C-2）
- SM2 PEM 缺类型断言（C-3）
- HTTP 无请求体大小限制（C-4）→ MaxBytesReader 1MB
- PEM 私钥磁盘残留（C-5）→ atomicWriteFileSecure
- JWT 缺过期/签发者校验（Auth-1）
- gRPC TLS 明文暴露（Auth-18）
- anchor 损坏静默重置（Audit-10）
- TLS 密码套件不可配置（Config-1）
- metrics 标签基数爆炸（Config-5）
- SigningMethod 切片 panic（BUG-018）
- CORS OPTIONS 405 + 实际请求无头
- Shamir gfInv(0) 静默返回 0（BUG-17）
- Shamir 路径 traversal（BUG-013）
- Limit=-1 DoS（BUG-6）
- CRLF 注入（BUG-9）

### v1.2.0 — API 完善版

**新增 API**：
- `POST /api/v1/mac/generate` — HMAC-SHA256 生成
- `POST /api/v1/mac/verify` — HMAC 验证（常量时间比较）
- `POST /api/v1/keys/gdk-no-plaintext` — 仅返回密文 DEK
- `GET /api/v1/keys/public-key` — 获取非对称密钥公钥
- `POST /api/v1/sign` — 非对称签名（骨架）
- `POST /api/v1/verify` — 验签（骨架）
- `POST /api/v1/re-encrypt` — KMS 内重加密（骨架）

### v1.2.1 — 安全加固版

**安全加固**：
- gosec 0 issues（21 #nosec）
- govulncheck 0 vulnerabilities
- Go 1.25.8 → 1.25.11（修复 10 个标准库 CVE）
- pgx v5.5.3 → v5.9.2
- golang.org/x/net v0.51.0 → v0.53.0
- CORS OPTIONS 预检修复 + 实际请求 CORS 头
- 12 个 CORS 集成测试

### v1.2.2 — Sign/Verify + ReEncrypt 完整实现

**新增功能**：
- `POST /api/v1/sign` — RSA-PSS / ECDSA / SM2 签名（服务端哈希）
- `POST /api/v1/verify` — 验签往返
- `POST /api/v1/re-encrypt` — KMS 内重加密（完整实现）
- `POST /api/v1/keys/asymmetric` — 创建 RSA/ECDSA/SM2 密钥
- SM2 全链路接入（CreateAsymmetricKey + Sign + Verify）
- KeyType 常量补全（KeyTypeSM2 / KeyTypeSM4）

### v1.3.0 — 合规深化版

**新增功能**：
- **MFA TOTP（RFC 6238）** — 敏感操作二次确认
  - `POST /api/v1/auth/mfa/setup` / `verify` / `disable`
  - ±30s 时钟漂移 + 防重放 + X-MFA-Code header
- **Quorum Approval（K-of-N 审批）**
  - `POST /api/v1/approvals` + `approve` + `reject` + `GET /api/v1/approvals`
  - 防自批准 + 幂等 + 过期清理 + 状态机
- **RFC 8998 国密 TLS（GB/T 38636）**
  - SM2 双证书 + GMTLS_SM2_WITH_SM4_SM3
- **OpenTelemetry tracing**
  - OTLP gRPC exporter + otelhttp 自动 instrumentation
  - TraceID 传播到 audit log
- **Config Reload（SIGHUP）**
  - 热更新白名单（logging/audit/observability）
- **Alerting Webhook**
  - Slack/钉钉/PagerDuty 自动检测格式

**配置新增**：
```json
{
  "mfa": {"enabled": true, "issuer": "Yvonne KMS"},
  "observability": {
    "tracing": {"enabled": true, "endpoint": "localhost:4317"},
    "alerting": {"enabled": true, "webhook_url": "..."}
  }
}
```

## 三、代码统计

### 源代码

| 指标 | 数值 |
|---|---|
| Go 源文件 | 77 个 |
| 代码行数 | ~15,000 行 |
| 测试文件 | 40+ 个 |
| 测试代码 | ~10,000 行 |
| Proto 定义 | 1 个（15 RPC 方法） |
| 依赖 | 20+ Go modules |

### 测试统计

| 测试类型 | 数量 |
|---|---|
| 单元测试（标准 CI） | 200+ |
| Integration 测试（PG） | 35 |
| MCP 工具调用测试 | 11 |
| gRPC E2E 测试 | 12 |
| 二进制全流程 E2E | 17 |
| CORS 集成测试 | 12 |
| **总计** | **287+** |

### 覆盖率

| 包 | 覆盖率 |
|---|---|
| metrics | 94.4% |
| memguard | 89.5% |
| seal | 88.2% |
| mcp | 86.7% |
| observability | 85.5% |
| grpc | 82.4% |
| auth | 82.0% |
| audit | 81.7% |
| admin | 81.7% |
| config | 81.3% |
| lifecycle | 81.2% |
| crypto | 72.3% |
| service | 72.3% |
| api | 64.3% |
| storage | 37.1%（integration: 62%） |
| bootstrap | 34.2% |

### 安全扫描

```
gosec:       0 issues (27 #nosec annotations)
govulncheck: 0 vulnerabilities
```

## 四、API 完整清单（v1.3.0）

### HTTP REST API

| 方法 | 端点 | 认证 | 说明 |
|---|---|---|---|
| GET | /api/v1/sys/health | 无 | 健康检查 |
| POST | /api/v1/sys/unseal | 无 | Shamir 分片提交 |
| POST | /api/v1/sys/panic | Admin Token | 紧急封印 |
| POST | /api/v1/keys | Bearer Token | 创建对称密钥 |
| POST | /api/v1/keys/asymmetric | Bearer Token | 创建非对称密钥 |
| POST | /api/v1/keys/{id}/rotate | Bearer Token | 轮转密钥 |
| DELETE | /api/v1/keys/{id}/shred | Bearer Token + MFA | 物理粉碎 |
| PATCH | /api/v1/keys/{id}/soft-delete | Bearer Token | 软删除 |
| POST | /api/v1/keys/{id}/restore | Bearer Token | 恢复 |
| POST | /api/v1/keys/{id}/generate-data-key | Bearer Token | 生成数据密钥 |
| POST | /api/v1/keys/gdk-no-plaintext | Bearer Token | 生成无明文 DEK |
| GET | /api/v1/keys/public-key | Bearer Token | 获取公钥 |
| POST | /api/v1/keys/transit-pub | 无 | BYOK 传输公钥 |
| POST | /api/v1/keys/import | 无 | BYOK 导入密钥 |
| POST | /api/v1/encrypt | Bearer Token | 信封加密 |
| POST | /api/v1/decrypt | Bearer Token | 信封解密 |
| POST | /api/v1/sign | Bearer Token | 非对称签名 |
| POST | /api/v1/verify | Bearer Token | 验签 |
| POST | /api/v1/mac/generate | Bearer Token | HMAC 生成 |
| POST | /api/v1/mac/verify | Bearer Token | HMAC 验证 |
| POST | /api/v1/re-encrypt | Bearer Token | KMS 内重加密 |
| POST | /api/v1/audit/query | Bearer Token | 审计日志查询 |
| POST | /api/v1/auth/mfa/setup | Bearer Token | MFA 注册 |
| POST | /api/v1/auth/mfa/verify | Bearer Token | MFA 验证 |
| POST | /api/v1/auth/mfa/disable | Bearer Token + MFA | MFA 禁用 |
| POST | /api/v1/approvals | Bearer Token | 创建审批 ticket |
| GET | /api/v1/approvals | Bearer Token | 列出/查询 ticket |
| POST | /api/v1/approvals/approve | Bearer Token | 审批通过 |
| POST | /api/v1/approvals/reject | Bearer Token | 审批拒绝 |
| GET | /metrics | Bearer Token | Prometheus 指标 |

### gRPC API（全镜像）

15 个 RPC 方法，与 HTTP REST 一一对应。

### MCP API

| Tool | 说明 |
|---|---|
| yvonne_encrypt | AI Agent 加密 |
| yvonne_decrypt | AI Agent 解密（白名单 + 64KB 限制） |

## 五、SDK

| 语言 | 版本 | 状态 |
|---|---|---|
| Go | v1.3.0 | ✅ 完整 |
| Python | v1.3.0 | ✅ 完整 |
| Java | — | 计划中 |

## 六、文档清单

| 文档 | 说明 |
|---|---|
| README.md | 项目简介 + 快速开始 |
| CHANGELOG.md | 完整变更日志 |
| docs/roadmap.md | 产品演进路线图 |
| docs/v1.3-compliance.md | v1.3 合规功能指南 |
| docs/gmsm-roadmap.md | 国密合规路线图 |
| docs/deployment.md | 部署指南 |
| docs/upgrade-guide.md | 升级指南 |
| docs/grpc-api.md | gRPC API 指南 |
| docs/mcp-api.md | MCP API 指南 |
| docs/pkcs11-hsm.md | PKCS#11 HSM 指南 |
| docs/aes-to-sm4-migration.md | AES→SM4 迁移指南 |
| docs/coverage-audit.md | 覆盖率审计报告 |
| docs/coverage-report.html | HTML 覆盖率报告 |
| docs/deliverables.md | 本文档 |
| SECURITY.md | 安全策略 |
| CONTRIBUTING.md | 贡献指南 |

## 七、编译模式

| 模式 | 构建标签 | 说明 |
|---|---|---|
| 标准 | `go build` | AES-256-GCM + SHA-256 |
| 国密 | `go build -tags gmsm` | + SM2/SM3/SM4 + 国密 TLS |
| HSM | `go build -tags hsm,pkcs11` | + PKCS#11 HSM |
| 全功能 | `go build -tags gmsm,hsm,pkcs11` | 国密 + HSM |

## 八、安全合规

| 标准 | 状态 |
|---|---|
| gosec | 0 issues |
| govulncheck | 0 vulnerabilities |
| 安全自检（12 项） | 全通过 |
| FIPS 140-3 | ❌ 未认证（国密路线为主） |
| PCI DSS 4.0 | ⚠️ 部分满足（MFA + Quorum + 审计链） |
| GB/T 39786-2021 | ⚠️ 第二级可达（国密闭环） |
| 等保 2.0 | ⚠️ 部分满足 |
