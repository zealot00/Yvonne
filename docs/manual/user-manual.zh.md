# Yvonne KMS 用户手册

> 版本：v1.3.2 | 最后更新：2026-07-01

欢迎使用 Yvonne KMS。本手册覆盖产品的全部功能与特性，按由浅入深的顺序组织，既适合初次接触的运维工程师，也适合需要深度定制的架构师。

## 目录

1. [产品简介](#1-产品简介)
2. [使用场景](#2-使用场景)
3. [安装与编译](#3-安装与编译)
4. [快速开始](#4-快速开始)
5. [运行模式与配置](#5-运行模式与配置)
6. [密钥管理](#6-密钥管理)
7. [密码运算](#7-密码运算)
8. [认证与授权](#8-认证与授权)
9. [多租户隔离](#9-多租户隔离)
10. [MFA 与 Quorum 审批](#10-mfa-与-quorum-审批)
11. [审计日志](#11-审计日志)
12. [可观测性](#12-可观测性)
13. [Web 控制台](#13-web-控制台)
14. [SDK 使用指南](#14-sdk-使用指南)
15. [部署指南](#15-部署指南)
16. [国密合规](#16-国密合规)
17. [HSM 集成](#17-hsm-集成)
18. [故障排查](#18-故障排查)
19. [附录](#19-附录)

---

## 1. 产品简介

Yvonne KMS 是一个自托管的密钥管理系统，为团队提供信封加密、可审计的密钥生命周期管理、绝对内存纪律和基于 JWT 的 RBAC 鉴权。

### 三个核心承诺

1. **明文密钥永不离开进程** — 所有明文密钥锁定在 `memguard.SecureBuffer` 中，用 `clear()` + `runtime.KeepAlive()` 擦除。网络、数据库、甚至 Go 的 GC 都无法泄露。

2. **每次密钥操作都可证明可审计** — HMAC 哈希链审计日志，文件轮转 + Syslog 双写。篡改一条记录，整条链断裂并报警。

3. **你拥有完整主权** — Shamir 分片主密钥，HSM 托管 CMK，全链路自托管。无厂商锁定，无云回调。

### 适用与不适用场景

- **适用**：金融支付、医疗、政府等强监管行业的内部密钥管理；微服务架构下的统一加密服务；AI Agent 通过 MCP 协议调用 KMS；国密合规场景（SM2/SM3/SM4 全栈）；需要 HSM 的企业。
- **不适用**：需要 FIPS 140-3 认证的场景（Yvonne 本身不是 FIPS 验证模块，需集成 FIPS HSM）；公网直接暴露的服务（Yvonne 设计为内网服务，需通过 mTLS 反向代理暴露）。

详细使用场景与架构示例见[第 2 章 使用场景](#2-使用场景)。

---

## 2. 使用场景

本章通过 7 个典型场景说明 Yvonne 在不同业务中的落地方式，每个场景给出架构要点、关键配置与代码片段。

### 2.1 微服务统一加密服务

**场景**：电商平台有订单、支付、用户、库存等十几个微服务，每个服务都需要加密敏感字段（手机号、身份证、银行卡号）。希望统一密钥管理、统一审计、避免每个服务各自实现加密逻辑。

**架构**：

```
订单服务 ─┐
支付服务 ─┤
用户服务 ─┼──→ Yvonne KMS 集群 ──→ PostgreSQL
库存服务 ─┘        │
                   ├─ 哈希链审计 → Syslog → SIEM
                   └─ Prometheus metrics → Grafana
```

**关键设计**：

1. 每个服务一个 AppRole，最小权限（仅 `Encrypt` + `Decrypt`）
2. 密钥按业务前缀命名：`order-*`、`payment-*`、`user-*`
3. 使用信封加密：KMS 生成 DEK，服务本地加密大量数据

**配置示例**：

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "order-service",
        "token": "order-secure-token",
        "allowed_keys": ["order-*"],
        "allowed_actions": ["encrypt", "decrypt", "generate-data-key"]
      },
      {
        "role_id": "payment-service",
        "token": "payment-secure-token",
        "allowed_keys": ["payment-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

**服务端代码（Go SDK）**：

```go
// 订单服务加密用户手机号
resp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "order-user-phone",
    Plaintext: []byte(user.Phone),
})
// 将 resp.Ciphertext 存入订单数据库
```

**收益**：密钥不落服务、全量审计、权限隔离、自动轮转。

---

### 2.2 数据库字段级加密

**场景**：用户表的身份证号、手机号、邮箱需要加密存储，但又要支持按手机号查询。

**方案**：采用"信封加密 + HMAC 索引"双字段策略。

**表结构**：

```sql
CREATE TABLE users (
    id           BIGSERIAL PRIMARY KEY,
    phone_enc    BYTEA,       -- Yvonne 加密后的密文
    phone_hmac   VARCHAR(64), -- HMAC 值（用于查询索引）
    id_card_enc  BYTEA,
    email_enc    BYTEA
);
CREATE INDEX idx_phone_hmac ON users(phone_hmac);
```

**写入**：

```go
// 1. 加密手机号
encResp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "user-phone",
    Plaintext: []byte(phone),
})

// 2. 生成 HMAC（用专门的 HMAC 密钥，不可逆）
macResp, _ := client.GenerateMAC(ctx, &yvonne.MACRequest{
    KeyID: "user-phone-hmac",
    Data:  []byte(phone),
})

// 3. 存入数据库
db.Exec("INSERT INTO users (phone_enc, phone_hmac) VALUES ($1, $2)",
    encResp.Ciphertext, macResp.MAC)
```

**按手机号查询**：

```go
// 1. 对输入手机号生成 HMAC
macResp, _ := client.GenerateMAC(ctx, &yvonne.MACRequest{
    KeyID: "user-phone-hmac",
    Data:  []byte(inputPhone),
})

// 2. 用 HMAC 查索引（无需解密全部数据）
var user User
db.QueryRow("SELECT phone_enc FROM users WHERE phone_hmac = $1", macResp.MAC).Scan(&user.PhoneEnc)

// 3. 解密
decResp, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
    KeyID:      "user-phone",
    Ciphertext: user.PhoneEnc,
})
```

**要点**：HMAC 密钥与加密密钥分离；HMAC 不可逆但可等值匹配，加密密钥可解密。

---

### 2.3 AI Agent 密钥访问（MCP）

**场景**：AI Agent（如 Claude、GPT）需要访问加密的用户数据，但不能直接持有解密密钥。希望 Agent 通过标准化协议调用 KMS，且可限制其只能解密特定密钥。

**架构**：

```
用户 ──→ AI Agent ──→ MCP Server ──→ Yvonne KMS
                       │
                       └─ 仅暴露 encrypt + restricted decrypt
```

**配置**：

```json
{
  "server": {
    "mcp": {
      "enabled": true,
      "bind_port": 8202
    }
  },
  "auth": {
    "app_roles": [
      {
        "role_id": "ai-agent",
        "token": "ai-agent-token",
        "allowed_keys": ["ai-readable-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

**Agent 调用**：AI Agent 通过 MCP 协议调用 `yvonne.encrypt` / `yvonne.decrypt` 工具。KMS 限制 Agent 只能访问 `ai-readable-*` 前缀的密钥，且所有操作全量审计。

**收益**：Agent 无需持有密钥、操作可审计、权限可回收、密钥可轮转。

---

### 2.4 国密合规场景

**场景**：金融机构需满足 GB/T 39786-2021 密码应用二级要求，全栈使用国密算法，并通过密评。

**配置**：

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  },
  "server": {
    "tls": {
      "enabled": true,
      "gm_enabled": true,
      "gm_sign_cert_file": "/etc/yvonne/certs/sm2-sign.pem",
      "gm_sign_key_file": "/etc/yvonne/certs/sm2-sign-key.pem",
      "gm_enc_cert_file": "/etc/yvonne/certs/sm2-enc.pem",
      "gm_enc_key_file": "/etc/yvonne/certs/sm2-enc-key.pem"
    }
  },
  "auth": {
    "jwt": {"signing_method": "SM2"}
  },
  "audit": {"dir": "/var/log/yvonne", "syslog_enabled": true}
}
```

**合规对照**（节选，完整 24 项见 [docs/compliance/self-assessment-level2.md](../compliance/self-assessment-level2.md)）：

| 密评二级要求 | Yvonne 实现 |
|---|---|
| SM4 对称加密 | SM4-GCM 信封加密 |
| SM2 非对称签名 | SM2 签名/验签 API |
| SM3 哈希 | HMAC-SM3 审计哈希链 |
| 国密 TLS | RFC 8998（SM2 双证书 + SM4/SM3） |
| 密钥生命周期 | 创建/轮转/软删除/物理销毁全流程 |
| 审计完整性 | HMAC 哈希链 + Syslog 双写 |

**编译**：`go build -tags gmsm -o bin/yvonne-gmsm ./cmd/yvonne`

---

### 2.5 Kubernetes 集群内密钥服务

**场景**：K8s 集群内的 Pod 需要访问 KMS 加密敏感配置，希望使用 ServiceAccount JWT 自动认证，无需管理静态 Token。

**架构**：

```
K8s Pod (SA: order-app) ──→ Yvonne KMS
   │                           │
   └─ 自动挂载 SA JWT           └─ K8s authenticator 验证 SA JWT
                                  并映射到 Policy
```

**KMS 配置**：

```json
{
  "auth": {
    "k8s": {
      "enabled": true,
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "audience": ["yvonne-kms"],
      "jwks_url": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
      "role_mapping": {
        "default/order-app": {
          "role_id": "order-app",
          "allowed_keys": ["order-*"],
          "allowed_actions": ["encrypt", "decrypt"]
        }
      }
    }
  }
}
```

**Pod 内代码**：

```go
// 自动读取 SA JWT（K8s 自动挂载到 /var/run/secrets/kubernetes.io/serviceaccount/token）
saToken, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
client := yvonne.New("http://yvonne.kms-system.svc:8200", string(saToken))

resp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "order-config",
    Plaintext: []byte(dbPassword),
})
```

**收益**：零 Token 管理、Pod 重启自动认证、RBAC 通过 K8s SA 控制。

---

### 2.6 多租户 SaaS 平台

**场景**：SaaS 平台服务多个企业客户，每个客户的密钥必须严格隔离，互不可见。

**配置**：

```json
{
  "multi_tenant": {"enabled": true},
  "auth": {
    "app_roles": [
      {
        "role_id": "tenant-a-admin",
        "token": "tenant-a-token",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-a"
      },
      {
        "role_id": "tenant-b-admin",
        "token": "tenant-b-token",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-b"
      }
    ]
  }
}
```

**隔离机制**：

- 租户 A 创建 `order-key` → 实际存储 `tenant-a:order-key`
- 租户 B 创建 `order-key` → 实际存储 `tenant-b:order-key`
- 两个租户互不可见，即使 KeyID 相同也隔离
- 对应用透明：客户端只需传 `order-key`，Yvonne 根据 Token 自动加前缀

**收益**：单 KMS 集群服务多租户、隔离无需应用层改造、向后兼容（`enabled=false` 时行为不变）。

---

### 2.7 高敏感操作的双人审批

**场景**：销毁生产密钥、紧急封印等高敏感操作必须经过 2 人审批，单人无法执行。

**流程**：

```
操作员 A 发起 ShredKey → 创建 Quorum 工单（required=2）
                          ↓
                       工单 pending
                          ↓
操作员 B 审批 ──────────────┘  （防自批准：A 不能批准自己的工单）
                          ↓
                       工单 approved
                          ↓
操作员 A 携带工单 ID 执行 ShredKey
```

**配置**：

```json
{
  "mfa": {
    "enabled": true,
    "sensitive_operations": ["ShredKey", "EmergencySeal"]
  }
}
```

**操作步骤**：

```bash
# 1. 操作员 A 发起审批
curl -X POST http://kms:8200/api/v1/approvals \
  -H 'Authorization: Bearer operator-a-token' \
  -d '{"operation":"ShredKey","key_id":"prod-master-key","required":2,"ttl_hours":24}'
# 返回 {"id":"ticket-123","status":"pending"}

# 2. 操作员 B 审批（A 不能自批准）
curl -X POST http://kms:8200/api/v1/approvals/approve \
  -H 'Authorization: Bearer operator-b-token' \
  -d '{"id":"ticket-123"}'

# 3. 操作员 A 携带 MFA + 工单 ID 执行销毁
curl -X DELETE http://kms:8200/api/v1/keys/prod-master-key/shred \
  -H 'Authorization: Bearer operator-a-token' \
  -H 'X-MFA-Code: 123456' \
  -H 'X-Approval-Ticket-ID: ticket-123'
```

**收益**：防单点误操作、防内部恶意、全流程审计、过期自动清理。

---

### 2.8 场景选型矩阵

| 场景 | 推荐模式 | 关键特性 | 复杂度 |
|---|---|---|---|
| 微服务统一加密 | Cluster | AppRole + 信封加密 | ★★☆ |
| 数据库字段加密 | Cluster | Encrypt + HMAC 索引 | ★★☆ |
| AI Agent 访问 | Cluster | MCP + 受限 Policy | ★★☆ |
| 国密合规 | Cluster + gmsm | SM2/SM3/SM4 + RFC 8998 | ★★★ |
| K8s 集成 | Cluster | K8s SA 认证 | ★★☆ |
| 多租户 SaaS | Cluster | 多租户隔离 | ★★☆ |
| 双人审批 | Cluster | MFA + Quorum | ★★★ |

---

## 3. 安装与编译

### 3.1 前置要求

- Go 1.25.11 或更高版本
- PostgreSQL 14+（仅 Cluster 模式需要）
- 可选：SoftHSM（HSM 测试）、Chrome（Web 控制台 E2E 测试）

### 3.2 从源码编译

```bash
git clone https://github.com/zealot00/Yvonne.git
cd Yvonne
make build
```

编译产物：`bin/yvonne`（13MB 单二进制，无运行时依赖）。

### 3.3 国密版本编译

```bash
go build -tags gmsm -o bin/yvonne-gmsm ./cmd/yvonne
```

国密版本包含 SM2/SM3/SM4 全栈支持、JWT SM2 签名、RFC 8998 国密 TLS。

### 3.4 HSM 版本编译

```bash
go build -tags hsm -o bin/yvonne-hsm ./cmd/yvonne
```

HSM 版本通过 PKCS#11 接口集成硬件安全模块。

### 3.5 Docker

```bash
docker build -t yvonne-kms .
docker run -p 8200:8200 yvonne-kms dev
```

### 3.6 验证安装

```bash
./bin/yvonne --help
./bin/yvonne dev --demo   # 30 秒启动 + 自动创建演示密钥
```

---

## 4. 快速开始

### 4.1 Dev 模式（零配置）

```bash
./bin/yvonne dev --demo
```

启动后：
- API 监听 `127.0.0.1:8200`
- Web 控制台监听 `127.0.0.1:8250`
- 内存存储，自动解封，自动创建 3 个演示密钥

### 4.2 第一次加密

```bash
# 加密
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"demo-order-key","plaintext":"SGVsbG8gWXZvbm5lIQ=="}'
# 返回 {"ok":true,"data":{"ciphertext":"AAAA...","version":1}}

# 解密
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"demo-order-key","ciphertext":"AAAA..."}'
# 返回 {"ok":true,"data":{"plaintext":"SGVsbG8gWXZvbm5lIQ==","version":1}}
```

> **注意**：`plaintext` 字段是 Base64 编码的字节串，不是原始字符串。

### 4.3 打开 Web 控制台

浏览器访问 `http://127.0.0.1:8250`，可见 Dashboard、密钥管理、密码运算、审计日志等页面。

### 4.4 三协议快速验证

```bash
# HTTP REST
curl http://127.0.0.1:8200/api/v1/sys/health | jq .

# gRPC（需启用 grpc）
grpcurl -plaintext 127.0.0.1:8201 yvonne.v1.YvonneService/Health

# MCP（AI Agent，需启用 mcp）
# 通过 MCP 协议调用 yvonne.encrypt / yvonne.decrypt
```

---

## 5. 运行模式与配置

### 5.1 两种模式

| 模式 | 适用场景 | 存储 | 解封 | 认证 |
|---|---|---|---|---|
| `dev` | 开发测试 | 内存 | 自动 | 无（可选） |
| `cluster` | 生产集群 | PostgreSQL | Shamir / PKI / HSM | AppRole / JWT / K8s SA |

### 5.2 配置文件

配置文件为 JSON 格式，通过 `--config` 参数加载。完整示例见 `deploy/examples/config-gmsm.json`。

#### 最小 Dev 配置

无需配置文件，直接 `./bin/yvonne dev`。

#### 最小 Cluster 配置

```json
{
  "mode": "cluster",
  "server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 8200,
    "tls": {"enabled": true, "cert_file": "/etc/yvonne/cert.pem", "key_file": "/etc/yvonne/key.pem"}
  },
  "storage": {
    "type": "postgres",
    "dsn": "postgresql://yvonne:password@db.internal:5432/yvonne"
  },
  "unseal": {
    "type": "shamir",
    "total_shares": 5,
    "threshold": 3
  },
  "auth": {
    "app_roles": [
      {
        "role_id": "admin",
        "token": "REPLACE_WITH_SECURE_TOKEN",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"]
      }
    ]
  },
  "audit": {
    "dir": "/var/log/yvonne",
    "retention_days": 180
  },
  "logging": {"level": "info", "redact_secrets": true}
}
```

### 5.3 配置项详解

#### `server` — 服务器

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `bind_addr` | string | `127.0.0.1` | 监听地址 |
| `bind_port` | int | `8200` | API 端口 |
| `tls.enabled` | bool | `false` | 启用 TLS |
| `tls.cert_file` | string | - | TLS 证书 |
| `tls.key_file` | string | - | TLS 私钥 |
| `tls.gm_enabled` | bool | `false` | 国密 TLS（RFC 8998） |
| `grpc.enabled` | bool | `false` | 启用 gRPC |
| `grpc.bind_port` | int | `8201` | gRPC 端口 |
| `admin.enabled` | bool | `true` | 启用 Web 控制台 |
| `admin.bind_port` | int | `8250` | 控制台端口 |
| `mcp.enabled` | bool | `false` | 启用 MCP（AI Agent） |

#### `storage` — 存储

| 字段 | 说明 |
|---|---|
| `type` | `memory`（Dev）或 `postgres`（Cluster） |
| `dsn` | PostgreSQL 连接串（含密码） |

#### `unseal` — 解封

| `type` | 说明 | 必填字段 |
|---|---|---|
| `auto` | Dev 自动解封 | - |
| `shamir` | Shamir 门限解封 | `total_shares`, `threshold` |
| `local_pki` | 本地 PKI 自动解封 | `pki_key_path` |
| `hsm` | HSM 硬件解封 | `hsm_backend`, `hsm_key_id` |

#### `auth` — 认证

支持三种认证方式，可组合使用：

- **AppRole**：静态 Token + Policy（适合服务间调用）
- **JWT**：RS/ES/HS/SM2 算法（适合用户身份）
- **K8s SA**：Kubernetes ServiceAccount JWT（适合集群内 Pod）

#### `crypto` — 密码套件

| 字段 | 说明 |
|---|---|
| `suite` | `standard`（AES-256-GCM + SHA-256）或 `gmsm`（SM4-GCM + SM3） |
| `strict` | `true` 时强制仅 SM2/SM3/SM4，禁用 AES/RSA/ECDSA |

### 5.4 环境变量覆盖

配置文件可被环境变量覆盖（优先级：环境变量 > 配置文件）：

| 环境变量 | 覆盖字段 |
|---|---|
| `YVONNE_MODE` | `mode` |
| `YVONNE_STORAGE_TYPE` | `storage.type` |
| `YVONNE_STORAGE_DSN` | `storage.dsn` |
| `YVONNE_UNSEAL_TYPE` | `unseal.type` |
| `YVONNE_UNSEAL_THRESHOLD` | `unseal.threshold` |

### 5.5 配置热更新

发送 `SIGHUP` 信号可热更新部分配置（无需重启）：

```bash
kill -HUP <yvonne-pid>
```

支持热更新的字段：`logging`、`audit`、`observability`。
冷更新字段（需重启）：`server`、`storage`、`unseal`、`auth`。

---

## 6. 密钥管理

Yvonne 支持 5 种密钥类型，覆盖对称、非对称、国密全栈。

### 6.1 密钥类型

| 类型 | 算法 | 用途 | 创建端点 |
|---|---|---|---|
| AES | AES-256-GCM | 信封加密、HMAC | `POST /api/v1/keys` |
| SM4 | SM4-GCM | 国密信封加密 | `POST /api/v1/keys`（gmsm 模式） |
| RSA | RSA-4096 | 签名/验签 | `POST /api/v1/keys/asymmetric` |
| ECDSA | ECDSA-P256 | 签名/验签 | `POST /api/v1/keys/asymmetric` |
| SM2 | SM2 | 国密签名/验签 | `POST /api/v1/keys/asymmetric`（gmsm 模式） |

### 6.2 密钥生命周期

```
CreateKey → Active → RotateKey → Active(v2) → SoftDelete → RecycleBin → Restore/Reaper
                                                          ↓
                                                      ShredKey (物理销毁)
```

#### 创建对称密钥

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"order-key","algorithm":"AES-256-GCM"}'
```

#### 创建非对称密钥

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/asymmetric \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"signing-key","key_type":"rsa"}'
# 返回 {"ok":true,"data":{"public_key":"...","version":1}}
```

`key_type` 取值：`rsa` / `ecdsa` / `sm2`。

#### 轮转密钥

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/rotate
# 旧版本密文仍可解密（版本自路由）
```

#### 软删除（进入回收站）

```bash
curl -X PATCH http://127.0.0.1:8200/api/v1/keys/order-key/soft-delete \
  -H 'Content-Type: application/json' \
  -d '{"version": 1}'
```

软删除后：仍可解密历史密文，不可加密，90 天后自动粉碎。

#### 从回收站恢复

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/restore \
  -H 'Content-Type: application/json' \
  -d '{"version": 1}'
```

#### 物理销毁（Crypto-Shred）

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred
# 永久销毁，所有密文无法解密
```

> **警告**：Shred 不可逆。如果配置了 MFA，需要 `X-MFA-Code` header。

### 6.3 BYOK（自带密钥）

允许将外部生成的 DEK 安全导入 Yvonne，无需明文传输。

```bash
# 1. 获取临时 RSA-4096 传输公钥（阅后即焚）
curl http://127.0.0.1:8200/api/v1/keys/transit-pub
# 返回 {"transit_key_id":"...","public_key":"..."}

# 2. 客户端用传输公钥加密自己的 DEK

# 3. 导入加密后的 DEK
curl -X POST http://127.0.0.1:8200/api/v1/keys/import \
  -H 'Content-Type: application/json' \
  -d '{
    "key_id":"imported-key",
    "transit_key_id":"...",
    "wrapped_material":"..."
  }'
```

### 6.4 自动轮转

Cluster 模式下，Yvonne 通过 PostgreSQL Advisory Lock 选主，每小时扫描过期密钥自动轮转，Actor=`SYSTEM_DAEMON`。

### 6.5 冷存储备份

Shamir 分片 Wrapped CMK 到 N 个 USB 驱动器，每片附 HMAC 完整性校验。详见 `yvonne init --wrapped-out`。

---

## 7. 密码运算

### 7.1 信封加密

```bash
# 加密
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -d '{"key_id":"order-key","plaintext":"SGVsbG8="}'

# 解密（自动路由到正确版本）
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"order-key","ciphertext":"AAAA..."}'
```

**密文格式**：`[uint32 版本 BE][nonce][密文+tag]` — 解密时自动路由到对应版本 DEK，无需客户端管理版本。

### 7.2 Generate Data Key（GDK）

客户端信封加密，KMS 永不接触业务明文。

```bash
# 带 plaintext DEK（本地加密）
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/generate-data-key
# 返回 {"plaintext_dek":"...","ciphertext_dek":"..."}

# 仅密文 DEK（更安全）
curl -X POST "http://127.0.0.1:8200/api/v1/keys/gdk-no-plaintext?key_id=order-key"
# 返回 {"ciphertext_dek":"..."}
```

### 7.3 签名与验签

```bash
# 签名（RSA-PSS / ECDSA / SM2）
curl -X POST http://127.0.0.1:8200/api/v1/sign \
  -d '{"key_id":"signing-key","data":"c2lnbi1tZQ=="}'
# 返回 {"signature":"...","version":1}

# 验签
curl -X POST http://127.0.0.1:8200/api/v1/verify \
  -d '{"key_id":"signing-key","data":"c2lnbi1tZQ==","signature":"..."}'
# 返回 {"valid":true,"version":1}
```

### 7.4 HMAC

```bash
# 生成 MAC
curl -X POST http://127.0.0.1:8200/api/v1/mac/generate \
  -d '{"key_id":"hmac-key","data":"bWFjLWRhdGE="}'
# 返回 {"mac":"...","version":1}

# 验证 MAC（常量时间比较）
curl -X POST http://127.0.0.1:8200/api/v1/mac/verify \
  -d '{"key_id":"hmac-key","data":"bWFjLWRhdGE=","mac":"..."}'
# 返回 {"valid":true,"version":1}
```

> HMAC 仅支持对称密钥（AES/SM4）。

### 7.5 ReEncrypt（重加密）

将密文从一个密钥版本迁移到另一个密钥，无需客户端解密。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/re-encrypt \
  -d '{
    "source_key_id":"order-key",
    "dest_key_id":"order-key-v2",
    "ciphertext":"AAAA..."
  }'
```

### 7.6 获取公钥

```bash
curl "http://127.0.0.1:8200/api/v1/keys/public-key?key_id=signing-key"
# 返回 {"public_key":"...","version":1}
```

---

## 8. 认证与授权

### 8.1 认证方式

#### AppRole（服务间）

静态 Token，适合服务间调用：

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "order-service",
        "token": "secure-random-token",
        "allowed_keys": ["order-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

调用时在 header 中携带：

```bash
curl -H "Authorization: Bearer secure-random-token" http://127.0.0.1:8200/api/v1/...
```

#### JWT（用户身份）

支持 RS256/384/512、ES256/384/512、HS256/384/512、SM2 算法，防算法混淆攻击。

```json
{
  "auth": {
    "jwt": {
      "signing_method": "RS256",
      "verifying_key_path": "/etc/yvonne/keys/jwt-pub.pem",
      "issuer": "your-issuer",
      "audience": ["yvonne-clients"]
    }
  }
}
```

#### Kubernetes ServiceAccount

集群内 Pod 使用 SA JWT 自动认证：

```json
{
  "auth": {
    "k8s": {
      "enabled": true,
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "audience": ["yvonne-kms"],
      "jwks_url": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
      "role_mapping": {
        "default/order-app": {
          "role_id": "order-app",
          "allowed_keys": ["order-*"],
          "allowed_actions": ["encrypt", "decrypt"]
        }
      }
    }
  }
}
```

### 8.2 RBAC 权限模型

#### Policy 字段

| 字段 | 说明 |
|---|---|
| `RoleID` | 角色 ID |
| `AllowedKeys` | 允许访问的密钥（支持 `*` 通配符 + 前缀匹配） |
| `AllowedActions` | 允许的操作（如 `Encrypt`、`Decrypt`、`Sign`、`*`） |
| `TenantID` | 租户 ID（v1.3.1，多租户隔离） |

#### 资源级授权

每次请求都会校验 body 中的 `key_id` 是否匹配 `AllowedKeys`，默认拒绝。

```json
{
  "role_id": "order-service",
  "allowed_keys": ["order-*", "payment-*"],
  "allowed_actions": ["encrypt", "decrypt", "generate-data-key"]
}
```

### 8.3 mTLS 客户端证书

除了 Token 认证，Yvonne 还支持 mTLS 双向证书认证。在 `server.tls` 中配置 `client_ca_file` 即可启用。

---

## 9. 多租户隔离

v1.3.1 引入多租户隔离，通过 keyID 前缀策略实现租户间密钥隔离。

### 9.1 启用多租户

```json
{
  "multi_tenant": {"enabled": true}
}
```

### 9.2 租户 ID 绑定

在 AppRole 中配置 `tenant_id`：

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "tenant-a-app",
        "token": "...",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-a"
      }
    ]
  }
}
```

### 9.3 密钥隔离机制

- 租户 A 创建密钥 `order-key` → 实际存储为 `tenant-a:order-key`
- 租户 B 创建密钥 `order-key` → 实际存储为 `tenant-b:order-key`
- 租户 A 无法访问 `tenant-b:order-key`，反之亦然

### 9.4 向后兼容

`multi_tenant.enabled=false`（默认）时，行为与单租户完全一致。已有的 `key_id` 不加前缀。

---

## 10. MFA 与 Quorum 审批

### 10.1 MFA TOTP

v1.3 引入 RFC 6238 TOTP，对敏感操作强制二次确认。

#### 启用 MFA

```json
{
  "mfa": {
    "enabled": true,
    "issuer": "Yvonne KMS",
    "window_seconds": 30,
    "sensitive_operations": ["ShredKey", "EmergencySeal", "ExportKey", "SoftDeleteKey"]
  }
}
```

#### 设置 MFA

```bash
curl -X POST http://127.0.0.1:8200/api/v1/auth/mfa/setup \
  -H 'Authorization: Bearer <token>' \
  -d '{"role_id":"admin"}'
# 返回 {"secret":"...","uri":"otpauth://totp/..."}
```

用 Google Authenticator / 1Password 扫描 `uri` 中的 QR code。

#### 验证并启用

```bash
curl -X POST http://127.0.0.1:8200/api/v1/auth/mfa/verify \
  -H 'Authorization: Bearer <token>' \
  -d '{"role_id":"admin","code":"123456"}'
```

#### 敏感操作携带 MFA

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred \
  -H 'Authorization: Bearer <token>' \
  -H 'X-MFA-Code: 123456'
```

容差 ±30s，防重放。

### 10.2 Quorum 审批

K-of-N 审批工作流，适合高敏感操作。

#### 创建审批工单

```bash
curl -X POST http://127.0.0.1:8200/api/v1/approvals \
  -H 'Authorization: Bearer <token>' \
  -d '{
    "operation":"ShredKey",
    "key_id":"order-key",
    "required":2,
    "ttl_hours":24
  }'
# 返回 {"id":"ticket-xxx","status":"pending"}
```

#### 查询与审批

```bash
# 列出 pending
curl http://127.0.0.1:8200/api/v1/approvals \
  -H 'Authorization: Bearer <token>'

# 批准
curl -X POST http://127.0.0.1:8200/api/v1/approvals/approve \
  -H 'Authorization: Bearer <token>' \
  -d '{"id":"ticket-xxx"}'

# 拒绝
curl -X POST http://127.0.0.1:8200/api/v1/approvals/reject \
  -H 'Authorization: Bearer <token>' \
  -d '{"id":"ticket-xxx"}'
```

#### 状态机

```
pending → approved (达到 K 票)
       → rejected (任一拒绝)
       → expired (TTL 过期)
```

特性：防自批准（创建者不能批准自己的工单）、幂等（重复批准无效）、过期自动清理。

### 10.3 携带审批执行操作

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Approval-Ticket-ID: ticket-xxx'
```

---

## 11. 审计日志

### 11.1 哈希链审计

每次密钥操作生成一条审计记录，记录间通过 HMAC-SHA256（或 HMAC-SM3）形成哈希链：

```
entry_1.signature = HMAC(key, entry_1.payload || prev_signature)
entry_2.signature = HMAC(key, entry_2.payload || entry_1.signature)
...
```

篡改任意一条记录，后续所有 signature 验证失败。

### 11.2 双写策略

- **文件轮转**：按天切分，保留 `retention_days`（默认 180 天）
- **Syslog 双写**：异步发送到 syslog（tag=`yvonne-kms`），适合 SIEM 接入

### 11.3 审计记录字段

```json
{
  "trace_id": "uuid",
  "timestamp": "2026-07-01T09:00:00Z",
  "client_ip": "10.0.0.1",
  "actor": "admin",
  "resource": "order-key",
  "action": "Encrypt",
  "result": "success",
  "status": "ok"
}
```

### 11.4 查询审计

```bash
curl -X POST http://127.0.0.1:8200/api/v1/audit/query \
  -H 'Authorization: Bearer <token-with-AuditQuery-action>' \
  -d '{"limit":100,"action":"Encrypt"}'
```

需要 `AuditQuery` 权限。

### 11.5 验证链完整性

```bash
yvonne audit verify --dir /var/log/yvonne
```

---

## 12. 可观测性

### 12.1 OpenTelemetry Tracing

```json
{
  "observability": {
    "tracing": {
      "enabled": true,
      "endpoint": "otel-collector:4317",
      "service_name": "yvonne-kms"
    }
  }
}
```

- OTLP gRPC exporter
- otelhttp 自动 instrumentation
- TraceID 自动传播到审计日志

### 12.2 Prometheus Metrics

```bash
curl http://127.0.0.1:8200/metrics
```

指标包含：请求量、延迟分位数、失败率、密钥数、Sealed 状态等。

> Dev 模式仅允许 loopback 访问 metrics；Cluster 模式需要 `Metrics` action 权限。

### 12.3 Webhook 告警

```json
{
  "observability": {
    "alerting": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/...",
      "high_risk_operations": ["ShredKey", "EmergencySeal", "QuorumReject"]
    }
  }
}
```

自动检测 Slack / 钉钉 / PagerDuty 格式，高危操作触发告警。

### 12.4 配置热更新

```bash
kill -HUP <yvonne-pid>
```

热更新 `logging`、`audit`、`observability` 配置，无需重启。

---

## 13. Web 控制台

### 13.1 访问

浏览器打开 `http://<admin-bind>:8250`，输入 Bearer Token 登录。

### 13.2 功能页面

| 页面 | 功能 |
|---|---|
| Dashboard | 密钥数、Vault 状态、Sealed 状态 |
| Keys | 密钥列表、刷新 |
| Crypto | 在线加密/解密测试 |
| Audit | 审计日志查看（需 audit query 权限） |
| MFA & Quorum | MFA/Quorum 管理入口（API 调用） |

### 13.3 安全策略

- 严格 CSP：`script-src 'self'`（无 CDN、无内联脚本、无 `unsafe-eval`）
- 纯原生 JS（无 Vue/Tailwind 等框架依赖）
- 静态资源通过 `go:embed` 内嵌到二进制

### 13.4 Admin REST API

Web 控制台后端的 REST API 也可独立调用：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/admin/api/dashboard` | 仪表盘数据 |
| GET | `/admin/api/keys` | 密钥列表 |
| POST | `/admin/api/crypto/encrypt` | 加密（转发到 V1Router） |
| POST | `/admin/api/crypto/decrypt` | 解密（转发到 V1Router） |
| GET | `/admin/api/audit?limit=N` | 审计日志 |

---

## 14. SDK 使用指南

Yvonne 提供三种语言 SDK，均内置重试、熔断、trace_id 透传。

### 14.1 Go SDK

```go
package main

import (
    "context"
    "fmt"
    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.NewWithOpts(
        "http://127.0.0.1:8200",
        "your-token",
        yvonne.WithRetry(yvonne.RetryConfig{
            MaxRetries: 3,
            InitialBackoff: 100 * time.Millisecond,
        }),
        yvonne.WithCircuitBreaker(yvonne.CircuitBreaker{
            Threshold: 5,
            ResetTimeout: 60 * time.Second,
        }),
        yvonne.WithTraceIDHeader("X-Request-ID"),
    )

    // 加密
    resp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID:     "order-key",
        Plaintext: []byte("hello"),
    })
    if err != nil {
        panic(err)
    }
    fmt.Println("ciphertext:", resp.Ciphertext)
}
```

### 14.2 Python SDK

```python
from yvonne import YvonneClient

client = YvonneClient(
    "http://127.0.0.1:8200",
    token="your-token",
    max_retries=3,
    retry_backoff=0.1,
    circuit_breaker_threshold=5,
    trace_id_header="X-Request-ID",
)

# 加密
resp = client.encrypt("order-key", b"hello")
print(resp["ciphertext"])

# 解密
dec = client.decrypt("order-key", resp["ciphertext"])
print(dec["plaintext"])
```

### 14.3 Java SDK

```java
import io.yvonne.kms.YvonneClient;
import io.yvonne.kms.RetryConfig;
import io.yvonne.kms.CircuitBreaker;

YvonneClient client = YvonneClient.builder()
    .baseUrl("http://127.0.0.1:8200")
    .token("your-token")
    .timeout(Duration.ofSeconds(30))
    .retry(RetryConfig.defaultConfig())
    .circuitBreaker(CircuitBreaker.defaultBreaker())
    .traceIdHeader("X-Request-ID")
    .build();

JsonObject enc = client.encrypt("order-key", "hello".getBytes());
String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();
```

### 14.4 SDK 通用特性

| 特性 | 说明 |
|---|---|
| 重试 | 指数退避 + jitter，仅对幂等/网络错误重试 |
| 熔断 | closed → open（连续失败 N 次）→ half-open（恢复后试探） |
| trace_id | 自动生成 UUID 注入 header，便于跨服务追踪 |
| 超时 | 默认 30s，可配置 |

---

## 15. 部署指南

### 15.1 单机部署

```bash
./bin/yvonne server --config /etc/yvonne/config.json
```

适合小规模测试或单节点生产（配合 `local_pki` 解封）。

### 15.2 集群部署

推荐 3 节点集群 + PostgreSQL 主从：

```
Node 1 ─┐
Node 2 ─┼── PostgreSQL (primary + replica)
Node 3 ─┘
```

所有节点共享同一 PostgreSQL，通过 Advisory Lock 选主执行后台任务（如自动轮转）。

### 15.3 反向代理 + mTLS

Yvonne 设计为内网服务，生产环境应通过 Nginx/Envoy + mTLS 暴露：

```nginx
server {
    listen 443 ssl;
    server_name kms.internal;

    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    ssl_client_certificate /etc/nginx/client-ca.pem;
    ssl_verify_client on;

    location / {
        proxy_pass http://127.0.0.1:8200;
    }
}
```

### 15.4 Kubernetes 部署

详见 [docs/deployment.md](../deployment.md)，推荐使用 StatefulSet + PVC 持久化审计日志。

### 15.5 滚动升级

1. 滚动升级一个节点
2. 验证 `/api/v1/sys/health` 返回 unsealed
3. 继续其他节点

升级指南详见 [docs/upgrade-guide.md](../upgrade-guide.md)。

### 15.6 备份恢复

- **CMK 冷备份**：`yvonne init --wrapped-out /mnt/usb/cmk-backup.bin` + Shamir 分片
- **审计日志备份**：每日 cron 备份 `/var/log/yvonne/audit-*.log`
- **PostgreSQL 备份**：标准 PG 备份策略

---

## 16. 国密合规

### 16.1 启用国密

编译时加 `-tags gmsm`，配置：

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  }
}
```

### 16.2 国密全栈

| 层 | 算法 |
|---|---|
| 信封加密 | SM4-GCM |
| 哈希链审计 | HMAC-SM3 |
| 非对称签名 | SM2 |
| JWT 签名 | SM2 |
| TLS | RFC 8998（SM2 双证书 + SM4/SM3） |

### 16.3 严格模式

`crypto.strict: true` 时：
- 禁用 AES/RSA/ECDSA
- 仅允许 SM2/SM3/SM4
- 适合国密二级及以上合规场景

### 16.4 密评二级对照

详见 [docs/compliance/self-assessment-level2.md](../compliance/self-assessment-level2.md)，24 项逐项评估。

---

## 17. HSM 集成

### 17.1 PKCS#11

```bash
go build -tags hsm -o bin/yvonne-hsm ./cmd/yvonne
```

配置：

```json
{
  "unseal": {
    "type": "hsm",
    "hsm_backend": "pkcs11",
    "hsm_key_id": "yvonne-cmk"
  }
}
```

CMK 永不离开 HSM 芯片，所有加解密操作在 HSM 内部完成。

### 17.2 SoftHSM（测试）

CI 使用 SoftHSM 模拟硬件 HSM，详见 [docs/pkcs11-hsm.md](../pkcs11-hsm.md)。

### 17.3 KEK 抽象

Yvonne 提供统一的 KEK 抽象（`softwareKEK` / `hsmKEK`），业务代码无需感知 HSM 是否启用。

---

## 18. 故障排查

### 18.1 常见问题

#### 服务启动失败

```
error: cluster mode requires storage.type='postgres'
```

→ 检查配置文件 `mode` 字段，或使用 `dev` 模式。

#### Vault 处于 sealed 状态

```
{"ok":false,"error":"kms is sealed"}
```

→ 提交 Shamir 分片解封：

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/unseal \
  -d '{"shares":["base64-share-1","base64-share-2","base64-share-3"]}'
```

#### 401 authentication required

→ 检查 `Authorization: Bearer <token>` header 是否正确。

#### 403 action not allowed

→ 检查 Policy 的 `AllowedActions` 是否包含当前操作。`*` 是通配符。

#### Web 控制台白板

→ 检查浏览器 console。可能是 CSP 阻断、embed 缓存未刷新。

```bash
go clean -cache  # 清理 Go 编译缓存
go build -o bin/yvonne ./cmd/yvonne  # 重新编译
```

### 18.2 日志位置

- 应用日志：stdout（JSON 格式）
- 审计日志：`audit.dir` 配置的目录
- Syslog：`/var/log/system.log`（macOS）或 `/var/log/syslog`（Linux）

### 18.3 健康检查

```bash
curl http://127.0.0.1:8200/api/v1/sys/health | jq .
# {"ok":true,"data":{"sealed":false,"state":"unsealed","status":"alive"}}
```

### 18.4 紧急封印

如怀疑密钥泄露，立即紧急封印：

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/panic \
  -H 'Authorization: Bearer <admin-token>'
```

封印后所有密钥从内存擦除，需手动重启 + Shamir 解封才能恢复。

### 18.5 调试模式

```bash
YVONNE_LOG_LEVEL=debug ./bin/yvonne dev
```

### 18.6 获取帮助

- GitHub Issues: https://github.com/zealot00/Yvonne/issues
- 文档：[docs/](../)

---

## 19. 附录

### 18.1 API 端点速查

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/sys/health` | 健康检查 |
| POST | `/api/v1/sys/unseal` | 提交 Shamir 分片 |
| POST | `/api/v1/sys/panic` | 紧急封印 |
| POST | `/api/v1/keys` | 创建对称密钥 |
| POST | `/api/v1/keys/asymmetric` | 创建非对称密钥 |
| GET | `/api/v1/keys/transit-pub` | BYOK 传输公钥 |
| POST | `/api/v1/keys/import` | BYOK 导入 |
| POST | `/api/v1/keys/{id}/rotate` | 轮转 |
| DELETE | `/api/v1/keys/{id}/shred` | 物理销毁 |
| PATCH | `/api/v1/keys/{id}/soft-delete` | 软删除 |
| POST | `/api/v1/keys/{id}/restore` | 恢复 |
| POST | `/api/v1/keys/{id}/generate-data-key` | GDK |
| POST | `/api/v1/keys/gdk-no-plaintext` | GDK（仅密文） |
| GET | `/api/v1/keys/public-key` | 获取公钥 |
| POST | `/api/v1/encrypt` | 信封加密 |
| POST | `/api/v1/decrypt` | 信封解密 |
| POST | `/api/v1/sign` | 签名 |
| POST | `/api/v1/verify` | 验签 |
| POST | `/api/v1/mac/generate` | HMAC 生成 |
| POST | `/api/v1/mac/verify` | HMAC 验证 |
| POST | `/api/v1/re-encrypt` | 重加密 |
| POST | `/api/v1/auth/mfa/setup` | MFA 设置 |
| POST | `/api/v1/auth/mfa/verify` | MFA 验证 |
| POST | `/api/v1/auth/mfa/disable` | MFA 禁用 |
| POST | `/api/v1/approvals` | 创建审批 |
| GET | `/api/v1/approvals` | 列出/查询审批 |
| POST | `/api/v1/approvals/approve` | 批准 |
| POST | `/api/v1/approvals/reject` | 拒绝 |
| POST | `/api/v1/audit/query` | 查询审计 |
| GET | `/metrics` | Prometheus 指标 |

### 18.2 错误码

| HTTP | 含义 | 说明 |
|---|---|---|
| 200 | 成功 | - |
| 400 | 请求错误 | 参数缺失/格式错误 |
| 401 | 未认证 | Token 缺失或无效 |
| 403 | 无权限 | Action 或 KeyID 不在 Policy 中 |
| 404 | 未找到 | 密钥不存在 |
| 429 | 限流 | 超过速率限制 |
| 500 | 内部错误 | 服务端异常 |
| 503 | 不可用 | Sealed 或 EmergencySealed |

### 18.3 安全检查清单

每次代码变更后强制运行：

```bash
bash scripts/security-check.sh  # 12 项安全检查
gosec ./...                      # 0 issues
govulncheck ./...                # 0 vulnerabilities
```

### 18.4 Release Gate

每次发布前必须运行：

```bash
python3 scripts/release_gate_e2e.py
# 必须 37/37 通过（3 项 dev 模式跳过）
```

### 18.5 相关文档

- [产品演进路线图](../roadmap.md)
- [交付物清单](../deliverables.md)
- [国密合规指南](../gmsm-compliance.md)
- [密评二级自评报告](../compliance/self-assessment-level2.md)
- [v1.3 合规功能指南](../v1.3-compliance.md)
- [部署指南](../deployment.md)
- [升级指南](../upgrade-guide.md)
- [gRPC API 指南](../grpc-api.md)
- [MCP API 指南](../mcp-api.md)
- [PKCS#11 HSM 指南](../pkcs11-hsm.md)
- [AES→SM4 迁移指南](../aes-to-sm4-migration.md)
- [安全策略](../../SECURITY.md)
- [Changelog](../../CHANGELOG.md)

### 18.6 许可证

Apache License 2.0。详见 [LICENSE](../../LICENSE)。

### 18.7 合规免责声明

> 本项目未通过 FIPS 140-3 或 PCI-DSS 正式审计。对于强监管环境（金融、医疗、政府），需完成第三方审计 + FIPS HSM 集成 + 合规认证后方可生产部署。

---

> 反馈与建议：[GitHub Issues](https://github.com/zealot00/Yvonne/issues)
