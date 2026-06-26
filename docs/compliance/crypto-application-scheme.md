# Yvonne KMS 密码应用方案

> 版本：1.0 | 日期：2026-06-26 | 适用：等保二级/三级 密评材料

## 1. 系统概述

### 1.1 系统名称

Yvonne KMS（密钥管理系统）

### 1.2 系统功能

Yvonne KMS 提供集中式密钥管理服务，包括：

- 对称密钥（AES-256-GCM / SM4-GCM）的创建、轮转、软删除、物理销毁
- 非对称密钥（RSA-4096 / ECDSA P-256 / SM2）的生成与存储
- 信封加密（Envelope Encryption）：CMK 保护 DEK，DEK 加密业务数据
- 版本化自路由密文：密文头部含版本号，自动路由到对应 DEK
- 审计日志：HMAC 链式签名，防篡改，支持文件轮转 + Syslog 双写
- 密钥封印/解封：Shamir 门限分片（N 分片 K 门限）
- 紧急封印：一键擦除所有内存密钥

### 1.3 密码算法清单

| 算法 | 用途 | 标准 | 密钥长度 |
|---|---|---|---|
| AES-256-GCM | DEK 加密（标准模式） | NIST SP 800-38D | 256 位 |
| SM4-GCM | DEK 加密（国密模式） | GB/T 32907 | 128 位 |
| SHA-256 | 审计链 HMAC（标准模式） | NIST FIPS 180-4 | - |
| SM3 | 审计链 HMAC（国密模式） | GB/T 32905 | - |
| RSA-4096 | BYOK 传输密钥 | PKCS#1 v2.2 | 4096 位 |
| SM2 | 公钥加密/签名（国密模式） | GB/T 32918 | 256 位 |
| Shamir | Master Key 分片 | GF(2^8) | - |

### 1.4 密码模块边界

- 软件模块：Go 进程内 `memguard.SecureBuffer`，mlock 锁定物理内存
- 硬件模块（可选）：PKCS#11 HSM，CMK 不离开芯片

## 2. 密钥层次结构

```
┌─────────────────────────────────────────────┐
│  Master Key (CMK)                           │
│  256 位 AES-256 / SM4                       │
│  存储方式：Shamir 分片 或 HSM 不可导出       │
│  用途：加密 DEK（KEK 层）                    │
├─────────────────────────────────────────────┤
│  DEK (Data Encryption Key)                  │
│  256 位 AES-256 / 128 位 SM4                │
│  存储方式：CMK 加密后存 DB                   │
│  用途：加密业务数据                          │
├─────────────────────────────────────────────┤
│  业务密文                                    │
│  格式：[4B版本][12B Nonce][密文+AuthTag]     │
│  存储：由业务系统保存，KMS 不存储             │
└─────────────────────────────────────────────┘
```

## 3. 密钥生命周期

### 3.1 密钥状态机

```
                  CreateKey
                      │
                      ▼
                 ┌─────────┐
                 │ Active  │ ← 加密 + 解密
                 └────┬────┘
            RotateKey │
                      ▼
              ┌───────────────┐
              │ Deactivated   │ ← 仅解密（向后兼容）
              └──┬───────┬────┘
       SoftDelete│       │ShredKey
                 ▼       ▼
        ┌────────────┐ ┌─────────┐
        │SoftDeleted │ │Destroyed│ ← 不可恢复
        └─────┬──────┘ └─────────┘
        Restore│
              ▼
        ┌───────────────┐
        │ Deactivated   │
        └───────────────┘
```

### 3.2 密钥操作对照

| 状态 | 加密 | 解密 | 轮转 | 软删 | 粉碎 | 恢复 |
|---|---|---|---|---|---|---|
| Active | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Deactivated | ❌ | ✅ | - | ✅ | ✅ | - |
| SoftDeleted | ❌ | ✅ | - | - | ✅ | ✅ |
| Destroyed | ❌ | ❌ | - | - | - | - |

### 3.3 密钥轮转

- 手动轮转：`POST /api/v1/keys/{id}/rotate`
- 自动轮转：`RotationDaemon` 每小时扫描 `NextRotationAt` 过期的密钥
- 轮转后旧版本 → Deactivated，新版本 → Active
- 旧密文仍可解密（向后兼容），新加密用新版本

### 3.4 密钥销毁

- 软删除（SoftDelete）：标记 SoftDeleted，90 天 TTL 后 reaper 物理粉碎
- 物理粉碎（ShredKey）：`clear()` 内存 + `DELETE` DB 行 + `clear` 缓存
- 粉碎后密文永久不可解密（crypto-shredding）

## 4. 访问控制

### 4.1 角色模型

| 角色 | 权限 | 认证方式 |
|---|---|---|
| 管理员 | 创建/轮转/粉碎密钥 | AppRole Token / JWT / K8s SA |
| 审计员 | 查询审计日志 | AppRole Token / JWT |
| 业务服务 | 加密/解密（授权的 key） | AppRole Token / JWT / K8s SA |
| 紧急操作员 | Emergency Seal | Admin Token |

### 4.2 资源级授权

- Policy 含 `AllowedKeys`（支持通配符 `order-*` / `*`）和 `AllowedActions`
- 加密/解密请求的 `key_id` 必须在 `AllowedKeys` 范围内
- 默认拒绝：无 Policy 或 Policy 不匹配 → 403

## 5. 审计与追溯

### 5.1 审计日志格式

```json
{
  "trace_id": "a1b2c3d4",
  "timestamp": "2026-06-26T10:00:00Z",
  "actor": "order-service",
  "resource": "order-key",
  "action": "Encrypt",
  "result": "success"
}
```

### 5.2 审计链完整性

- 每条日志用 HMAC-SHA256（标准）或 HMAC-SM3（国密）签名
- 签名包含前一条日志的签名（链式）
- 第一条日志锚定为 `SHA256(AuditKey)`
- `audit-verify` 命令可离线验证链完整性

### 5.3 审计日志留存

- 文件轮转：按日期切分，保留 180 天（可配置）
- Syslog 双写：异步发送到集中日志服务器
- 查询接口：`POST /api/v1/audit/query`（需 AuditQuery 权限）

## 6. 传输安全

### 6.1 TLS/mTLS

- HTTPS：TLS 1.2/1.3，服务端证书
- mTLS：`client_auth: "require"` 强制客户端证书
- Admin UI：默认 127.0.0.1，需反向代理 + mTLS 暴露

### 6.2 gRPC 传输

- gRPC over HTTP/2 + TLS
- 复用 HTTP 的 TLS 配置（含 mTLS）

## 7. 备份与恢复

### 7.1 Master Key 备份

- Shamir 分片：N 份分片（默认 5 份），K 门限（默认 3 份）
- 分片分发到不同 USB 介质，不同管理员保管
- 每个分片含 HMAC 完整性校验

### 7.2 恢复流程

1. 收集 K 份分片
2. `POST /api/v1/sys/unseal` 重组 Master Key
3. 系统进入 Unsealed 状态

### 7.3 紧急封印

- `POST /api/v1/sys/panic`（需 Admin Token + confirm=true）
- 立即擦除 Master Key + DEK 缓存 + 收集的分片
- 不可逆，需重启进程 + Shamir 解封才能恢复

## 8. 密码应用合规对照

### GB/T 39786-2021 第二级对照

| 要求项 | 实现方式 | 合规 |
|---|---|---|
| SM4 对称加密 | SM4-GCM（国密模式） | ✅ |
| SM3 密码杂凑 | SM3 + HMAC-SM3（国密模式） | ✅ |
| SM2 公钥密码 | SM2 加密/签名（国密模式） | ✅ |
| 密钥生成 | CSPRNG + SecureBuffer | ✅ |
| 密钥存储 | CMK 加密 + Shamir 分片 | ✅ |
| 密钥分发 | 版本化密文 + KEK 包封 | ✅ |
| 密钥使用 | RBAC + 资源级授权 | ✅ |
| 密钥更新 | 自动轮转 + 手动轮转 | ✅ |
| 密钥销毁 | Wipe + ShredKey + crypto-shredding | ✅ |
| 密钥备份恢复 | Shamir 冷存储 | ✅ |
| 审计完整性 | HMAC 链式签名 | ✅ |
| 身份认证 | JWT SM2 签名（国密模式） | ⚠️ v1.1 |
| 通信安全 | TLS 1.3 + mTLS | ✅ |
| 密码模块隔离 | 进程隔离 + SecureBuffer | ✅ |

## 9. 部署架构

### 9.1 Dev 模式

```
单进程 → MemoryStore → 自动 Unseal → 127.0.0.1
```

### 9.2 Cluster 模式

```
3× Yvonne Pod → PostgreSQL（HA）
     │              │
     │   ┌──────────┘
     │   │
     ▼   ▼
  pg_advisory_lock（选主）
  LISTEN/NOTIFY（缓存失效）
```

### 9.3 HSM 模式

```
Yvonne → PKCS#11 → HSM 芯片（CMK 不可导出）
```
