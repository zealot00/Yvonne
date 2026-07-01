# Yvonne KMS 国密合规指南

> 版本：v1.3.0 | 日期：2026-06-30
> 适用标准：GB/T 39786-2021《信息系统密码应用基本要求》第二级

## 一、合规概述

Yvonne KMS 在 `-tags gmsm` 编译模式下，满足 GB/T 39786-2021 第二级密码应用要求：

| 要求项 | 标准条款 | Yvonne 实现 | 合规状态 |
|---|---|---|---|
| 对称加密 | SM4（GB/T 32907） | SM4-GCM | ✅ |
| 密码杂凑 | SM3（GB/T 32905） | SM3 + HMAC-SM3 审计链 | ✅ |
| 公钥密码 | SM2（GB/T 32918） | SM2 加密/签名/验签 | ✅ |
| 随机数 | 国密 CSPRNG | `crypto/rand`（系统熵） | ⚠️ 需接国密认证 RNG |
| 算法禁用 | 严格模式 | `crypto.strict: true` | ✅ |
| 密钥存储 | 加密存储 | CMK 加密 DEK + SecureBuffer | ✅ |
| 密钥销毁 | 物理销毁 | Wipe + Crypto-Shredding | ✅ |
| 审计完整性 | 哈希链 | HMAC-SM3 链 + anchor 文件 | ✅ |

## 二、编译与配置

### 2.1 编译

```bash
# 国密模式编译
go build -tags gmsm -o yvonne ./cmd/yvonne/

# 国密 + HSM
go build -tags gmsm,hsm,pkcs11 -o yvonne ./cmd/yvonne/
```

### 2.2 配置

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  },
  "auth": {
    "jwt": {
      "signing_method": "SM2",
      "verifying_key_path": "/path/to/sm2-pub.pem",
      "issuer": "yvonne-kms"
    }
  },
  "audit": {
    "dir": "/var/log/yvonne",
    "retention_days": 180
  }
}
```

### 2.3 严格国密模式

`crypto.strict: true` 时：
- 仅允许 SM2/SM3/SM4 算法
- 禁用 AES/RSA/ECDSA
- JWT 签名方法必须为 SM2
- 审计链使用 HMAC-SM3

## 三、密码算法清单

### 3.1 对称加密

| 算法 | 模式 | 用途 | 实现 |
|---|---|---|---|
| SM4 | GCM | DEK 加密 + 业务数据加密 | `internal/crypto/suite_gmsm.go` |
| AES-256 | GCM | 兼容模式（非 strict） | `internal/crypto/suite_standard.go` |

### 3.2 密码杂凑

| 算法 | 用途 | 实现 |
|---|---|---|
| SM3 | 审计哈希链 + HMAC | `internal/audit/chain_gmsm.go` |
| HMAC-SM3 | 审计链签名 | `internal/audit/logger.go` |
| SHA-256 | 兼容模式 + TOTP | `internal/crypto/suite_standard.go` |

### 3.3 公钥密码

| 算法 | 用途 | 实现 |
|---|---|---|
| SM2 | 密钥对生成/加密/解密/签名/验签 | `internal/crypto/sm2.go` |
| SM2 JWT | JWT 签名（`-tags gmsm`） | `internal/auth/jwt_sm2.go` |
| RSA-4096 | BYOK 传输密钥 + 兼容模式 | `internal/crypto/asymmetric.go` |

### 3.4 随机数

| 来源 | 用途 | 合规性 |
|---|---|---|
| `crypto/rand` | 密钥生成 + Nonce | ⚠️ 系统 CSPRNG（非国密认证） |
| HSM RNG | HSM 模式下密钥生成 | ✅ 硬件认证 RNG（需 HSM 模块） |

> **密评二级要求**：需使用经国家密码管理局批准的随机数发生器。当前使用系统 CSPRNG，密评时需说明或接入国密认证 RNG 模块。

## 四、密钥层次结构

```
┌─────────────────────────────────────────┐
│  Master Key (CMK) — 32 字节             │
│  存储：Shamir 分片 / Local PKI / HSM    │
│  保护：SecureBuffer + Wipe              │
├─────────────────────────────────────────┤
│  KEK (Key Encryption Key)              │
│  CMK 加密 KEK → 存储于 PG/BoltDB       │
├─────────────────────────────────────────┤
│  DEK (Data Encryption Key) — 32 字节    │
│  KEK 加密 DEK → 版本化密文返回给客户端  │
│  明文 DEK 用完即 Wipe                   │
├─────────────────────────────────────────┤
│  业务密文                               │
│  客户端用 DEK 加密业务数据              │
└─────────────────────────────────────────┘
```

## 五、密评二级对照表

### 第一类：密码算法合规性

| 序号 | 检查项 | 标准要求 | Yvonne 实现 | 证据 | 状态 |
|---|---|---|---|---|---|
| 1.1 | 对称加密算法 | SM4 | SM4-GCM（`-tags gmsm`） | `suite_gmsm.go` | ✅ |
| 1.2 | 密码杂凑算法 | SM3 | SM3 + HMAC-SM3 | `chain_gmsm.go` | ✅ |
| 1.3 | 公钥密码算法 | SM2 | SM2 加密/签名 | `sm2.go` | ✅ |
| 1.4 | 随机数生成 | 国密 CSPRNG | `crypto/rand` | `memguard/entropy.go` | ⚠️ |
| 1.5 | 算法禁用 | 严格模式禁用非国密 | `crypto.strict: true` | `validator.go` | ✅ |

### 第二类：密钥管理

| 序号 | 检查项 | 标准要求 | Yvonne 实现 | 证据 | 状态 |
|---|---|---|---|---|---|
| 2.1 | 密钥生成 | 批准的随机数 | CSPRNG + SecureBuffer | `memguard` | ✅ |
| 2.2 | 密钥存储 | 加密存储 | CMK 加密 DEK | `seal/kek.go` | ✅ |
| 2.3 | 密钥分发 | 传输加密 | 版本化密文 + KEK 包封 | `versioned_encrypt.go` | ✅ |
| 2.4 | 密钥使用 | 最小权限 | RBAC + AllowedKeys | `auth/auth.go` | ✅ |
| 2.5 | 密钥更新 | 定期轮转 | 自动轮转 + 手动轮转 | `lifecycle/daemon.go` | ✅ |
| 2.6 | 密钥销毁 | 安全销毁 | Wipe + ShredKey | `lifecycle/manager.go` | ✅ |
| 2.7 | 密钥备份 | 加密备份 | Shamir 分片 + 冷存储 | `seal/shamir.go` | ✅ |
| 2.8 | 密钥归档 | 安全归档 | SoftDelete 90 天 + 审计 | `lifecycle/manager.go` | ✅ |

### 第三类：密码应用方案

| 序号 | 检查项 | 标准要求 | Yvonne 实现 | 证据 | 状态 |
|---|---|---|---|---|---|
| 3.1 | 密码应用方案文档 | 有完整方案 | `docs/compliance/crypto-application-scheme.md` | 本目录 | ✅ |
| 3.2 | 密钥层次结构 | CMK → DEK → 业务密文 | 三层信封加密 | 密码应用方案 §2 | ✅ |
| 3.3 | 密钥生命周期管理 | 有管理制度 | `docs/compliance/key-lifecycle-management.md` | 本目录 | ✅ |
| 3.4 | 角色职责分离 | 管理/审计/业务分离 | `docs/compliance/role-separation-matrix.md` | 本目录 | ✅ |

### 第四类：网络与通信安全

| 序号 | 检查项 | 标准要求 | Yvonne 实现 | 证据 | 状态 |
|---|---|---|---|---|---|
| 4.1 | 传输加密 | SM4/SM2 传输加密 | TLS + RFC 8998 国密 TLS | `config/tlsconfig_gmsm.go` | ✅ |
| 4.2 | 完整性校验 | HMAC-SM3 | 审计链 HMAC-SM3 | `audit/chain_gmsm.go` | ✅ |
| 4.3 | 身份认证 | SM2 签名 | JWT SM2 + AppRole | `auth/jwt_sm2.go` | ✅ |

### 第五类：审计与追溯

| 序号 | 检查项 | 标准要求 | Yvonne 实现 | 证据 | 状态 |
|---|---|---|---|---|---|
| 5.1 | 审计日志完整性 | 哈希链防篡改 | HMAC-SM3 链 + anchor | `audit/logger.go` | ✅ |
| 5.2 | 审计日志留存 | ≥ 180 天 | 可配置（默认 180） | `audit/file_rotator.go` | ✅ |
| 5.3 | 审计日志查询 | 可查询 | `POST /api/v1/audit/query` | `api/handler_audit.go` | ✅ |
| 5.4 | 日志双写 | 文件 + Syslog | 双写审计器 | `audit/logger.go` | ✅ |

## 六、合规配置示例

### 6.1 完全国密模式

```json
{
  "mode": "cluster",
  "crypto": {"suite": "gmsm", "strict": true},
  "auth": {
    "jwt": {
      "signing_method": "SM2",
      "verifying_key_path": "/etc/yvonne/sm2-pub.pem",
      "issuer": "yvonne-kms"
    }
  },
  "server": {
    "tls": {
      "enabled": true,
      "gm_enabled": true,
      "gm_sign_cert_file": "/etc/yvonne/sm2-sign.pem",
      "gm_sign_key_file": "/etc/yvonne/sm2-sign-key.pem",
      "gm_enc_cert_file": "/etc/yvonne/sm2-enc.pem",
      "gm_enc_key_file": "/etc/yvonne/sm2-enc-key.pem"
    }
  },
  "audit": {"dir": "/var/log/yvonne", "retention_days": 180}
}
```

### 6.2 混合模式（国密 + 兼容）

```json
{
  "crypto": {"suite": "gmsm", "strict": false}
}
```

## 七、待改进项

| 项目 | 当前状态 | 密评要求 | 改进计划 |
|---|---|---|---|
| 国密认证 RNG | 系统 CSPRNG | 国密认证 RNG | v2.0 接入硬件 RNG |
| 密码模块认证 | 软件模块 | 需商密检测中心认证 | 客户自行对接测评机构 |
| 物理防护 | 无 | 密评三级需 HSM | v2.0 HSM 集成 |
