# 等保/密评检查点映射表

> 适用：Yvonne KMS v1.0+ | 日期：2026-06-26
> 对照标准：GB/T 39786-2021（信息系统密码应用基本要求）第二级

## 1. 密码算法合规性

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 对称加密算法 | SM4（GB/T 32907） | SM4-GCM（`-tags gmsm`） | ✅ | `internal/crypto/suite_gmsm.go` |
| 密码杂凑算法 | SM3（GB/T 32905） | SM3 + HMAC-SM3 | ✅ | `internal/crypto/suite_gmsm.go` |
| 公钥密码算法 | SM2（GB/T 32918） | SM2 加密/签名 | ✅ | `internal/crypto/sm2.go` |
| 随机数生成 | 国密 CSPRNG | `crypto/rand`（系统熵） | ⚠️ | `internal/memguard/random.go`（系统 CSPRNG，非国密认证 RNG） |
| 算法禁用 | 禁用非国密算法（严格模式） | `crypto.suite: "gmsm"` 切换 | ⚠️ | 当前仅切换非禁用，需增加 `strict` 模式 |

## 2. 密钥管理

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 密钥生成 | 使用批准的随机数发生器 | CSPRNG + SecureBuffer | ✅ | `memguard.NewSecureBufferFromRandom` |
| 密钥存储 | 密钥加密存储，明文不外泄 | CMK 加密 DEK，SecureBuffer 保护 | ✅ | `internal/seal/kek.go` |
| 密钥分发 | 密钥传输加密保护 | 版本化密文 + KEK 包封 | ✅ | `internal/crypto/versioned_encrypt.go` |
| 密钥使用 | 按需使用，最小权限 | RBAC + AllowedKeys 白名单 | ✅ | `internal/auth/auth.go` |
| 密钥更新 | 定期轮转 | 自动轮转 + 手动轮转 | ✅ | `internal/lifecycle/daemon.go` |
| 密钥销毁 | 安全销毁，不可恢复 | Wipe + ShredKey + crypto-shredding | ✅ | `internal/lifecycle/manager.go` |
| 密钥备份恢复 | 加密备份，分片存储 | Shamir 分片 + 冷存储 | ✅ | `internal/seal/shamir.go` |
| 密钥归档 | 归档密钥安全保存 | SoftDelete 90 天 + 审计日志 | ✅ | `internal/lifecycle/manager.go` |

## 3. 密码应用方案

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 密码应用方案文档 | 有完整方案 | `docs/compliance/crypto-application-scheme.md` | ✅ | 本目录 |
| 密钥层次结构 | CMK → DEK → 业务密文 | 三层信封加密 | ✅ | 密码应用方案 §2 |
| 密钥生命周期管理 | 有管理制度 | `docs/compliance/key-lifecycle-management.md` | ✅ | 本目录 |
| 角色职责分离 | 管理员/审计员/业务分离 | `docs/compliance/role-separation-matrix.md` | ✅ | 本目录 |

## 4. 网络与通信安全

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 通信加密 | TLS 1.2+ | TLS 1.2/1.3 | ✅ | `internal/config/tlsconfig.go` |
| 身份认证 | 双向证书认证（mTLS） | `client_auth: "require"` | ✅ | `internal/config/tlsconfig.go` |
| 密码模块隔离 | 进程隔离 | SecureBuffer + mlock | ✅ | `internal/memguard/secure_buffer.go` |

## 5. 设备与计算安全

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 密码模块 | 软件/硬件模块 | 软件模块（SecureBuffer） | ✅ | 二级允许软件模块 |
| HSM 支持 | 可选硬件模块 | CryptoBackend 接口 + Mock | ⚠️ | PKCS#11 未实现（v1.2） |
| 密钥不出模块 | CMK 不离开进程/HSM | softwareKEK / hsmKEK | ✅ | `internal/seal/kek.go` |

## 6. 应用与数据安全

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 数据加密 | 敏感数据加密存储 | 信封加密 + 版本化密文 | ✅ | `internal/crypto/versioned_encrypt.go` |
| 数据完整性 | HMAC 校验 | GCM AuthTag + 审计链 HMAC | ✅ | `internal/crypto/gcm.go` |
| 审计日志 | 完整性保护 + 不可篡改 | HMAC 链式签名 | ✅ | `internal/audit/chain.go` |
| 审计日志留存 | ≥180 天 | 文件轮转 + 180 天留存 | ✅ | `internal/audit/logger.go` |
| 审计日志查询 | 认证 + 授权 | AuditQuery 权限 | ✅ | `internal/api/handler_audit.go` |

## 7. 密钥管理实体

| 检查项 | 标准要求 | Yvonne 实现 | 合规 | 证据 |
|---|---|---|---|---|
| 密钥管理实体独立性 | KMS 独立于业务系统 | 独立进程 + API | ✅ | 架构设计 |
| 密钥管理操作审计 | 全操作记录 | 所有操作审计 | ✅ | `internal/service/core.go` |
| 密钥管理权限控制 | RBAC + 资源级授权 | Policy + AllowedKeys | ✅ | `internal/auth/auth.go` |

## 8. 合规风险评估

### 8.1 已满足（二级要求）

| 领域 | 状态 |
|---|---|
| 密码算法（SM2/SM3/SM4） | ✅ 已实现（`-tags gmsm`） |
| 密钥全生命周期 | ✅ 完整 |
| 信封加密 | ✅ 三层结构 |
| 审计完整性 | ✅ HMAC 链 |
| 通信安全 | ✅ TLS 1.3 + mTLS |
| 访问控制 | ✅ RBAC + 资源级 |
| 密码应用方案文档 | ✅ 完整 |

### 8.2 待改进

| 领域 | 缺口 | 建议 | 优先级 |
|---|---|---|---|
| 审计链 HMAC-SM3 | gmsm 模式仍用 SHA-256 | v1.1 M2 切换 | P0 |
| JWT SM2 签名 | JWT 仅 RS/ES/HS | v1.1 M4 实现 | P1 |
| 密文算法标识 | 密文无算法字段 | v1.1 加 `alg_id` | P1 |
| 国密认证 RNG | 系统 CSPRNG 非 GM/T 认证 | 硬件 RNG / 国密库 | P2 |
| PKCS#11 HSM | 仅 Mock | v1.2 实现 | P2 |
| 严格国密模式 | 可切换但不禁用 AES | 增加 `strict` 模式 | P1 |

### 8.3 不适用

| 领域 | 原因 |
|---|---|
| 物理安全 | 二级不要求硬件模块 |
| FIPS 140-3 | 非联邦场景 |
| 密码模块三级认证 | 二级允许软件模块 |

## 9. 测评准备清单

- [x] 密码应用方案文档
- [x] 密钥生命周期管理制度
- [x] 角色职责分离矩阵
- [x] 审计日志样例与验证流程
- [x] 应急响应与演练手册
- [x] 等保/密评检查点映射表
- [x] 审计链 HMAC-SM3 接入（v1.1 ✅）
- [x] JWT SM2 签名（v1.1 ✅）
- [x] SM2 公钥密码（v1.1 ✅）
- [x] 密钥算法标识（v1.1 ✅）
- [x] 严格国密模式（v1.1 ✅）
- [x] AES→SM4 迁移指南（v1.1 ✅）
- [ ] 国密认证 CSPRNG（v1.3 硬件 RNG）
- [ ] 第三方测评机构对接
- [ ] 密文算法标识（v1.1）
- [ ] 第三方测评机构对接
