# Yvonne KMS v1.1 国密合规版路线图

> 日期：2026-06-26 | 目标：满足 GB/T 39786-2021 第二级密评要求 | 工期：3-4 周

## 一、合规目标

### 目标密评级别：第二级（增强）

| 级别 | 适用场景 | Yvonne 可达性 |
|---|---|---|
| 第一级（基础） | 一般信息系统 | ✅ v1.0 接近 |
| **第二级**（增强） | 重要信息系统 | ✅ v1.1 目标 |
| 第三级（重要） | 关键基础设施 | ⚠️ 需 HSM（v1.2） |
| 第四级（核心） | 国家核心系统 | ❌ 需硬件模块认证 |

### 第二级核心要求（GB/T 39786-2021）

| 层面 | 要求 | v1.0 状态 | v1.1 目标 |
|---|---|---|---|
| **密码算法** | SM2/SM3/SM4 | SM4/SM3 原语已实现，未接入 | ✅ 端到端接入 |
| **密钥管理** | 生成/存储/使用/销毁全生命周期 | ✅ 已完整 | ✅ 保持 |
| **密码模块** | 软件模块隔离 | ✅ SecureBuffer | ✅ 保持 |
| **随机数** | 国密 CSPRNG | `crypto/rand`（系统熵） | ✅ 可接受（系统 CSPRNG 满足二级） |
| **审计** | HMAC 完整性保护 | HMAC-SHA256 | HMAC-SM3 |
| **身份认证** | 数字签名/证书 | JWT(RSA/ECDSA) | JWT + SM2 签名 |

## 二、当前缺口

| # | 缺口 | 影响 | 工期 |
|---|---|---|---|
| G1 | KEK 层硬编码 AES-256-GCM，未走 CryptoSuite 接口 | 无法用 SM4 加密 DEK | 3 天 |
| G2 | 审计链硬编码 HMAC-SHA256 | 审计完整性非国密 | 1 天 |
| G3 | 配置无 `crypto.suite` 字段 | 无法切换 standard/gmsm | 1 天 |
| G4 | SM2 公钥密码完全缺失 | 无密钥协商/数字签名 | 5 天 |
| G5 | JWT 不支持 SM2 签名 | 身份认证非国密 | 2 天 |
| G6 | KEK 密钥长度硬编码 32 字节（AES-256） | SM4 需 16 字节 | 1 天 |
| G7 | BYOK 传输密钥仅 RSA-4096 | 合规场景需 SM2 传输 | 2 天 |
| G8 | 国密端到端测试缺失 | 无法验证集成正确性 | 2 天 |

**总工期**：约 17 工作日（3.5 周，含测试 + 文档）

## 三、里程碑划分

### M1：配置 + KEK 层接入（3 天）

**目标**：`crypto.suite: "gmsm"` 配置生效，KEK 用 SM4-GCM 加密 DEK。

| 任务 | 文件 | 说明 |
|---|---|---|
| 配置开关 | `config/config.go` | 新增 `CryptoConfig.Suite` 字段（"standard"/"gmsm"） |
| 配置校验 | `config/validator.go` | gmsm 模式要求 `-tags gmsm` 编译 |
| KEK 重构 | `internal/seal/kek.go` | `softwareKEK` 走 `CryptoSuite.Cipher()` 而非硬编码 `EncryptGCM` |
| 密钥长度 | `internal/seal/kek.go` | 按 `Cipher.KeySize()` 动态生成，不再硬编码 32 |
| bootstrap 装配 | `internal/bootstrap/bootstrap.go` | 根据 `crypto.suite` 选择 `NewStandardSuite()` 或 `NewGMSMSuite()` |

**验收**：
- `crypto.suite: "gmsm"` 时 KEK 用 SM4-GCM
- `crypto.suite: "standard"` 时保持 AES-256-GCM（向后兼容）
- 旧密文仍可解密（版本化密文格式算法无关）

### M2：审计链 HMAC-SM3（1 天）

**目标**：gmsm 模式下审计链用 HMAC-SM3 替代 HMAC-SHA256。

| 任务 | 文件 | 说明 |
|---|---|---|
| 审计链重构 | `internal/audit/chain.go` | `NewAuditLogger` 接收 `Hash` 接口，按 suite 选择 SHA-256 或 SM3 |
| bootstrap 注入 | `internal/bootstrap/bootstrap.go` | 传入 `suite.Hash()` 给 audit logger |
| 向后兼容 | `internal/audit/chain.go` | 旧审计链（SHA-256）仍可验证（算法标识在链头） |

**验收**：
- gmsm 模式审计日志用 HMAC-SM3 签名
- `audit-verify` 能验证两种算法的链
- 旧日志（SHA-256）不丢失

### M3：SM2 公钥密码（5 天）

**目标**：实现 SM2 密钥对生成 + 加解密 + 数字签名。

| 任务 | 文件 | 说明 |
|---|---|---|
| SM2 实现 | `internal/crypto/sm2.go`（新） | 基于 `tjfoc/gmsm/sm2`，实现 `Encrypt/Decrypt/Sign/Verify` |
| 非对称密钥支持 | `internal/lifecycle/manager.go` | `CreateAsymmetricKey` 支持 SM2（已有 RSA/ECDSA） |
| BYOK 传输 | `internal/lifecycle/transit.go` | 传输密钥支持 SM2（除 RSA-4096 外新增 SM2-256） |
| 测试 | `internal/crypto/sm2_test.go`（新） | SM2 KAT + 往返 + 签名验证 |

**验收**：
- SM2 密钥对生成 + 加解密往返
- SM2 数字签名 + 验证
- BYOK 支持 SM2 传输密钥

### M4：JWT SM2 签名（2 天）

**目标**：JWT 支持 SM2-SM3 签名算法。

| 任务 | 文件 | 说明 |
|---|---|---|
| 签名方法注册 | `internal/auth/jwt_authenticator.go` | `parseSigningMethod` 新增 `SM2` 分支 |
| 公钥加载 | `internal/auth/jwt_authenticator.go` | SM2 公钥 PEM 加载 |
| 配置 | `config/yvonne_config.go` | `JWTConfig.SigningMethod` 支持 `"SM2"` |
| 测试 | `internal/auth/jwt_sm2_test.go`（新） | SM2 JWT 签发 + 验证往返 |

**验收**：
- JWT `signing_method: "SM2"` 可用
- SM2 签名的 JWT 能被正确验证
- 算法混淆攻击仍被拒绝

### M5：端到端集成 + 测试（2 天）

**目标**：gmsm 模式全链路可用 + 测试覆盖。

| 任务 | 文件 | 说明 |
|---|---|---|
| E2E 测试 | `internal/api/gmsm_e2e_test.go`（新） | gmsm 模式下 CreateKey→Encrypt→Decrypt→Rotate→Shred 全链路 |
| 密评对照测试 | `internal/crypto/gmsm_compliance_test.go`（新） | SM2/SM3/SM4 KAT（GB/T 标准测试向量） |
| 审计链测试 | `internal/audit/gmsm_chain_test.go`（新） | HMAC-SM3 审计链验证 + 篡改检测 |
| 配置测试 | `internal/config/gmsm_config_test.go`（新） | suite 切换 + 向后兼容 |

**验收**：
- `-tags gmsm` 编译全量测试通过
- GB/T 标准测试向量全部通过
- gmsm ↔ standard 套件隔离正确

### M6：文档 + 合规声明（1 天）

**目标**：国密合规文档就绪。

| 任务 | 文件 | 说明 |
|---|---|---|
| 国密合规指南 | `docs/gmsm-compliance.md`（新） | 配置 + 算法 + 密评对照表 |
| 升级指南更新 | `docs/upgrade-guide.md` | v1.0→v1.1 国密切换说明 |
| 配置示例 | `deploy/examples/config-gmsm.json` | 国密模式配置模板 |
| README 更新 | `README.md` | 国密合规声明 |

## 四、不做的内容（v1.1 范围外）

| 项 | 原因 | 后续版本 |
|---|---|---|
| 密评三级（HSM 硬件模块） | 需 PKCS#11 真实硬件联调 | v1.2 |
| 国密认证 CSPRNG | 需商密检测中心认证的 RNG 模块 | v1.3（或用硬件 RNG） |
| SM9 标识密码 | 极少使用，无密评二级要求 | 不做 |
| 密码模块物理防护 | 需硬件模块认证 | 不做（软件模块满足二级） |
| 第三方测评机构认证 | 非代码工作，需独立流程 | 客户自行对接 |

## 五、时间线

```
Week 1:  M1 配置 + KEK 层接入（3 天）+ M2 审计链 HMAC-SM3（1 天）+ M3 SM2 开始（1 天）
Week 2:  M3 SM2 公钥密码（4 天）+ M4 JWT SM2 签名开始（1 天）
Week 3:  M4 JWT SM2 签名（1 天）+ M5 端到端测试（2 天）+ M6 文档（1 天）+ 缓冲（1 天）
```

| 里程碑 | 工期 | 累计 |
|---|---|---|
| M1 配置 + KEK | 3 天 | 3 天 |
| M2 审计链 | 1 天 | 4 天 |
| M3 SM2 | 5 天 | 9 天 |
| M4 JWT SM2 | 2 天 | 11 天 |
| M5 E2E 测试 | 2 天 | 13 天 |
| M6 文档 | 1 天 | 14 天 |
| 缓冲 | 3 天 | 17 天 |

## 六、风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| `tjfoc/gmsm` SM2 实现有 bug | 中 | SM2 功能不可用 | 预留备选 `emmansun/gmsm` |
| 旧审计链（SHA-256）无法与 SM3 混合 | 低 | 升级后旧日志不可验证 | 链头存算法标识，验证时按标识选择 |
| gmsm build tag 导致 CI 复杂化 | 低 | CI 时间增加 | 矩阵编译：`go test` + `go test -tags gmsm` |
| SM2 JWT 与标准库不兼容 | 中 | JWT 验证失败 | 自定义 `jwt.SigningMethod` 实现 |
| 密评二级最终需测评机构确认 | 高 | 代码合规但测评不通过 | 文档对标 GB/T 39786，预留测评整改时间 |

## 七、密评二级对照表（v1.1 完成后）

| GB/T 39786-2021 要求 | v1.1 实现 | 合规 |
|---|---|---|
| SM4 对称加密 | SM4-GCM（KEK + DEK） | ✅ |
| SM3 密码杂凑 | SM3（审计链 + HMAC） | ✅ |
| SM2 公钥密码 | SM2（BYOK + JWT 签名） | ✅ |
| 密钥生成 | CSPRNG + SecureBuffer | ✅ |
| 密钥存储 | KEK 加密 + Shamir 分片 | ✅ |
| 密钥分发 | 版本化密文 + KEK 包封 | ✅ |
| 密钥使用 | RBAC + 资源级授权 | ✅ |
| 密钥更新 | 自动轮转 + 手动轮转 | ✅ |
| 密钥销毁 | Wipe + ShredKey | ✅ |
| 密钥备份恢复 | Shamir 冷存储 | ✅ |
| 审计完整性 | HMAC-SM3 链式签名 | ✅ |
| 身份认证 | JWT SM2 签名 | ✅ |
| 通信安全 | TLS 1.3 | ✅ |
| 密码模块隔离 | 进程隔离 + SecureBuffer | ✅（软件模块） |

## 八、v1.1 发布物

| 交付物 | 说明 |
|---|---|
| `yvonne:1.1` 镜像 | 含 `-tags gmsm` 编译的国密版 |
| `yvonne:1.1-standard` 镜像 | 标准版（AES/SHA，向后兼容） |
| `docs/gmsm-compliance.md` | 国密合规指南 |
| `deploy/examples/config-gmsm.json` | 国密配置模板 |
| 密评二级自评报告 | 对照 GB/T 39786 的自评文档 |
