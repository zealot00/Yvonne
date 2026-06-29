# Yvonne KMS 产品演进路线图

> 版本：v1.2 | 日期：2026-06-29 | 维护：Yvonne 团队

本文档基于 v1.1 国密闭环版发布后的产品缺陷分析、合规要求、客户场景反馈制定。

## 一、版本规划总览

```
v1.0 (GA)        → v1.1 (国密闭环) ✅ → v1.2 (API 完善) → v1.3 (合规深化) → v2.0 (企业级)
   2026-06-26         2026-06-28           2026-07            2026-09          2026-12+
```

| 版本 | 主题 | 核心交付 | 工期 |
|---|---|---|---|
| v1.0 ✅ | GA 稳定版 | 安全闭环 + mTLS + 审计链 | - |
| v1.1 ✅ | 国密闭环 | SM2/SM3/SM4 + HMAC-SM3 + JWT SM2 + PKCS#11 | - |
| v1.2 | API 完善 | Sign/Verify + GDK无明文 + HMAC + ReEncrypt + 国密证书 | 3-4 周 |
| v1.3 | 合规深化 | MFA + 双人控制 + RFC 8998 + OpenTelemetry + Config Reload | 6-8 周 |
| v2.0 | 企业级 | 多租户 + Web 控制台 + KMIP + Vault 兼容 + 多区域 | 3-6 个月 |

## 二、v1.2 — API 完善版（2026-07）

### 2.1 密钥操作补全（对标 AWS KMS 核心子集）

| 功能 | 优先级 | 说明 | 工期 |
|---|---|---|---|
| **Sign / Verify API** | P0 | 非对称签名/验签直接暴露 API（当前仅 MCP 间接） | 3 天 |
| **GenerateDataKeyWithoutPlaintext** | P0 | 仅返回密文 DEK，不返回明文（信封加密标准能力） | 1 天 |
| **GenerateMac / VerifyMac** | P0 | HMAC-SHA256 / HMAC-SM3 生成与验证 | 2 天 |
| **ReEncrypt** | P1 | KMS 内重加密（改 CMK），支持密钥迁移 | 3 天 |
| **GetPublicKey** | P1 | 直接获取非对称密钥公钥（非 BYOK 流程） | 1 天 |
| **DisableKey / EnableKey** | P1 | 禁用/启用密钥（区别于 Deactivated 状态） | 2 天 |
| **CancelKeyDeletion** | P1 | 取消待删除密钥（窗口期内恢复） | 1 天 |
| **CreateAlias / DeleteAlias / ListAliases** | P2 | 密钥别名（友好名映射） | 2 天 |
| **TagResource / UntagResource / ListResourceTags** | P2 | 密钥标签（资源管理） | 2 天 |
| **GetKeyRotationStatus** | P2 | 查询轮转状态 | 1 天 |

### 2.2 国密证书链验证

| 功能 | 优先级 | 标准 | 工期 |
|---|---|---|---|
| **X.509 SM2 证书签发** | P0 | GM/T 0015 | 3 天 |
| **SM2 证书链验证** | P0 | GM/T 0015 | 2 天 |
| **SM2 CRL/OCSP 支持** | P1 | GM/T 0015 | 3 天 |
| **密钥使用可信时间戳** | P1 | GM/T 0022 | 3 天 |

### 2.3 SDK 补全

| 功能 | 优先级 | 工期 |
|---|---|---|
| **Java SDK** | P0 | 2 天（OpenAPI 生成 + 手工优化） |
| **SDK 重试/超时/熔断** | P0 | 2 天 |
| **SDK trace_id 透传** | P1 | 1 天 |

### 2.4 SM2 互操作增强

| 功能 | 优先级 | 说明 | 工期 |
|---|---|---|---|
| **C1C3C2 / C1C2C3 双模** | P0 | SM2 加密模式可配置（Crypto-6 已修 UID，需补模式） | 2 天 |
| **SM2 证书 PEM 导入导出** | P0 | 支持 SM2 证书作为 JWT 验签密钥 | 1 天 |

## 三、v1.3 — 合规深化版（2026-09）

### 3.1 安全治理（密评三级 + PCI DSS）

| 功能 | 优先级 | 标准依据 | 工期 |
|---|---|---|---|
| **MFA 二次确认** | P0 | NIST SP 800-57、PCI DSS 4.0 Req 8.4 | 5 天 |
| **Dual Control（双人控制）** | P0 | NIST SP 800-57 §8 | 5 天 |
| **Quorum Approval（K-of-N 审批）** | P1 | 金融/医疗合规 | 5 天 |
| **Granular Key Policies** | P0 | AWS KMS policy 体系（resource-level） | 5 天 |
| **Grants（临时授权）** | P1 | AWS KMS 临时凭证 | 5 天 |
| **Key Origin 元数据** | P1 | FIPS 140-2 Level 3 | 2 天 |
| **Key Attestation（HSM 凭证）** | P2 | FIPS 140-2 Level 3 | 5 天 |
| **Cryptographic Shredding ZKP** | P2 | GDPR Art.17 | 5 天 |

### 3.2 国密 TLS 与传输

| 功能 | 优先级 | 标准 | 工期 |
|---|---|---|---|
| **RFC 8998 国密 TLS** | P0 | GB/T 38636-2020 | 5 天 |
| **国密双证书（签名+加密）** | P0 | GB/T 38636-2020 | 3 天 |
| **TLCP 协议支持** | P1 | GB/T 38636-2020 | 5 天 |

### 3.3 运维与可观测性

| 功能 | 优先级 | 工期 |
|---|---|---|
| **OpenTelemetry tracing** | P0 | 3 天 |
| **Alerting / Webhook（钉钉/Slack/PagerDuty）** | P0 | 3 天 |
| **Config Reload（SIGHUP 无重启）** | P1 | 3 天 |
| **Key Usage Analytics** | P1 | 3 天 |
| **Compliance Report 生成（PCI/SOC2）** | P2 | 5 天 |
| **分布式速率限制（Redis）** | P2 | 3 天 |

### 3.4 灾备与高可用

| 功能 | 优先级 | 工期 |
|---|---|---|
| **Backup/Restore API** | P0 | 3 天 |
| **Multi-Region Replication** | P1 | 5 天 |
| **审计日志远程公证** | P2 | 5 天 |
| **KEK→DEK→ciphertext 血缘追踪** | P2 | 5 天 |

## 四、v2.0 — 企业级（2026-12+）

### 4.1 多租户与企业治理

| 功能 | 优先级 | 工期 |
|---|---|---|
| **多租户隔离** | P0 | 3 周 |
| **完整 Web 控制台** | P0 | 4 周 |
| **企业版 License** | P0 | 2 周 |
| **Tenant Quota 配额** | P1 | 1 周 |
| **Cross-account Access** | P1 | 1 周 |
| **VPC Endpoint / PrivateLink** | P2 | 1 周 |
| **Service Control Policy (SCP) Hook** | P2 | 1 周 |

### 4.2 协议互操作

| 功能 | 优先级 | 说明 | 工期 |
|---|---|---|---|
| **KMIP 1.4/2.1** | P0 | 金融/电信标准协议 | 2 周 |
| **Vault Transit 兼容接口** | P1 | 迁移客户 | 1 周 |
| **AWS Encryption SDK 兼容** | P1 | 迁移客户 | 1 周 |
| **Kubernetes CSI driver** | P2 | 云原生 | 1 周 |

### 4.3 HSM 集群与灾备

| 功能 | 优先级 | 工期 |
|---|---|---|
| **HSM Provider 抽象（AWS/Azure/华为/卫士通）** | P0 | 2 周 |
| **HSM 集群故障切换** | P0 | 1 周 |
| **HSM 部署拓扑文档** | P1 | 3 天 |

## 五、不纳入路线图的功能

以下功能经评估**不纳入** Yvonne 演进路线，原因如下：

| 功能 | 原因 |
|---|---|
| **SM9 标识密码** | 超出中小企业 KMS 场景，标准库无支持，密评二级不要求 |
| **ZUC 序列密码** | 通信加密场景，非 KMS 职责 |
| **GraphQL API** | 客户需求极低，REST + gRPC 已覆盖 |
| **Chaos Engineering hooks** | 过度工程，由运维平台层负责 |
| **FIPS 140-3 Boundary Self-test** | FIPS 认证非 Yvonne 目标（国密路线为主） |
| **ReplicateKey（多区域 CMK 复制）** | 云厂商特性，自托管场景无需求 |
| **CreateGrant/RetireGrant 细粒度授权** | v1.3 Grants 已覆盖核心场景，完整 AWS Grants 模型过度 |
| **API v2 并行维护** | v1 API 已稳定，无需 v2 |

## 六、缺陷分析对照

### 6.1 已在 v1.1 修复的安全 Bug

| Bug | 修复版本 |
|---|---|
| C-1/C-2: PEM 解析静默吞错 | v1.1.1 |
| C-3: SM2 PEM 缺类型断言 | v1.1.1 |
| C-4: HTTP 无请求体大小限制 | v1.1.1 |
| C-5: PEM 私钥磁盘残留 | v1.1.1 |
| Auth-1: JWT 缺过期/签发者校验 | v1.1.1 |
| Auth-14: 轮转锁外竞态 | v1.1.1（确认安全） |
| Auth-16: 删除 PEM 失败不致命 | v1.1.1 |
| Auth-18: gRPC TLS 明文暴露 | v1.1.1 |
| Audit-10: anchor 损坏静默重置 | v1.1.1 |
| Config-1: TLS 密码套件不可配置 | v1.1.1 |
| Config-5: metrics 标签基数爆炸 | v1.1.1 |
| Config-018: SigningMethod 切片 panic | v1.1.1 |
| BUG-3: CORS DefaultCORSConfig | v1.1.1（注释明确 Dev 模式） |
| BUG-6: Limit=-1 DoS | v1.1.1 |
| BUG-9: CRLF 注入 | v1.1.1 |
| BUG-17: gfInv(0) 静默返回 0 | v1.1.1 |
| BUG-013: Shamir 路径 traversal | v1.1.1 |

### 6.2 缺陷与路线图映射

| 缺陷 | 严重程度 | 路线图版本 | 说明 |
|---|---|---|---|
| Sign/Verify API | HIGH | v1.2 | 直接暴露非对称签名 API |
| GenerateDataKeyWithoutPlaintext | HIGH | v1.2 | 信封加密标准能力 |
| GenerateMac/VerifyMac | HIGH | v1.2 | HMAC 合规必需 |
| ReEncrypt | CRITICAL→P1 | v1.2 | KMS 内重加密 |
| MFA/Dual Control | CRITICAL | v1.3 | 密评三级 + PCI DSS |
| RFC 8998 国密 TLS | HIGH | v1.3 | 国密传输闭环 |
| OpenTelemetry | MEDIUM | v1.3 | 可观测性 |
| Config Reload | MEDIUM | v1.3 | 运维 |
| 多租户隔离 | HIGH | v2.0 | 企业版核心 |
| KMIP | MEDIUM | v2.0 | 金融/电信 |
| Vault 兼容 | LOW | v2.0 | 迁移客户 |
| SM9/ZUC | MEDIUM | 不纳入 | 超范围 |
| GraphQL | LOW | 不纳入 | 无需求 |

## 七、优先级决策原则

1. **合规驱动优先**：密评/等保硬性要求 > 客户体验 > 技术先进性
2. **中小企业场景**：拒绝云厂商规模才需要的能力（多区域复制、完整 Grants 模型）
3. **国密为主**：FIPS 认证不纳入，国密认证为长期目标
4. **渐进式**：每个版本有明确主题，避免功能膨胀
5. **客户验证**：v1.2/v1.3 发布后需 3+ 试点客户验证后再推进 v2.0
