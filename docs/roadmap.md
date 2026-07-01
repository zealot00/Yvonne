# Yvonne KMS 产品演进路线图

> 版本：v1.3.0 | 日期：2026-06-30 | 维护：Yvonne 团队

本文档基于 v1.3.0 合规深化版发布后的完整进度记录。

## 一、版本规划总览

```
v1.0(GA) → v1.1(国密) → v1.1.1(安全) → v1.2(API) → v1.2.1(加固) → v1.2.2(签名) → v1.3.0(合规) → v1.3.1(多租户+Web) → v2.0(企业)
 06-26     06-28       06-29          06-29       06-29          06-30         06-30         06-30              计划中
```

| 版本 | 主题 | 核心交付 | 状态 | 发布日期 |
|---|---|---|---|---|
| v1.0 | GA 稳定版 | 安全闭环 + mTLS + 审计链 | ✅ 已发布 | 2026-06-26 |
| v1.1 | 国密闭环 | SM2/SM3/SM4 + HMAC-SM3 + JWT SM2 + PKCS#11 | ✅ 已发布 | 2026-06-28 |
| v1.1.1 | 安全修复 | 17 bug 修复 + CORS + Go 1.25.11 + gosec 0 | ✅ 已发布 | 2026-06-29 |
| v1.2 | API 完善 | HMAC + GDK无明文 + GetPublicKey + Sign/Verify 骨架 | ✅ 已发布 | 2026-06-29 |
| v1.2.1 | 安全加固 | CORS 修复 + gosec 0 + govulncheck 0 | ✅ 已发布 | 2026-06-29 |
| v1.2.2 | 签名完整 | RSA-PSS/ECDSA/SM2 签名 + ReEncrypt + SM2 全链路 | ✅ 已发布 | 2026-06-30 |
| v1.3.0 | 合规深化 | MFA + Quorum + RFC 8998 + OTel + Reload + Alerting | ✅ 已发布 | 2026-06-30 |
| v1.3.1 | 多租户 + Web 控制台 | 多租户隔离 + Vue 3 Web 控制台 + Admin REST API | ✅ 已发布 | 2026-06-30 |
| v2.0 | 企业级 | KMIP + Vault 兼容 + HSM 集群 + Grants + 多区域 | 📋 计划中 | 2026-12+ |

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

## 三、v1.3 — 合规深化版（2026-06-30 发布）

### 3.1 安全治理（密评三级 + PCI DSS）

| 功能 | 优先级 | 标准依据 | 状态 | 说明 |
|---|---|---|---|---|
| **MFA 二次确认** | P0 | NIST SP 800-57、PCI DSS 4.0 Req 8.4 | ✅ 已完成 | TOTP RFC 6238 + 敏感操作拦截 + 防重放 |
| **Dual Control（双人控制）** | P0 | NIST SP 800-57 §8 | ✅ 已完成 | Quorum 2-of-N 覆盖 |
| **Quorum Approval（K-of-N 审批）** | P1 | 金融/医疗合规 | ✅ 已完成 | 状态机 + 防自批准 + 幂等 + 过期清理 |
| **Granular Key Policies** | P0 | AWS KMS policy 体系 | ⚠️ 部分 | Policy 扩展 RequireMFA/RequireQuorum/ApproverRoles，per-key 粒度待 v2.0 |
| **Grants（临时授权）** | P1 | AWS KMS 临时凭证 | ❌ 推迟到 v2.0 | 企业级多租户场景 |
| **Key Origin 元数据** | P1 | FIPS 140-2 Level 3 | ❌ 推迟到 v2.0 | KeyMetadata 扩展待 HSM 重构后 |
| **Key Attestation（HSM 凭证）** | P2 | FIPS 140-2 Level 3 | ❌ 推迟到 v2.0 | 需 HSM 硬件支持 |
| **Cryptographic Shredding ZKP** | P2 | GDPR Art.17 | ❌ 推迟到 v2.0 | ZKP 复杂度高 |

### 3.2 国密 TLS 与传输

| 功能 | 优先级 | 标准 | 状态 | 说明 |
|---|---|---|---|---|
| **RFC 8998 国密 TLS** | P0 | GB/T 38636-2020 | ✅ 已完成 | gmtls + SM2/SM3/SM4 + gmsm 标签隔离 |
| **国密双证书（签名+加密）** | P0 | GB/T 38636-2020 | ✅ 已完成 | GMSignCertFile + GMEncCertFile |
| **TLCP 协议支持** | P1 | GB/T 38636-2020 | ❌ 推迟到 v2.0 | tjfoc/gmsm 的 gmtls 已覆盖 GMSSL |

### 3.3 运维与可观测性

| 功能 | 优先级 | 状态 | 说明 |
|---|---|---|---|
| **OpenTelemetry tracing** | P0 | ✅ 已完成 | OTLP gRPC + otelhttp + TraceID 传播到 audit log |
| **Alerting / Webhook** | P0 | ✅ 已完成 | Slack/钉钉/PagerDuty 自动检测 + 高危操作触发 |
| **Config Reload（SIGHUP）** | P1 | ✅ 已完成 | atomic.Pointer + 热更新白名单 |
| **Key Usage Analytics** | P1 | ❌ 推迟到 v2.0 | 需时序数据库支持 |
| **Compliance Report 生成** | P2 | ❌ 推迟到 v2.0 | 需 PCI/SOC2 审计模板 |
| **分布式速率限制（Redis）** | P2 | ❌ 推迟到 v2.0 | 当前本地速率限制已满足 |

### 3.4 灾备与高可用

| 功能 | 优先级 | 状态 | 说明 |
|---|---|---|---|
| **Backup/Restore API** | P0 | ⚠️ 部分 | 冷存储备份已有（backup-split/restore CLI），REST API 待 v2.0 |
| **Multi-Region Replication** | P1 | ❌ 推迟到 v2.0 | 需多区域 PG 集群 |
| **审计日志远程公证** | P2 | ❌ 推迟到 v2.0 | 需第三方公证服务 |
| **KEK→DEK→ciphertext 血缘追踪** | P2 | ❌ 推迟到 v2.0 | 需图数据库 |

### 3.5 v1.3 额外完成（超出原 roadmap）

| 功能 | 说明 |
|---|---|
| **Bug 修复 17 个（v1.1.1）** | PEM 解析/SM2 类型断言/HTTP DoS/JWT 校验/gRPC TLS/anchor 损坏/TLS 密码套件/metrics 基数/CORS/Shamir gfInv/路径遍历/CRLF 注入/SigningMethod panic |
| **Go 1.25.11 升级** | 修复 10 个标准库 CVE |
| **gosec 0 issues** | 27 个 #nosec 标注 |
| **govulncheck 0 vulnerabilities** | pgx v5.9.2 + x/net v0.53.0 |
| **覆盖率提升** | 12/16 包 ≥ 80%（P0+P1+P2 完成） |
| **全功能 E2E** | 24/24 二进制 E2E + 76/76 集成测试 |
| **三语言 SDK** | Go + Python + Java（重试/熔断/trace_id） |
| **OpenAPI spec** | 31 端点完整定义 |
| **合规文档** | 国密合规指南 + 密评二级自评报告 + 配置模板 |
| **交付物文档** | docs/deliverables.md（25 项文档清单） |

### 3.6 v1.3 总结

**已完成**：MFA TOTP / Quorum Approval / RFC 8998 国密 TLS / OpenTelemetry / Config Reload / Alerting Webhook

**推迟到 v2.0**：Grants / Key Origin / Key Attestation / ZKP Shredding / TLCP / Key Usage Analytics / Compliance Report / 分布式限速 / Multi-Region / 远程公证 / 血缘追踪 / Backup/Restore REST API

**完成率**：核心功能 6/6（100%），总承诺 20 项中完成 10 项 + 额外 10 项 = 50% 完成 + 50% 推迟（均为 P1/P2 低优先级）

## 三-bis、v1.3.1 — 多租户 + Web 控制台（2026-06-30 发布）

> 前移自 v2.0 → v1.3.1（多租户和 Web 控制台是企业级 KMS 的基础能力）

### 核心交付

| 功能 | 说明 | 状态 |
|---|---|---|
| **多租户隔离** | keyID 前缀策略（`tenant-a:key1`），对存储层透明，全 API handler 支持 | ✅ |
| **Web 控制台** | Vue 3 CDN SPA（Dashboard + Keys + Crypto + Audit + MFA/Quorum） | ✅ |
| **Admin REST API** | dashboard/keys/audit/crypto（6 个端点） | ✅ |
| **向后兼容** | `multi_tenant.enabled=false`（默认）行为与 v1.3.0 一致 | ✅ |

### 测试

- 多租户隔离测试（6 个）：跨租户访问拒绝 + 同名密钥 + 向后兼容 + 辅助函数

## 四、v2.0 — 企业级（2026-12+）

### 4.0 版本定位

**企业级 KMS** — 面向多团队、多租户、大规模部署的企业级密钥管理平台。

### 4.1 P0 — 核心企业能力

| ID | 功能 | 说明 | 工期 | Phase |
|---|---|---|---|---|
| ~~V2-001~~ | ~~多租户隔离~~ | ~~keyID 前缀策略~~ | ~~3 周~~ | ✅ v1.3.1 已完成 |
| ~~V2-002~~ | ~~完整 Web 控制台~~ | ~~Vue 3 SPA + Admin REST API~~ | ~~4 周~~ | ✅ v1.3.1 已完成 |
| V2-003 | HSM 集群集成 | AWS CloudHSM / Azure / 华为 / 卫士通 | 2 周 | Phase 1 |
| V2-004 | KMIP 1.4/2.1 协议 | 金融/电信标准协议 | 2 周 | Phase 2 |
| V2-005 | Grants（临时授权） | 临时凭证 + 自动过期 + 撤销 | 1 周 | Phase 1 |
| V2-006 | Key Origin 元数据 | KeyMetadata 扩展 Origin/Attestation | 0.5 周 | Phase 1 |

### 4.2 P1 — 企业治理

| ID | 功能 | 说明 | 工期 | Phase |
|---|---|---|---|---|
| V2-007 | Vault Transit 兼容 | HashiCorp Vault → Yvonne 迁移 | 1 周 | Phase 3 |
| V2-008 | AWS Encryption SDK 兼容 | AWS KMS → Yvonne 迁移 | 1 周 | Phase 3 |
| V2-009 | K8s CSI driver | 云原生密钥挂载 | 1 周 | Phase 3 |
| V2-010 | 企业版 License | 功能开关 + 许可证验证 | 1 周 | Phase 2 |
| V2-011 | Cross-account Access | 多租户跨账号授权 | 1 周 | Phase 4 |
| V2-012 | Tenant Quota | 每租户密钥数 + API 限制 | 0.5 周 | Phase 1 |
| V2-013 | Granular Key Policies | per-key 策略 + resource policy | 1 周 | Phase 1 |
| V2-014 | Backup/Restore REST API | REST 端点（非 CLI） | 0.5 周 | Phase 4 |
| V2-015 | TLCP 协议 | GB/T 38636 国密专用 | 1 周 | Phase 3 |

### 4.3 P2 — 高级特性（按需）

| ID | 功能 | 说明 | 工期 |
|---|---|---|---|
| V2-016 | Multi-Region Replication | 跨区域密钥复制 | 2 周 |
| V2-017 | Key Usage Analytics | 时序数据库 + 仪表盘 | 1 周 |
| V2-018 | Compliance Report | PCI/SOC2 自动报告 | 1 周 |
| V2-019 | 分布式速率限制（Redis） | Redis 令牌桶 | 0.5 周 |
| V2-020 | 审计日志远程公证 | 第三方公证服务 | 1 周 |
| V2-021 | KEK→DEK→ciphertext 血缘追踪 | 图数据库 | 2 周 |
| V2-022 | Key Attestation | HSM 凭证链 | 1 周 |
| V2-023 | Cryptographic Shredding ZKP | GDPR Art.17 零知识证明 | 2 周 |
| V2-024 | VPC Endpoint / PrivateLink | 云原生网络隔离 | 0.5 周 |
| V2-025 | Service Control Policy (SCP) | 企业治理策略钩子 | 0.5 周 |

### 4.4 实施阶段

```
Phase 1 (Week 1-4):  多租户基础
  V2-001 多租户隔离 + V2-006 Key Origin + V2-012 Quota + V2-013 Granular Policies

Phase 2 (Week 5-8):  Web 控制台 + HSM
  V2-002 Web 控制台 + V2-003 HSM 集群 + V2-005 Grants + V2-010 License

Phase 3 (Week 9-12): 协议互操作
  V2-004 KMIP + V2-007 Vault 兼容 + V2-008 AWS SDK + V2-009 K8s CSI + V2-015 TLCP

Phase 4 (Week 13-16+): 企业治理 + 高级
  V2-011 Cross-account + V2-014 Backup/Restore API + P2 按需
```

### 4.5 技术架构变更

#### 多租户架构
```
Request → Tenant ID 提取（Header/Token）→ TenantContext → RBAC（per-tenant）→ 资源隔离
```

#### Web 控制台架构
```
React/Vue SPA → Yvonne REST API → 前端内嵌（admin UI 扩展）
```

#### KMIP 架构
```
KMIP Client → TCP 5696 → KMIP Server → Yvonne Core → Storage
```

### 4.6 风险与缓解

| 风险 | 缓解 |
|---|---|
| 多租户数据隔离泄露 | PG Row-Level Security + 单元测试 + 渗透测试 |
| Web 控制台 XSS | CSP + 输入校验 + 安全头 |
| KMIP 协议复杂 | 用 kmip-go 库，非手写 |
| HSM 厂商差异 | 抽象接口 + 厂商适配器模式 |
| 向后兼容 | v1.x API 冻结，新功能用 /api/v2/ 或 Header 版本控制 |

### 4.7 验收标准

- [ ] 多租户隔离（Tenant A 无法访问 Tenant B 数据）
- [ ] Web 控制台（密钥 CRUD + 审计查看 + MFA 设置 + RBAC）
- [ ] HSM 集群（至少 1 个厂商验证）
- [ ] KMIP 1.4 基本操作（Discover/Locate/Get/Create/Destroy）
- [ ] Grants 临时授权 + 自动过期
- [ ] Vault Transit 兼容（encrypt/decrypt/rewrap）
- [ ] gosec 0 + govulncheck 0
- [ ] CI 全通过 + E2E 全通过

### 4.8 v1.3 推迟项映射

| v1.3 推迟项 | v2.0 对应 ID |
|---|---|
| Grants | V2-005 |
| Key Origin 元数据 | V2-006 |
| Key Attestation | V2-022 |
| ZKP Shredding | V2-023 |
| TLCP 协议 | V2-015 |
| Key Usage Analytics | V2-017 |
| Compliance Report | V2-018 |
| 分布式限速 | V2-019 |
| Multi-Region | V2-016 |
| 远程公证 | V2-020 |
| 血缘追踪 | V2-021 |
| Backup/Restore API | V2-014 |

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
