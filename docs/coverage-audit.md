# Yvonne KMS 覆盖率审计报告

> 日期：2026-06-30 | Go 1.25.11

## 一、各包单独覆盖率

| 包 | 覆盖率 | 状态 |
|---|---|---|
| internal/metrics | 94.4% | ✅ 优秀 |
| internal/memguard | 89.5% | ✅ 优秀 |
| internal/mcp | 86.7% | ✅ 优秀 |
| internal/seal | 85.7% | ✅ 优秀 |
| internal/observability | 85.5% | ✅ 优秀 |
| internal/grpc | 81.1% | ✅ 良好 |
| internal/lifecycle | 81.2% | ✅ 良好 |
| internal/audit | 75.1% | ⚠️ 可提升 |
| internal/crypto | 66.4% | ⚠️ 可提升 |
| internal/api | 64.3% | ⚠️ 可提升（单独跑，不含 integration） |
| internal/admin | 53.2% | ⚠️ 可提升 |
| internal/auth | 53.9% | ⚠️ 可提升 |
| internal/service | 50.8% | ⚠️ 可提升 |
| internal/config | 47.0% | ⚠️ 可提升 |
| internal/storage | 6.4% | ❌ 低（MemoryStore 覆盖，PG 需 integration） |
| cmd/yvonne | 5.4% | ❌ 低（main 入口，需二进制 E2E） |
| sdk/go/yvonne | 5.3% | ❌ 低（需 integration） |

## 二、0% 覆盖函数清单

### admin (3)
- handleListKeys — Admin UI 列出密钥
- SetAdminToken / SetManager — setter 方法

### api (3)
- handleImportKey — BYOK 导入密钥
- handleShredKey — 直接调用（路径分发覆盖间接调）
- handleGenerateDataKey — 直接调用（路径分发覆盖间接调）

### audit (3)
- newHashChainWithHash — 自定义 hash 构造
- Reset — 哈希链重置
- NewAuditLoggerWithHash — 自定义 hash logger

### auth (4)
- IsApprovalComplete / IsExpired / HasApproved — ApprovalTicket 方法
- HasRejected — 已有间接覆盖

### config (3)
- Duration.UnmarshalJSON / MarshalJSON / Std — 自定义 Duration 类型

### crypto (3)
- GenerateSM2AsymmetricKey (stub) — 非 gmsm 构建的 stub
- GenerateSM2KeyPair / SM2Encrypt (stub) — 非 gmsm 构建

### grpc (3)
- Unseal — gRPC unseal 端点
- ImportKey — gRPC import 端点
- AuditQuery — gRPC audit query 端点

### lifecycle (3)
- latestVersionKey — 内部辅助
- Store — getter
- StartSoftDeleteReaper — 后台回收 goroutine

### mcp (1)
- ServeStdio — stdio 传输（需子进程模式）

### seal (3)
- BuildHSMBackend (stub) — 非 hsm 构建的 stub
- IsEmergencySealed / Threshold — HSM unsealer 方法

### service (3)
- ClearCache — 缓存清理
- GenerateMac / VerifyMac — service 层（API 层已覆盖）

### storage (5+)
- NewBoltBackend / Get / Put / Delete / ScanPrefix — BoltDB 后端

## 三、提升计划

### P0 — 高影响（提升 internal 平均覆盖率 5%+）

1. **storage (6.4% → 50%+)** — 补 MemoryStore 完整测试
   - `TestMemoryStore_PutGetDelete` — 基本 CRUD
   - `TestMemoryStore_ScanPrefix` — 前缀扫描
   - `TestMemoryStore_WithTx` — 事务回滚
   - 工期：1 天

2. **config (47% → 70%+)** — 补 Duration + validator 边界
   - `TestDuration_UnmarshalMarshal` — JSON 序列化
   - `TestValidator_EdgeCases` — 边界配置
   - 工期：0.5 天

3. **auth (53.9% → 75%+)** — 补 ApprovalTicket 方法
   - `TestApprovalTicket_Methods` — IsApprovalComplete/IsExpired/HasApproved
   - `TestPolicy_RequireMFA` — Policy 字段
   - 工期：0.5 天

### P1 — 中影响

4. **admin (53.2% → 75%+)** — 补 handleListKeys
   - `TestAdmin_ListKeys` — Admin UI 密钥列表
   - `TestAdmin_SetAdminToken` — setter
   - 工期：0.5 天

5. **service (50.8% → 70%+)** — 补 GenerateMac/VerifyMac/ClearCache
   - `TestService_GenerateMac` — service 层 MAC
   - `TestService_ClearCache` — 缓存清理
   - 工期：0.5 天

6. **grpc (81.1% → 90%+)** — 补 Unseal/ImportKey/AuditQuery
   - `TestGRPC_Unseal` — gRPC unseal
   - `TestGRPC_AuditQuery` — gRPC audit
   - 工期：0.5 天

7. **audit (75.1% → 85%+)** — 补 NewAuditLoggerWithHash
   - `TestAuditLogger_CustomHash` — 自定义 hash
   - `TestHashChain_Reset` — 重置
   - 工期：0.5 天

### P2 — 低影响（stub 代码 + 难测试）

8. **crypto stubs** — 非 gmsm 构建的 stub 函数，无需测试
9. **seal stubs** — 非 hsm 构建的 stub，无需测试
10. **storage/boltdb.go** — BoltDB 后端，需嵌入式 DB 测试
11. **mcp/ServeStdio** — 需子进程模式，复杂度高
12. **cmd/yvonne** — main 入口，需二进制 E2E

## 四、二进制 E2E 全流程测试覆盖度

### 测试矩阵

| 协议 | 测试方式 | 测试数 | 通过率 |
|---|---|---|---|
| HTTP API | Python SDK + curl | 17 | 17/17 (100%) |
| gRPC API | Go client | 5 | 5/5 (100%) |
| MCP API | curl + Go in-memory | 11 | 11/11 (100%) |
| Cluster + Shamir | Go httptest | 6 | 6/6 (100%) |
| PG 持久化 | Go httptest + PG | 7 | 7/7 (100%) |
| 审计链 | Go test | 4 | 4/4 (100%) |
| 轮转守护 | Go test | 4 | 4/4 (100%) |
| Emergency Seal | Go test | 4 | 4/4 (100%) |
| 覆盖率补充 | Go test | 10 | 10/10 (100%) |
| gRPC 补充 | Go test | 8 | 8/8 (100%) |
| **总计** | | **76** | **76/76 (100%)** |

### 真实二进制 E2E（cluster 模式 + PG + TLS + 全协议）

| 测试项 | 通过 |
|---|---|
| Health | ✅ |
| CreateKey | ✅ |
| Encrypt + Decrypt | ✅ |
| RotateKey + 向后兼容 | ✅ |
| Sign + Verify (RSA) | ✅ |
| GenerateMac | ✅ |
| ReEncrypt | ✅ |
| GetPublicKey | ✅ |
| GDK | ✅ |
| SoftDelete + Restore | ✅ |
| RBAC (operator 允许/拒绝) | ✅ |
| MFA setup + verify | ✅ |
| Quorum create | ✅ |
| MCP health | ✅ |
| gRPC Health + Encrypt + Decrypt + Rotate + GDK | ✅ |
| Auth 失败 (无 token/错误 token) | ✅ |
| **总计** | **17/17 (100%)** |

### 总测试统计

```
单元测试:           150+ tests (标准 CI)
Integration 测试:    35 tests (PG + Cluster)
MCP 工具调用测试:    11 tests
gRPC E2E 测试:       8 tests
二进制全流程 E2E:    17 tests
总计:               220+ tests, 100% 通过率
```
