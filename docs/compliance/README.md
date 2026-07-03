# 合规证据包

> Yvonne KMS v1.4.0 | 日期：2026-07-03 | 适用：等保三级 + 密评三级 + 审计链证据

## 目录结构

本目录按"评估框架"组织文档，每个框架均含独立的自评报告 + 控制点映射 + 证据清单。

### 核心制度文档

| 文档 | 说明 |
|---|---|
| [密码应用方案](crypto-application-scheme.md) | 系统概述 + 算法清单 + 密钥层次 + 合规对照 |
| [密钥生命周期管理制度](key-lifecycle-management.md) | 创建/使用/轮转/备份/销毁全流程规范 |
| [角色职责分离矩阵](role-separation-matrix.md) | 管理员/审计员/业务/紧急操作员 RACI |
| [审计日志样例与验证流程](audit-samples-and-verification.md) | 日志格式 + 样例 + 链验证 + 定期审查 |
| [应急响应与演练手册](emergency-and-drill-handbook.md) | Emergency Seal + 解封恢复 + 销毁演练 + DB 故障 |

### 密评（商用密码应用安全性评估）

| 文档 | 级别 | 说明 |
|---|---|---|
| [等保/密评检查点映射表](compliance-checklist.md) | - | GB/T 39786-2021 逐项对照 |
| [密评二级自评报告](self-assessment-level2.md) | 二级 | 24 项逐项自评（23 合规 + 1 待改进） |
| **[密评三级自评报告](miansi-level3-self-assessment.md)** | **三级** | **95 项控制点逐项自评（86 完全合规 + 5 部分合规 + 4 N/A）** |

### 等保（网络安全等级保护）

| 文档 | 级别 | 说明 |
|---|---|---|
| **[等保三级密码应用对照](dengbao-level3-crypto.md)** | **三级** | **72 项控制点逐项自评（65 完全合规 + 4 部分合规 + 3 N/A）** |

### 审计链与代码安全证据

| 文档 | 说明 |
|---|---|
| **[审计哈希链完整性证明](audit-chain-evidence.md)** | **HMAC 链启动锚定 + 运行验证 + 篡改注入样例 + syslog 双写容灾** |
| **[gosec 扫描基线](gosec-baseline.md)** | **23 项告警分类（0 真实可利用 + 6 RFC 强制保留）** |
| **[govulncheck 漏洞扫描基线](govulncheck-baseline.md)** | **0 漏洞 + 13 间接依赖 CVE 升级计划** |

### 渗透测试

| 文档 | 说明 |
|---|---|
| **[渗透测试报告模板](penetration-test-template.md)** | **8 大类 94 项测试用例 + 通过/失败判定标准 + 漏洞跟踪表** |

### HSM 集成证据

| 文档 | 说明 |
|---|---|
| **[HSM 集成证据](hsm-integration-evidence.md)** | **PKCS#11 接口实现 + SoftHSM 集成验证 + 国产厂商兼容矩阵** |

---

## 外部参考文档

| 文档 | 说明 |
|---|---|
| [国密合规指南](../gmsm-compliance.md) | 编译配置 + 算法清单 + 密评对照表 |
| [v1.3 合规功能指南](../v1.3-compliance.md) | MFA + Quorum + 国密 TLS + OTel |
| [v1.4 OCSP 集成指南](../v1.4-ocsp.md) | OCSP 配置 + 客户端集成 |
| [国密配置示例](../../deploy/examples/config-gmsm.json) | 完全国密模式配置模板 |
| [HSM 集成指南](../hsm-integration-guide.md) | 5 分钟 SoftHSM 上手 + 国产 HSM 厂商配置 |

---

## 使用说明

### 等保三级整改

1. 提交 `dengbao-level3-crypto.md` 给测评机构
2. 配合 `compliance-checklist.md` 逐项准备证据
3. 现场测评：5-7 工作日
4. 整改 P2 项（v1.4.1 计划）

### 密评三级评估

1. 提交 `miansi-level3-self-assessment.md` 给密评机构
2. 准备 `audit-chain-evidence.md` 作为审计链完整性证据
3. 准备 `gosec-baseline.md` + `govulncheck-baseline.md` 作为代码安全证据
4. 现场测评：3-5 工作日
5. 颁发密评三级证书

### 内部审计

- 按 `role-separation-matrix.md` 分配权限
- 按 `key-lifecycle-management.md` 管理密钥
- 按 `audit-samples-and-verification.md` 定期审查
- 按 `emergency-and-drill-handbook.md` 每年至少 1 次演练

### 渗透测试

- 复制 `penetration-test-template.md` 到测试项目目录
- 替换占位符为实际值
- 执行测试，输出完整报告
- 跟踪 P0 / P1 漏洞至关闭

### HSM 集成

- 短期：使用 `hsm-integration-evidence.md` + `hsm-integration-guide.md` 完成 SoftHSM 对接
- 中期：硬件到货后实测，按 `hsm-integration-evidence.md` 收集真实硬件证据

---

## 版本对应

| Yvonne 版本 | 合规级别 | 新增文档 |
|---|---|---|
| v1.0 (GA) | 等保二级基础 | — |
| v1.1 ✅ | 等保二级完整 | — |
| v1.2 ✅ | 等保二级增强 | — |
| v1.3 ✅ | 等保二级完整 + 合规深化 | — |
| **v1.4.0 ✅** | **等保三级 + 密评三级** | **+ 6 个证据文档**（密评三级 / 等保三级 / 审计链 / gosec / govulncheck / 渗透模板 / HSM 集成证据） |

### v1.4.0 文档扩展

| 新增文档 | 文档大小 | 涵盖评估框架 |
|---|---|---|
| `miansi-level3-self-assessment.md` | 1500 行 | 密评三级（GM/T 0054） |
| `dengbao-level3-crypto.md` | 800 行 | 等保三级（GB/T 22239 + GB/T 39786） |
| `audit-chain-evidence.md` | 400 行 | 审计链完整性证据 |
| `gosec-baseline.md` | 200 行 | 静态扫描 |
| `govulncheck-baseline.md` | 150 行 | 漏洞扫描 |
| `penetration-test-template.md` | 600 行 | 渗透测试执行标准 |
| `hsm-integration-evidence.md` | 250 行 | HSM 集成 |

**合计 3,900+ 行合规证据**，覆盖国内主流密码应用合规框架。

---

## 评估清单速查

### 密评三级：是否准备完毕？

- [x] 自评报告：`miansi-level3-self-assessment.md`
- [x] 控制点映射：`reports/miansi-level3-matrix.csv`（参考附录 B）
- [x] 证据文件：`reports/gosec-baseline.json` + `reports/govulncheck-baseline.txt` + `reports/audit-verify-{date}.txt`

### 等保三级：是否准备完毕？

- [x] 自评报告：`dengbao-level3-crypto.md`
- [x] 控制点映射：`reports/dengbao-level3-matrix.csv`（参考附录 A）
- [x] 加固指南：`deploy/yvonne-os-hardening.md` + `deploy/yvonne-network-hardening.md`

### 审计证据：是否完备？

- [x] 哈希链算法证据：`audit-chain-evidence.md §1`
- [x] 实现位置证据：`audit-chain-evidence.md §2`
- [x] 启动期实测证据：`audit-chain-evidence.md §3`
- [x] 运行期验证证据：`audit-chain-evidence.md §4`（实测 43/43 通过）
- [x] 篡改注入证据：`audit-chain-evidence.md §5`
- [x] 容灾方案证据：`audit-chain-evidence.md §6`

### HSM 集成：是否准备完毕？

- [x] 代码路径证据：`hsm-integration-evidence.md §1`
- [x] SoftHSM 集成：`hsm-integration-evidence.md §2`
- [x] 密钥不可导出：`hsm-integration-evidence.md §3`
- [x] 国产厂商矩阵：`hsm-integration-evidence.md §5`
- [ ] 真机对接：硬件到货后执行

---

## 快速链接

- **[README.md](../../README.md)**: 项目主页
- **[CHANGELOG.md](../../CHANGELOG.md)**: 版本历史
- **[manual/user-manual.zh.md](../manual/user-manual.zh.md)**: 用户手册（中文）
- **[manual/user-manual.en.md](../manual/user-manual.en.md)**: 用户手册（英文）

---

**索引版本**：v1.4.0-rev1
**下次更新**：v1.5.0 发布前（约 2026 Q4）
