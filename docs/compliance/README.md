# 合规证据包

> Yvonne KMS v1.0 | 日期：2026-06-26 | 适用：等保二级/三级 + 密评二级

## 目录

| 文档 | 说明 |
|---|---|
| [密码应用方案](crypto-application-scheme.md) | 系统概述 + 算法清单 + 密钥层次 + 合规对照 |
| [密钥生命周期管理制度](key-lifecycle-management.md) | 创建/使用/轮转/备份/销毁全流程规范 |
| [角色职责分离矩阵](role-separation-matrix.md) | 管理员/审计员/业务/紧急操作员 RACI |
| [审计日志样例与验证流程](audit-samples-and-verification.md) | 日志格式 + 样例 + 链验证 + 定期审查 |
| [应急响应与演练手册](emergency-and-drill-handbook.md) | Emergency Seal + 解封恢复 + 销毁演练 + DB 故障 |
| [等保/密评检查点映射表](compliance-checklist.md) | GB/T 39786-2021 逐项对照 |

## 使用说明

1. **等保整改**：将本目录文档作为密码管理整改附件提交
2. **密评准备**：对照检查点映射表逐项准备证据
3. **内部审计**：按角色职责矩阵分配权限 + 定期审查
4. **应急演练**：按演练手册每年至少执行 1 次

## 版本对应

| Yvonne 版本 | 合规级别 | 说明 |
|---|---|---|
| v1.0 (GA) | 等保二级基础 | SM4/SM3/SM2 已实现，审计链 HMAC-SHA256 |
| v1.1 | 等保二级完整 | HMAC-SM3 + JWT SM2 + 密文算法标识 |
| v1.2 | 等保三级 | PKCS#11 HSM + 国密认证 RNG |
