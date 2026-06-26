# 审计日志样例与验证流程

> 适用：Yvonne KMS v1.0+ | 日期：2026-06-26

## 1. 审计日志格式

### 1.1 JSON 格式（落盘）

```json
{
  "trace_id": "a1b2c3d4e5f6",
  "timestamp": "2026-06-26T10:30:00.123456789Z",
  "client_ip": "10.0.0.1",
  "actor": "order-service",
  "resource": "order-encrypt-key",
  "action": "Encrypt",
  "result": "success",
  "key_id": "order-encrypt-key"
}
```

### 1.2 签名信封（落盘最终格式）

```json
{
  "payload": "{\"trace_id\":\"a1b2...\",\"timestamp\":\"2026-06-26T10:30:00Z\",...}",
  "signature": "hex(hmac(key, prev_signature + payload))",
  "prev_signature": "hex(prev_entry_signature)"
}
```

- 第一条日志的 `prev_signature` = `SHA256(AuditKey)`
- 每条日志的 `signature` = `HMAC-SHA256(key, prev_signature + payload)` 或 `HMAC-SM3(key, prev_signature + payload)`

## 2. 审计日志样例

### 2.1 密钥创建

```json
{"trace_id":"abc123","timestamp":"2026-06-26T10:00:00Z","actor":"admin","resource":"payment-key","action":"CreateKey","result":"success","key_id":"payment-key"}
```

### 2.2 加密操作

```json
{"trace_id":"def456","timestamp":"2026-06-26T10:01:00Z","actor":"order-service","resource":"order-key","action":"Encrypt","result":"success","key_id":"order-key"}
```

### 2.3 解密操作

```json
{"trace_id":"ghi789","timestamp":"2026-06-26T10:02:00Z","actor":"order-service","resource":"order-key","action":"Decrypt","result":"success","key_id":"order-key"}
```

### 2.4 密钥轮转

```json
{"trace_id":"jkl012","timestamp":"2026-06-26T10:03:00Z","actor":"SYSTEM_DAEMON","resource":"payment-key","action":"RotateKey","result":"success","key_id":"payment-key"}
```

### 2.5 物理粉碎

```json
{"trace_id":"mno345","timestamp":"2026-06-26T10:04:00Z","actor":"admin","resource":"old-key","action":"ShredKey","result":"success","key_id":"old-key"}
```

### 2.6 授权拒绝

```json
{"trace_id":"pqr678","timestamp":"2026-06-26T10:05:00Z","actor":"order-service","resource":"payment-key","action":"Encrypt","result":"denied","key_id":"payment-key"}
```

### 2.7 紧急封印

```json
{"trace_id":"stu901","timestamp":"2026-06-26T10:06:00Z","actor":"emergency-operator","resource":"","action":"EmergencySeal","result":"success","key_id":""}
```

### 2.8 数据库降级

```json
{"trace_id":"vwx234","timestamp":"2026-06-26T10:07:00Z","actor":"system","resource":"","action":"DegradedMode","result":"warning","key_id":""}
```

## 3. 审计日志验证流程

### 3.1 离线验证命令

```bash
# 验证审计链完整性
yvonne audit-verify --dir /var/log/yvonne

# 输出示例：
# ✅ Chain verified: 15234 entries, 0 tampered
# ✅ First entry: 2026-06-20T00:00:00Z
# ✅ Last entry: 2026-06-26T10:07:00Z
```

### 3.2 验证步骤

1. **加载审计密钥**：从 Master Key 经 HKDF 派生
2. **读取第一条日志**：验证 `prev_signature` == `SHA256(AuditKey)`
3. **逐条验证**：
   - 计算 `expected_sig = HMAC(key, prev_sig + payload)`
   - 对比 `entry.signature` == `expected_sig`
   - 更新 `prev_sig = entry.signature`
4. **结果报告**：总条数、篡改条数、时间范围

### 3.3 在线查询

```bash
# 查询最近 100 条加密操作
curl -X POST http://yvonne:8400/api/v1/audit/query \
  -H "Authorization: Bearer auditor-token" \
  -d '{"action":"Encrypt","limit":100}'
```

### 3.4 定期审查流程

| 频率 | 审查项 | 负责人 |
|---|---|---|
| 每日 | 检查 denied 操作 | 审计员 |
| 每周 | 验证审计链完整性 | 审计员 |
| 每月 | 审查密钥创建/销毁记录 | 审计员 + 管理员 |
| 每季度 | 审查 Token 使用 + 轮转记录 | 审计员 + 安全负责人 |

## 4. Syslog 双写

### 4.1 配置

```json
{
  "audit": {
    "syslog_enabled": true,
    "syslog_tag": "yvonne-kms"
  }
}
```

### 4.2 Syslog 格式

```
<134>Jun 26 10:30:00 yvonne-kms yvonne[1234]: {"trace_id":"abc123","action":"Encrypt",...}
```

### 4.3 集中日志收集

- rsyslog / syslog-ng → 集中日志服务器
- 可接入 SIEM（如 Splunk / ELK / 阿里云日志服务）

## 5. 审计日志防篡改保证

| 威胁 | 防御 |
|---|---|
| 修改日志内容 | HMAC 签名不匹配 |
| 删除日志 | `prev_signature` 链断裂 |
| 插入伪造日志 | 签名无法伪造（无 AuditKey） |
| 重放旧日志 | 时间戳 + trace_id |
| 数据库篡改 | 日志独立文件存储 + Syslog 双写 |
