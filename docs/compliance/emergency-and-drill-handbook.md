# 应急响应与密钥销毁演练手册

> 适用：Yvonne KMS v1.0+ | 日期：2026-06-26

## 1. 应急场景

### 1.1 场景分类

| 级别 | 场景 | 响应时间 |
|---|---|---|
| P0 | Master Key 疑似泄露 | 立即 Emergency Seal |
| P0 | Shamir 分片泄露 | 立即 Emergency Seal + 重新生成 CMK |
| P1 | DB 被入侵 | Emergency Seal + DB 隔离 |
| P1 | 管理员 Token 泄露 | 撤销 Token + 审查操作记录 |
| P2 | 单个 DEK 疑似泄露 | ShredKey 该版本 + 轮转 |
| P2 | 审计链断裂 | 调查原因 + 修复 + 报告 |

## 2. Emergency Seal 操作流程

### 2.1 触发条件

- Master Key 或 Shamir 分片疑似泄露
- 系统被入侵，需要立即停止服务
- 合规审计要求紧急冻结

### 2.2 操作步骤

```bash
# 1. 紧急操作员执行 Emergency Seal
curl -X POST http://yvonne:8400/api/v1/sys/panic \
  -H "Content-Type: application/json" \
  -d '{"admin_token":"$ADMIN_TOKEN","confirm":true}'

# 2. 验证系统已封印
curl http://yvonne:8400/api/v1/sys/health
# 期望: {"state":"emergency_sealed","emergency_sealed":true}

# 3. 所有后续 API 请求返回 503
curl http://yvonne:8400/api/v1/encrypt
# 期望: 503 Service Unavailable
```

### 2.3 封印后效果

- Master Key 内存清零
- DEK 缓存清空
- 收集的 Shamir 分片清零
- 所有 API 返回 503
- 审计日志记录 EmergencySeal 操作
- **不可逆**：需重启进程 + Shamir 解封

## 3. Shamir 解封恢复流程

### 3.1 前置条件

- ≥3 名管理员到场（3 门限）
- 各自保管的分片可读
- Yvonne 进程已重启

### 3.2 操作步骤

```bash
# 1. 重启 Yvonne 进程
kubectl rollout restart statefulset/yvonne

# 2. 等待 Pod 就绪（Sealed 状态）
kubectl exec yvonne-0 -- curl localhost:8400/api/v1/sys/health
# 期望: {"state":"sealed"}

# 3. 管理员 A 提交分片
curl -X POST http://yvonne:8400/api/v1/sys/unseal \
  -d '{"shares":["<share_A_base64>"]}'
# 期望: {"unsealed":false}

# 4. 管理员 B 提交分片
curl -X POST http://yvonne:8400/api/v1/sys/unseal \
  -d '{"shares":["<share_B_base64>"]}'
# 期望: {"unsealed":false}

# 5. 管理员 C 提交分片（达门限）
curl -X POST http://yvonne:8400/api/v1/sys/unseal \
  -d '{"shares":["<share_C_base64>"]}'
# 期望: {"unsealed":true}

# 6. 验证系统恢复
curl http://yvonne:8400/api/v1/sys/health
# 期望: {"state":"unsealed"}
```

## 4. 密钥销毁演练

### 4.1 演练目标

验证密钥物理粉碎后密文永久不可解密。

### 4.2 演练步骤

```bash
# 1. 创建演练密钥
curl -X POST http://yvonne:8400/api/v1/keys \
  -H "Authorization: Bearer admin-token" \
  -d '{"key_id":"drill-destroy-key"}'

# 2. 加密演练数据
RESP=$(curl -X POST http://yvonne:8400/api/v1/encrypt \
  -H "Authorization: Bearer admin-token" \
  -d '{"key_id":"drill-destroy-key","plaintext":"SGVsbG8="}')
CIPHERTEXT=$(echo $RESP | jq -r .data.ciphertext)

# 3. 物理粉碎密钥 v1
curl -X DELETE http://yvonne:8400/api/v1/keys/drill-destroy-key/shred \
  -H "Authorization: Bearer admin-token" \
  -d '{"version":1}'

# 4. 验证密文不可解密
curl -X POST http://yvonne:8400/api/v1/decrypt \
  -H "Authorization: Bearer admin-token" \
  -d "{\"key_id\":\"drill-destroy-key\",\"ciphertext\":\"$CIPHERTEXT\"}"
# 期望: 400 或 404 (key version destroyed/not found)

# 5. 验证审计日志
curl -X POST http://yvonne:8400/api/v1/audit/query \
  -H "Authorization: Bearer auditor-token" \
  -d '{"action":"ShredKey","limit":1}'
# 期望: 含 ShredKey drill-destroy-key v1 的记录
```

### 4.3 演练验收

- [ ] 粉碎前密文可解密
- [ ] 粉碎后密文不可解密（返回 4xx）
- [ ] 审计日志记录粉碎操作
- [ ] DB 中该版本元数据已删除

## 5. 备份恢复演练

### 5.1 演练目标

验证 Shamir 分片可恢复 Master Key。

### 5.2 演练步骤

1. 从 3 名管理员处获取分片文件
2. `yvonne backup-restore --out /tmp/recovered.bin share1.bin share2.bin share3.bin`
3. 验证恢复的 wrapped CMK 与原始一致
4. 在测试环境用恢复的 CMK 启动 Yvonne
5. 验证可解密历史密文

### 5.3 演练频率

- 每年至少 1 次
- CMK 轮转后立即验证
- 管理员变更后立即验证

## 6. 数据库故障演练

### 6.1 PG 断连

```bash
# 模拟 PG 断连
kubectl scale statefulset postgres --replicas=0

# 验证 Yvonne 进入 degraded 模式
curl http://yvonne:8400/api/v1/sys/health
# 期望: 仍 unsealed（缓存 DEK 可解密）

# 验证写操作被拒绝
curl -X POST http://yvonne:8400/api/v1/keys \
  -H "Authorization: Bearer admin-token" \
  -d '{"key_id":"should-fail"}'
# 期望: 503 (degraded mode)

# 恢复 PG
kubectl scale statefulset postgres --replicas=1

# 验证自动恢复
sleep 15
curl -X POST http://yvonne:8400/api/v1/keys \
  -H "Authorization: Bearer admin-token" \
  -d '{"key_id":"should-work-now"}'
# 期望: 200
```

### 6.2 验收标准

- [ ] PG 断连后解密仍可用（缓存）
- [ ] PG 断连后写操作返回明确错误
- [ ] PG 恢复后自动退出 degraded 模式
- [ ] 审计日志记录 degraded 事件

## 7. 演练记录模板

| 项 | 内容 |
|---|---|
| 演练名称 | |
| 演练日期 | |
| 参与人员 | |
| 演练场景 | |
| 执行步骤 | |
| 验收结果 | |
| 问题与改进 | |
| 审计日志 trace_id | |
| 下次演练计划 | |
