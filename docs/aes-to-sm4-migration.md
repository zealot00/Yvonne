# AES → SM4 迁移指南

> Yvonne KMS v1.1 | 日期：2026-06-28

## 迁移策略

### 方案 A：版本轮转迁移（推荐，零停服）

1. **切换 suite**：`crypto.suite: "gmsm"`（新密钥用 SM4）
2. **轮转现有密钥**：`RotateKey` 生成 SM4 DEK，旧 AES DEK → Deactivated
3. **旧密文仍可解密**：版本化密文自动路由到旧版本 AES DEK
4. **逐步重加密**：业务系统读取旧密文 → 解密 → 用新密钥重新加密

```bash
# 1. 切换配置
# config.json: "crypto": {"suite": "gmsm"}
yvonne server --config config.json

# 2. 轮转所有密钥（新版本用 SM4）
for key in order-key payment-key user-key; do
  curl -X POST http://yvonne:8400/api/v1/keys/$key/rotate \
    -H "Authorization: Bearer admin-token"
done

# 3. 旧密文仍可解密（向后兼容）
# 4. 业务系统逐步重加密
```

### 方案 B：双读双写（过渡期）

- 新加密用 SM4（新版本）
- 旧解密仍支持 AES（旧版本 Deactivated）
- 过渡期结束后粉碎旧版本

### 方案 C：全量重建（停服）

1. 停服
2. 切换 `crypto.suite: "gmsm"`
3. 删除旧密钥 + 重建所有密钥
4. 重新加密所有业务数据

## 迁移检查清单

- [ ] `crypto.suite: "gmsm"` 配置生效
- [ ] 所有密钥已轮转（新版本 Algorithm=sm4-gcm）
- [ ] 旧密文仍可解密（向后兼容验证）
- [ ] 业务系统重加密完成
- [ ] 旧版本 ShredKey（物理粉碎）
- [ ] 审计链切换 HMAC-SM3
- [ ] JWT 切换 SM2 签名

## 注意事项

- **不可回退**：SM4 密钥轮转后，旧 AES DEK 被 Deactivated 但仍可解密旧密文
- **密文格式不变**：版本化密文格式 `[4B版本][12B Nonce][CT+Tag]` 算法无关
- **KEK 密文不兼容**：softwareKEK 的密文格式取决于 suite，跨 suite 不可互解（需轮转重建）
