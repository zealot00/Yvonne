# Yvonne KMS Java SDK

> 版本：v1.3.0 | 日期：2026-06-30

Java SDK for Yvonne KMS, supporting all v1.0-v1.3 API endpoints.

## 安装

### Maven

```xml
<dependency>
    <groupId>io.yvonne</groupId>
    <artifactId>yvonne-kms-sdk</artifactId>
    <version>1.3.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.yvonne:yvonne-kms-sdk:1.3.0'
```

## 快速开始

```java
import io.yvonne.kms.YvonneClient;
import io.yvonne.kms.model.*;

// 创建客户端
YvonneClient client = new YvonneClient("https://kms.internal:8200", "admin-token");

// 健康检查
HealthResponse health = client.health();
System.out.println("State: " + health.getState());

// 创建密钥
client.createKey("order-key");

// 加密
EncryptResponse enc = client.encrypt("order-key", "hello world".getBytes());
String ciphertext = enc.getCiphertext();

// 解密
DecryptResponse dec = client.decrypt("order-key", ciphertext);
System.out.println("Decrypted: " + new String(dec.getPlaintext()));
```

## API 方法

### 系统

| 方法 | 说明 |
|---|---|
| `health()` | 健康检查 |

### 密钥管理

| 方法 | 说明 |
|---|---|
| `createKey(keyId)` | 创建对称密钥 |
| `createAsymmetricKey(keyId, keyType)` | 创建非对称密钥（RSA/ECDSA/SM2） |
| `rotateKey(keyId)` | 轮转密钥 |
| `shredKey(keyId, version)` | 物理粉碎密钥 |
| `softDeleteKey(keyId, version)` | 软删除 |
| `restoreKey(keyId, version)` | 恢复 |
| `getPublicKey(keyId)` | 获取公钥 |
| `generateDataKey(keyId)` | 生成数据密钥 |
| `generateDataKeyWithoutPlaintext(keyId)` | 生成无明文 DEK |

### 密码运算

| 方法 | 说明 |
|---|---|
| `encrypt(keyId, plaintext)` | 信封加密 |
| `decrypt(keyId, ciphertext)` | 信封解密 |
| `sign(keyId, data)` | 非对称签名 |
| `verify(keyId, data, signature)` | 验签 |
| `generateMac(keyId, data)` | HMAC 生成 |
| `verifyMac(keyId, data, mac)` | HMAC 验证 |
| `reEncrypt(sourceKeyId, destKeyId, ciphertext)` | KMS 内重加密 |

### BYOK

| 方法 | 说明 |
|---|---|
| `transitPub()` | 获取传输公钥 |
| `importKey(keyId, transitKeyId, wrappedMaterial)` | 导入外部密钥 |

### MFA (v1.3)

| 方法 | 说明 |
|---|---|
| `mfaSetup(roleId)` | MFA TOTP 注册 |
| `mfaVerify(roleId, code)` | MFA 验证 + 启用 |
| `mfaDisable(roleId, code)` | 禁用 MFA |

### Quorum Approval (v1.3)

| 方法 | 说明 |
|---|---|
| `createApproval(operation, keyId, required, ttlHours)` | 创建审批 ticket |
| `getApproval(ticketId)` | 查询 ticket |
| `listApprovals()` | 列出 pending |
| `approveTicket(ticketId)` | 审批通过 |
| `rejectTicket(ticketId)` | 审批拒绝 |

### 审计

| 方法 | 说明 |
|---|---|
| `auditQuery(limit, filters)` | 查询审计日志 |

## 配置

```java
YvonneClient client = YvonneClient.builder()
    .baseUrl("https://kms.internal:8200")
    .token("admin-token")
    .timeout(30, TimeUnit.SECONDS)
    .retry(3)                    // 重试次数
    .retryBackoff(1, TimeUnit.SECONDS)  // 重试退避
    .circuitBreaker(10, 60)      // 熔断：10 次失败后熔断 60 秒
    .traceIdHeader("X-Request-ID") // trace_id 透传
    .build();
```

## 状态

当前为接口定义 + 文档，实际 Java 实现待生成。可用 Python SDK 或 Go SDK 替代。
