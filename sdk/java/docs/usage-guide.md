# Yvonne KMS Java SDK 使用文档

> 版本：v1.3.0 | 日期：2026-06-30

## 一、安装

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

### 源码编译

```bash
cd sdk/java
mvn clean install
```

## 二、快速开始

```java
import io.yvonne.kms.YvonneClient;
import io.yvonne.kms.YvonneException;
import com.google.gson.JsonObject;

public class QuickStart {
    public static void main(String[] args) {
        // 创建客户端（Dev 模式无需 token）
        YvonneClient client = YvonneClient.builder()
            .baseUrl("http://127.0.0.1:8200")
            .build();

        // 健康检查
        JsonObject health = client.health();
        System.out.println("State: " + health.getAsJsonObject("data").get("state"));

        // 创建密钥
        client.createKey("order-key");

        // 加密
        JsonObject enc = client.encrypt("order-key", "hello world".getBytes());
        String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();
        System.out.println("Ciphertext: " + ciphertext);

        // 解密
        JsonObject dec = client.decrypt("order-key", ciphertext);
        String plaintext = dec.getAsJsonObject("data").get("plaintext").getAsString();
        System.out.println("Decrypted: " + new String(Base64.getDecoder().decode(plaintext)));
    }
}
```

## 三、客户端配置

### 3.1 完整配置

```java
YvonneClient client = YvonneClient.builder()
    .baseUrl("https://kms.internal:8200")
    .token("your-admin-token")           // Bearer Token
    .timeout(Duration.ofSeconds(30))         // 请求超时
    .retry(RetryConfig.defaultConfig())      // 重试（3 次 + 指数退避）
    .circuitBreaker(CircuitBreaker.defaultBreaker()) // 熔断器（10 次失败 + 60s 恢复）
    .traceIdHeader("X-Request-ID")           // trace_id 透传
    .build();
```

### 3.2 重试配置

```java
RetryConfig retry = new RetryConfig(
    5,                          // maxRetries: 最大重试次数
    Duration.ofMillis(200),     // initialBackoff: 初始退避
    Duration.ofSeconds(10),     // maxBackoff: 最大退避
    Set.of(502, 503, 504)       // retryableStatusCodes: 可重试状态码
);
```

重试策略：
- 指数退避：`initialBackoff * 2^(attempt-1)`
- ±20% 抖动防惊群
- 超过 maxBackoff 后不再增长
- 网络错误（IOException）自动重试

### 3.3 熔断器配置

```java
CircuitBreaker cb = new CircuitBreaker(
    5,                          // failureThreshold: 连续失败阈值
    Duration.ofSeconds(30)      // resetTimeout: 熔断恢复时间
);
```

状态机：
```
CLOSED（正常）→ 连续失败达阈值 → OPEN（熔断）
                                    ↓ 等待 resetTimeout
                              HALF_OPEN（半开，允许一次试探）
                                    ↓ 成功 → CLOSED
                                    ↓ 失败 → OPEN
```

### 3.4 trace_id 透传

```java
YvonneClient client = YvonneClient.builder()
    .baseUrl("https://kms.internal:8200")
    .traceIdHeader("X-Request-ID")
    .build();

// 每个请求自动生成 32 字符 hex trace_id 并注入 header
// 服务端可通过 header 追踪请求链路
```

## 四、API 方法

### 4.1 系统管理

```java
// 健康检查
JsonObject health = client.health();
// {"ok":true,"data":{"sealed":false,"state":"unsealed","status":"alive"}}
```

### 4.2 密钥管理

```java
// 创建对称密钥
client.createKey("order-key");

// 创建非对称密钥（RSA-4096）
JsonObject rsa = client.createAsymmetricKey("signing-key", "rsa");
String publicKey = rsa.getAsJsonObject("data").get("public_key").getAsString();

// 创建非对称密钥（ECDSA P-256）
client.createAsymmetricKey("ecdsa-key", "ecdsa");

// 创建非对称密钥（SM2，需 -tags gmsm）
client.createAsymmetricKey("sm2-key", "sm2");

// 轮转密钥
JsonObject rotated = client.rotateKey("order-key");
int newVersion = rotated.getAsJsonObject("data").get("version").getAsInt();

// 物理粉碎密钥
client.shredKey("order-key", 1);

// 获取公钥
JsonObject pub = client.getPublicKey("signing-key");

// 生成数据密钥（GDK）
JsonObject gdk = client.generateDataKey("order-key");
String plaintextDek = gdk.getAsJsonObject("data").get("plaintext_dek").getAsString();
String ciphertextDek = gdk.getAsJsonObject("data").get("ciphertext_dek").getAsString();

// 生成无明文 DEK（更安全）
JsonObject gdkNp = client.generateDataKeyWithoutPlaintext("order-key");
String ciphertextOnly = gdkNp.getAsJsonObject("data").get("ciphertext").getAsString();
```

### 4.3 密码运算

```java
// 信封加密
JsonObject enc = client.encrypt("order-key", "sensitive data".getBytes());
String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();

// 信封解密
JsonObject dec = client.decrypt("order-key", ciphertext);
byte[] plaintext = Base64.getDecoder().decode(
    dec.getAsJsonObject("data").get("plaintext").getAsString()
);

// 非对称签名
JsonObject sig = client.sign("signing-key", "data to sign".getBytes());
String signature = sig.getAsJsonObject("data").get("signature").getAsString();

// 验签
JsonObject verifyResult = client.verify("signing-key", "data to sign".getBytes(), signature);
boolean valid = verifyResult.getAsJsonObject("data").get("valid").getAsBoolean();

// HMAC 生成
JsonObject mac = client.generateMac("order-key", "data".getBytes());
String macValue = mac.getAsJsonObject("data").get("mac").getAsString();

// HMAC 验证
JsonObject macResult = client.verifyMac("order-key", "data".getBytes(), macValue);
boolean macValid = macResult.getAsJsonObject("data").get("valid").getAsBoolean();

// KMS 内重加密
JsonObject reEnc = client.reEncrypt("old-key", "new-key", ciphertext);
String newCiphertext = reEnc.getAsJsonObject("data").get("ciphertext").getAsString();
```

### 4.4 BYOK（自带密钥）

```java
// 获取传输公钥
JsonObject transit = client.transitPub();
String transitKey = transit.getAsJsonObject("data").get("transit_key_id").getAsString();
String pubPem = transit.getAsJsonObject("data").get("public_key").getAsString();

// 用公钥加密 DEK 后导入
// （需在外部用 RSA-OAEP 加密 DEK）
// String wrappedMaterial = ...; // RSA-OAEP 加密后的 DEK
// client.importKey("byok-key", transitKey, wrappedMaterial);
```

### 4.5 MFA（v1.3）

```java
// 注册 MFA TOTP
JsonObject setup = client.mfaSetup("admin");
String secret = setup.getAsJsonObject("data").get("secret").getAsString();
String qrUri = setup.getAsJsonObject("data").get("uri").getAsString();
// 用 Google Authenticator 扫描 qrUri

// 验证 TOTP code + 启用 MFA
client.mfaVerify("admin", "123456");

// 敏感操作需在 header 中携带 X-MFA-Code（通过自定义 HttpClient 实现）
```

### 4.6 Quorum 审批（v1.3）

```java
// 创建 2-of-3 审批 ticket
JsonObject ticket = client.createApproval("ShredKey", "order-key", 2, 24);
String ticketId = ticket.getAsJsonObject("data").get("id").getAsString();

// 审批通过
client.approveTicket(ticketId);

// 审批拒绝
client.rejectTicket(ticketId);

// 列出 pending
JsonObject pending = client.listApprovals();
int count = pending.getAsJsonObject("data").get("count").getAsInt();
```

### 4.7 审计

```java
// 查询审计日志
JsonObject audit = client.auditQuery(100);
// {"ok":true,"data":{"count":5,"entries":[...]}}
```

## 五、错误处理

```java
try {
    client.encrypt("nonexistent-key", "data".getBytes());
} catch (YvonneException e) {
    int statusCode = e.getStatusCode();
    String message = e.getMessage();
    System.err.println("Error " + statusCode + ": " + message);
}
```

常见错误码：
| 状态码 | 说明 |
|---|---|
| 400 | 请求参数错误 |
| 401 | 未认证（无 token 或 token 无效） |
| 403 | 越权（RBAC 拒绝） |
| 404 | 密钥不存在 |
| 503 | 服务不可用（sealed 或熔断） |

## 六、完整示例

```java
import io.yvonne.kms.*;
import com.google.gson.JsonObject;
import java.time.Duration;
import java.util.Base64;

public class FullExample {
    public static void main(String[] args) {
        // 1. 创建带完整配置的客户端
        YvonneClient client = YvonneClient.builder()
            .baseUrl("https://kms.internal:8200")
            .token("your-admin-token")
            .timeout(Duration.ofSeconds(30))
            .retry(RetryConfig.defaultConfig())
            .circuitBreaker(CircuitBreaker.defaultBreaker())
            .traceIdHeader("X-Request-ID")
            .build();

        // 2. 健康检查
        JsonObject health = client.health();
        System.out.println("KMS State: " + health.getAsJsonObject("data").get("state"));

        // 3. 创建密钥
        client.createKey("order-service-key");

        // 4. 加密业务数据
        JsonObject enc = client.encrypt("order-service-key", "order-12345".getBytes());
        String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();
        System.out.println("Encrypted order: " + ciphertext);

        // 5. 解密
        JsonObject dec = client.decrypt("order-service-key", ciphertext);
        byte[] plaintext = Base64.getDecoder().decode(
            dec.getAsJsonObject("data").get("plaintext").getAsString()
        );
        System.out.println("Decrypted: " + new String(plaintext));

        // 6. 生成 HMAC 签名
        JsonObject mac = client.generateMac("order-service-key", "order-12345".getBytes());
        System.out.println("MAC: " + mac.getAsJsonObject("data").get("mac").getAsString());

        // 7. 轮转密钥
        client.rotateKey("order-service-key");
        System.out.println("Key rotated to v2");

        // 8. 解密旧密文（向后兼容）
        JsonObject decOld = client.decrypt("order-service-key", ciphertext);
        System.out.println("Old ciphertext still decrypts: " +
            new String(Base64.getDecoder().decode(
                decOld.getAsJsonObject("data").get("plaintext").getAsString()
            ))
        );

        System.out.println("\n✅ Full example completed!");
    }
}
```

## 七、线程安全

`YvonneClient` 是线程安全的，可在多线程环境中共享单个实例。内部 `HttpClient` 和熔断器状态均为线程安全实现。

## 八、依赖

| 依赖 | 版本 | 说明 |
|---|---|---|
| Java | 17+ | 使用 java.net.http.HttpClient |
| Gson | 2.11.0 | JSON 序列化/反序列化 |
| JUnit 5 | 5.10.2 | 测试（仅 test scope） |
