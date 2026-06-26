# Yvonne KMS SDK

Yvonne KMS 官方 SDK，提供类型安全的 API 客户端封装。

## Go SDK

### 安装

```bash
go get yvonne/sdk/go/yvonne
```

### 快速开始

```go
package main

import (
    "context"
    "fmt"
    "log"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8400", "your-app-role-token")
    ctx := context.Background()

    // 1. 健康检查
    health, err := client.Health(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("State: %s\n", health.State)

    // 2. 创建密钥
    createResp, err := client.CreateKey(ctx, &yvonne.CreateKeyRequest{
        KeyID: "order-key",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created: %s v%d\n", createResp.KeyID, createResp.Version)

    // 3. 加密
    encResp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID:     "order-key",
        Plaintext: []byte("order-12345"),
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: v%d, %d bytes\n", encResp.Version, len(encResp.Ciphertext))

    // 4. 解密
    decResp, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
        KeyID:      "order-key",
        Ciphertext: encResp.Ciphertext,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", string(decResp.Plaintext))

    // 5. 轮转
    rotResp, err := client.RotateKey(ctx, "order-key")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Rotated to v%d\n", rotResp.Version)

    // 6. 旧密文仍可解密（向后兼容）
    decOld, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
        KeyID:      "order-key",
        Ciphertext: encResp.Ciphertext,
    })
    fmt.Printf("v1 still decrypts: %s\n", string(decOld.Plaintext))
}
```

### API 方法

| 方法 | 说明 |
|---|---|
| `Health(ctx)` | 健康检查（无需认证） |
| `CreateKey(ctx, req)` | 创建密钥 |
| `RotateKey(ctx, keyID)` | 轮转密钥 |
| `ShredKey(ctx, keyID, version)` | 物理粉碎 |
| `Encrypt(ctx, req)` | 加密 |
| `Decrypt(ctx, req)` | 解密（向后兼容） |
| `GenerateDataKey(ctx, keyID)` | 生成数据密钥（GDK） |

### 错误处理

SDK 返回的 error 包含 HTTP 状态码和服务器错误消息：

```go
resp, err := client.Encrypt(ctx, req)
if err != nil {
    // err = "yvonne: HTTP 403: resource access denied"
    log.Fatal(err)
}
```

## OpenAPI Spec

完整的 OpenAPI 3.0 规范位于 `docs/openapi.yaml`，可用于：

- 生成其他语言 SDK（Python / Java / TypeScript / Rust）
- Swagger UI 在线文档
- Postman / Insomnia 集合导入

### 生成 Python SDK

```bash
# 安装 openapi-generator
npm install @openapitools/openapi-generator-cli -g

# 生成 Python SDK
openapi-generator-cli generate \
  -i docs/openapi.yaml \
  -g python \
  -o sdk/python
```

### 生成 TypeScript SDK

```bash
openapi-generator-cli generate \
  -i docs/openapi.yaml \
  -g typescript-fetch \
  -o sdk/typescript
```

### Swagger UI

```bash
# Docker 启动 Swagger UI
docker run -p 8080:8080 -e SWAGGER_JSON=/docs/openapi.yaml \
  -v $(pwd)/docs/openapi.yaml:/docs/openapi.yaml \
  swaggerapi/swagger-ui
```

访问 http://localhost:8080 查看交互式 API 文档。
