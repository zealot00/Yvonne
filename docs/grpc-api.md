# Yvonne KMS gRPC API 使用文档

> 版本：0.4.0 | 协议：gRPC over HTTP/2 | 默认端口：8251

Yvonne KMS 提供完整的 gRPC API，与 HTTP REST API 功能等价（全量镜像 14 个端点）。gRPC 适合高性能内网调用、强类型客户端、流式扩展场景。

## 目录

- [快速开始](#快速开始)
- [服务定义](#服务定义)
- [认证](#认证)
- [端点详解](#端点详解)
- [错误码](#错误码)
- [客户端示例](#客户端示例)
- [配置参考](#配置参考)

## 快速开始

### 1. 启动 gRPC server

`config.json`：
```json
{
  "mode": "dev",
  "server": {
    "grpc": {
      "enabled": true,
      "bind_addr": "127.0.0.1",
      "bind_port": 8251
    }
  }
}
```

```bash
yvonne server --config config.json
# 输出：yvonne gRPC listening on 127.0.0.1:8251
```

### 2. 生成客户端代码

```bash
# 从 .proto 生成（Go）
make proto

# 其他语言：用 protoc 生成
protoc --proto_path=proto \
  --go_out=. --go-grpc_out=. \
  proto/yvonne/v1/yvonne.proto
```

### 3. 最小客户端

```go
package main

import (
    "context"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    pb "yvonne/gen/proto/yvonne/v1"
)

func main() {
    conn, err := grpc.NewClient("127.0.0.1:8251",
        grpc.WithTransportCredentials(insecure.NewCredentials()), // 生产用 TLS
        grpc.WithUnaryInterceptor(tokenInterceptor("your-token")),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewYvonneServiceClient(conn)

    // Encrypt
    resp, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
        KeyId:     "order-key",
        Plaintext: []byte("hello gRPC"),
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("ciphertext version: %d, %d bytes", resp.Version, len(resp.Ciphertext))
}
```

## 服务定义

### proto 文件位置

```
proto/yvonne/v1/yvonne.proto
```

### 服务方法一览

| 方法 | 请求 | 响应 | 认证 | Sealed 拦截 |
|---|---|---|---|---|
| `Health` | `HealthRequest` | `HealthResponse` | 豁免 | 豁免 |
| `Unseal` | `UnsealRequest` | `UnsealResponse` | 需要 | 豁免 |
| `EmergencySeal` | `EmergencySealRequest` | `EmergencySealResponse` | admin token | 豁免 |
| `CreateKey` | `CreateKeyRequest` | `CreateKeyResponse` | 需要 | 拦截 |
| `RotateKey` | `RotateKeyRequest` | `RotateKeyResponse` | 需要 | 拦截 |
| `ShredKey` | `ShredKeyRequest` | `ShredKeyResponse` | 需要 | 拦截 |
| `SoftDeleteKey` | `SoftDeleteKeyRequest` | `SoftDeleteKeyResponse` | 需要 | 拦截 |
| `RestoreKey` | `RestoreKeyRequest` | `RestoreKeyResponse` | 需要 | 拦截 |
| `GenerateDataKey` | `GenerateDataKeyRequest` | `GenerateDataKeyResponse` | 需要 | 拦截 |
| `TransitPub` | `TransitPubRequest` | `TransitPubResponse` | 需要 | 拦截 |
| `ImportKey` | `ImportKeyRequest` | `ImportKeyResponse` | 需要 | 拦截 |
| `AuditQuery` | `AuditQueryRequest` | `AuditQueryResponse` | 需要 | 拦截 |
| `Encrypt` | `EncryptRequest` | `EncryptResponse` | 需要 | 拦截 |
| `Decrypt` | `DecryptRequest` | `DecryptResponse` | 需要 | 拦截 |

> **注意**：`Unseal` 和 `TransitPub`/`ImportKey`/`AuditQuery` 当前返回 `Unimplemented` 错误，请通过 HTTP API 调用。后续版本会补全。

## 认证

### Bearer Token（metadata）

gRPC 认证通过 metadata `authorization: Bearer <token>` 传递，复用 HTTP API 的 `Authenticator` 接口（AppRole 或 JWT）。

### 客户端拦截器示例

```go
func tokenInterceptor(token string) grpc.UnaryClientInterceptor {
    return func(ctx context.Context, method string, req, reply interface{},
        cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
        ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
        return invoker(ctx, method, req, reply, cc, opts...)
    }
}
```

### Dev 模式

Dev 模式下 `authenticator = nil`，跳过认证（所有请求放行）。仅限 `127.0.0.1` 调试。

### Cluster 模式

Cluster 模式强制认证，Token 来自 `auth.app_roles[].token` 或 `auth.jwt` 配置。Policy 的 `AllowedActions` + `AllowedKeys` 做资源级授权。

## 端点详解

### Health（健康检查）

```protobuf
rpc Health(HealthRequest) returns (HealthResponse);

message HealthResponse {
  string state = 1;              // "sealed" | "unsealed" | "emergency_sealed"
  bool emergency_sealed = 2;
  int64 uptime_seconds = 3;
}
```

**无需认证**，可用于负载均衡探活。

**示例**：
```go
resp, _ := client.Health(ctx, &pb.HealthRequest{})
// resp.State == "unsealed"
```

### Encrypt（加密）

```protobuf
rpc Encrypt(EncryptRequest) returns (EncryptResponse);

message EncryptRequest {
  string key_id = 1;
  bytes plaintext = 2;           // 原始明文（非 base64）
}
message EncryptResponse {
  bytes ciphertext = 1;          // 版本化密文（含 4 字节版本前缀）
  int32 version = 2;
}
```

**授权**：Policy 需 `AllowedActions: ["Encrypt"]` + `AllowedKeys` 包含 `key_id`。

**示例**：
```go
resp, err := client.Encrypt(ctx, &pb.EncryptRequest{
    KeyId:     "order-key",
    Plaintext: []byte("sensitive data"),
})
// resp.Ciphertext: 4字节版本 + 12字节nonce + 密文 + 16字节tag
// resp.Version: 1
```

### Decrypt（解密）

```protobuf
rpc Decrypt(DecryptRequest) returns (DecryptResponse);

message DecryptRequest {
  string key_id = 1;
  bytes ciphertext = 2;          // 版本化密文
}
message DecryptResponse {
  bytes plaintext = 1;           // 原始明文
  int32 version = 2;
}
```

**授权**：Policy 需 `AllowedActions: ["Decrypt"]` + `AllowedKeys` 包含 `key_id`。

**向后兼容**：密文版本前缀自动路由到对应版本的 DEK（Active/Deactivated 均可解密，Destroyed 拒绝）。

### CreateKey（创建密钥）

```protobuf
rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);

message CreateKeyRequest {
  string key_id = 1;
  int32 rotation_period_days = 2;
  bool return_dek = 3;           // false 时不返回明文 DEK
}
message CreateKeyResponse {
  string key_id = 1;
  int32 version = 2;
  bytes plaintext_dek = 3;       // base64 明文 DEK（return_dek=false 时为空）
}
```

**授权**：Policy 需 `AllowedActions: ["CreateKey"]`。

### RotateKey（轮转密钥）

```protobuf
rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);

message RotateKeyResponse {
  string key_id = 1;
  int32 new_version = 2;
  bytes plaintext_dek = 3;
}
```

**授权**：Policy 需 `AllowedActions: ["KeyOp"]` + `AllowedKeys` 包含 `key_id`。

### ShredKey（物理粉碎）

```protobuf
rpc ShredKey(ShredKeyRequest) returns (ShredKeyResponse);

message ShredKeyRequest {
  string key_id = 1;
  int32 version = 2;
}
```

**授权**：Policy 需 `AllowedActions: ["KeyOp"]`。

**后果**：版本物理删除，对应密文永久不可解密（crypto-shredding）。

### GenerateDataKey（数据密钥）

```protobuf
rpc GenerateDataKey(GenerateDataKeyRequest) returns (GenerateDataKeyResponse);

message GenerateDataKeyResponse {
  bytes plaintext_dek = 1;       // 明文 DEK
  bytes ciphertext_dek = 2;      // 密文 DEK（含版本前缀，可离线解密）
}
```

**授权**：Policy 需 `AllowedActions: ["KeyOp"]`。

### EmergencySeal（紧急封印）

```protobuf
rpc EmergencySeal(EmergencySealRequest) returns (EmergencySealResponse);

message EmergencySealRequest {
  string admin_token = 1;
  bool confirm = 2;
}
```

**特殊**：需 `admin_token`（非 Policy 认证），通过拦截器单独校验。触发后 MasterKey + DEK 缓存全部 Wipe，不可逆。

## 错误码

| gRPC Code | HTTP 等价 | 含义 |
|---|---|---|
| `Unauthenticated` | 401 | Token 缺失/无效/过期 |
| `PermissionDenied` | 403 | Policy 不允许此 action 或 key |
| `Unavailable` | 503 | Vault Sealed 或 EmergencySealed |
| `NotFound` | 404 | KeyID/版本不存在 |
| `FailedPrecondition` | 400 | 密钥状态不允许（如 Destroyed 解密）|
| `Internal` | 500 | 内部错误（panic 已 recover）|

## 客户端示例

### Go 完整示例

```go
package main

import (
    "context"
    "encoding/base64"
    "fmt"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/metadata"

    pb "yvonne/gen/proto/yvonne/v1"
)

func main() {
    conn, err := grpc.NewClient("127.0.0.1:8251",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewYvonneServiceClient(conn)
    ctx := metadata.AppendToOutgoingContext(context.Background(),
        "authorization", "Bearer your-app-role-token")

    // 1. 创建密钥
    createResp, err := client.CreateKey(ctx, &pb.CreateKeyRequest{
        KeyId:               "order-key",
        RotationPeriodDays: 30,
        ReturnDek:           false,
    })
    if err != nil {
        log.Fatalf("CreateKey: %v", err)
    }
    fmt.Printf("Created key %s v%d\n", createResp.KeyId, createResp.Version)

    // 2. 加密
    encResp, err := client.Encrypt(ctx, &pb.EncryptRequest{
        KeyId:     "order-key",
        Plaintext: []byte("order-12345"),
    })
    if err != nil {
        log.Fatalf("Encrypt: %v", err)
    }
    ctB64 := base64.StdEncoding.EncodeToString(encResp.Ciphertext)
    fmt.Printf("Encrypted: %s (v%d)\n", ctB64, encResp.Version)

    // 3. 解密
    decResp, err := client.Decrypt(ctx, &pb.DecryptRequest{
        KeyId:      "order-key",
        Ciphertext: encResp.Ciphertext,
    })
    if err != nil {
        log.Fatalf("Decrypt: %v", err)
    }
    fmt.Printf("Decrypted: %s\n", string(decResp.Plaintext))

    // 4. 轮转
    rotResp, err := client.RotateKey(ctx, &pb.RotateKeyRequest{
        KeyId:   "order-key",
        Version: int32(encResp.Version),
    })
    if err != nil {
        log.Fatalf("RotateKey: %v", err)
    }
    fmt.Printf("Rotated to v%d\n", rotResp.NewVersion)

    // 5. 旧密文仍可解密（向后兼容）
    decResp2, err := client.Decrypt(ctx, &pb.DecryptRequest{
        KeyId:      "order-key",
        Ciphertext: encResp.Ciphertext, // v1 密文
    })
    if err != nil {
        log.Fatalf("Decrypt v1 after rotate: %v", err)
    }
    fmt.Printf("v1 still decrypts: %s\n", string(decResp2.Plaintext))
}
```

### Python 示例

```python
import grpc
from yvonne.v1 import yvonne_pb2, yvonne_pb2_grpc

channel = grpc.insecure_channel('127.0.0.1:8251')
stub = yvonne_pb2_grpc.YvonneServiceStub(channel)

metadata = [('authorization', 'Bearer your-token')]

# 加密
resp = stub.Encrypt(
    yvonne_pb2.EncryptRequest(key_id='order-key', plaintext=b'hello'),
    metadata=metadata,
)
print(f"ciphertext: {resp.ciphertext.hex()}, version: {resp.version}")

# 解密
dec = stub.Decrypt(
    yvonne_pb2.DecryptRequest(key_id='order-key', ciphertext=resp.ciphertext),
    metadata=metadata,
)
print(f"plaintext: {dec.plaintext.decode()}")
```

## 配置参考

### 完整 gRPC 配置

```json
{
  "server": {
    "grpc": {
      "enabled": true,
      "bind_addr": "127.0.0.1",
      "bind_port": 8251,
      "tls": {
        "enabled": true,
        "cert_file": "/etc/yvonne/grpc.crt",
        "key_file": "/etc/yvonne/grpc.key",
        "min_version": "TLS1.3"
      }
    }
  }
}
```

### TLS 配置（生产强制）

生产环境必须启用 TLS：

```json
{
  "server": {
    "grpc": {
      "enabled": true,
      "bind_addr": "0.0.0.0",
      "bind_port": 8251,
      "tls": {
        "enabled": true,
        "cert_file": "/etc/yvonne/server.crt",
        "key_file": "/etc/yvonne/server.key",
        "min_version": "TLS1.3"
      }
    }
  }
}
```

客户端使用 TLS：
```go
creds, _ := credentials.NewClientTLSFromFile("/etc/yvonne/ca.crt", "")
conn, _ := grpc.NewClient("example.com:8251",
    grpc.WithTransportCredentials(creds),
)
```

### 拦截器链顺序

gRPC 请求经过的拦截器链（从外到内）：

```
1. panic recover（捕获 handler panic，返回 Internal）
2. 认证（从 metadata 取 Bearer Token，调 Authenticator）
3. Sealed 检查（EmergencySealed/Sealed 返回 Unavailable）
4. 业务 handler（调用 service.Core）
5. 审计（Core 内部 recordAudit）
```

## 健康检查

gRPC server 注册了标准 `grpc_health_v1` 健康检查服务：

```go
import "google.golang.org/grpc/health/grpc_health_v1"

resp, _ := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
    Service: "yvonne.v1.YvonneService",
})
// resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
```

## 与 HTTP API 对照

| 功能 | HTTP | gRPC |
|---|---|---|
| 认证 | `Authorization: Bearer` header | `authorization: Bearer` metadata |
| 加密 | `POST /api/v1/encrypt` | `Encrypt` rpc |
| 解密 | `POST /api/v1/decrypt` | `Decrypt` rpc |
| 建密钥 | `POST /api/v1/keys` | `CreateKey` rpc |
| 轮转 | `POST /api/v1/keys/{id}/rotate` | `RotateKey` rpc |
| 粉碎 | `DELETE /api/v1/keys/{id}/shred` | `ShredKey` rpc |
| 健康检查 | `GET /api/v1/sys/health` | `Health` rpc + grpc_health_v1 |

## 常见问题

### Q: gRPC 和 HTTP 能同时启用吗？

可以。Yvonne 支持三 server 并行（HTTP + gRPC + MCP），共享同一 `service.Core` 业务层。配置中分别设置 `server.enabled`（HTTP）和 `server.grpc.enabled`。

### Q: gRPC 调用被 Unavailable 拒绝？

检查 vault 状态：
```go
health, _ := client.Health(ctx, &pb.HealthRequest{})
// health.State == "sealed" → 需先 Unseal（通过 HTTP /api/v1/sys/unseal 或 Admin UI）
```

### Q: 如何选择 HTTP vs gRPC？

| 场景 | 推荐 |
|---|---|
| 后端微服务间调用 | gRPC（强类型 + 高性能） |
| CLI 工具 / 脚本 | HTTP（curl 友好） |
| 浏览器 / 移动端 | HTTP（gRPC-Web 需额外网关） |
| AI agent | MCP（专用协议） |
