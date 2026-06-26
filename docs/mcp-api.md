# Yvonne KMS MCP 使用文档

> 版本：0.4.0 | 协议：Model Context Protocol | SDK：go-sdk v1.6.1

Yvonne KMS 提供 MCP（Model Context Protocol）server，让 AI agent 安全地使用 KMS 加解密能力。仅暴露 Encrypt + 受限 Decrypt 两个 Tool，强制 token 鉴权 + key 白名单。

## 目录

- [设计原则](#设计原则)
- [快速开始](#快速开始)
- [传输方式](#传输方式)
- [Tools 一览](#tools-一览)
- [鉴权](#鉴权)
- [安全约束](#安全约束)
- [客户端配置](#客户端配置)
- [配置参考](#配置参考)
- [FAQ](#faq)

## 设计原则

MCP 集成遵循**最小暴露面**原则：

1. **只暴露必要操作**：仅 `encrypt` + 受限 `decrypt`，不暴露建密钥/轮转/粉碎/紧急封印等管理操作
2. **独立鉴权**：MCP 专用 `mcp_token`（非主 API Token），ConstantTimeCompare 防计时攻击
3. **Decrypt 白名单**：仅允许解密配置的 `allowed_keys` 中的密钥，防止 AI 解密任意数据
4. **全量审计**：每次 MCP 调用都记录审计日志（Actor=`mcp-agent`）
5. **Sealed 拒绝**：Vault Sealed 时所有 MCP 调用失败

## 快速开始

### 1. 配置 MCP server

`config.json`：
```json
{
  "mode": "dev",
  "server": {
    "mcp": {
      "enabled": true,
      "http_bind_addr": "127.0.0.1",
      "http_bind_port": 8252,
      "token": "your-secret-mcp-token",
      "allowed_keys": ["ai-encrypt-key", "ai-decrypt-key"]
    }
  }
}
```

启动：
```bash
yvonne server --config config.json
# 输出：yvonne MCP HTTP listening on 127.0.0.1:8252
```

### 2. 创建 AI 专用密钥

通过 HTTP API 创建 `ai-encrypt-key`（MCP 不暴露建密钥操作）：
```bash
curl -X POST http://127.0.0.1:8400/api/v1/keys \
  -H "Authorization: Bearer your-admin-token" \
  -d '{"key_id": "ai-encrypt-key"}'
```

### 3. 配置 AI agent

以 Claude Desktop 为例，`claude_desktop_config.json`：
```json
{
  "mcpServers": {
    "yvonne-kms": {
      "url": "http://127.0.0.1:8252/mcp",
      "headers": {
        "X-MCP-Token": "your-secret-mcp-token"
      }
    }
  }
}
```

### 4. AI 调用示例

AI agent 可调用：
```
用户：帮我加密这段数据 "customer-email@example.com"
AI：[调用 yvonne_encrypt tool]
    → key_id: "ai-encrypt-key"
    → plaintext: base64("customer-email@example.com")
    → 返回密文: "AQAA..."
    
AI：已加密，密文为 AQAA...（v1）

用户：解密这个密文
AI：[调用 yvonne_decrypt tool]
    → key_id: "ai-decrypt-key"  ← 必须在 allowed_keys 中
    → ciphertext: "AQAA..."
    → 返回明文: "customer-email@example.com"
```

## 传输方式

### Streamable HTTP（推荐，多客户端）

Yvonne 主进程同时监听 MCP HTTP 端点（`/mcp`），支持多 AI agent 并发连接。

```
POST http://127.0.0.1:8252/mcp
Content-Type: application/json

{"jsonrpc":"2.0","method":"tools/list","id":1}
```

配置：
```json
{
  "mcp": {
    "enabled": true,
    "http_bind_addr": "127.0.0.1",
    "http_bind_port": 8252,
    "stdio": false
  }
}
```

### stdio（单客户端，子进程模式）

AI agent 作为父进程启动 Yvonne MCP server，通过 stdin/stdout 通信。

配置：
```json
{
  "mcp": {
    "enabled": true,
    "stdio": true
  }
}
```

Claude Desktop 配置（stdio）：
```json
{
  "mcpServers": {
    "yvonne-kms": {
      "command": "yvonne",
      "args": ["mcp-serve", "--config", "/etc/yvonne/config.json"],
      "env": {
        "YVONNE_MCP_TOKEN": "your-secret-mcp-token"
      }
    }
  }
}
```

> **注意**：stdio 模式当前与主 `yvonne server` 命令集成（通过配置 `mcp.stdio=true`）。独立 `mcp-serve` 子命令将在后续版本支持。

### 两者都支持

可同时启用 stdio + HTTP：
```json
{
  "mcp": {
    "enabled": true,
    "stdio": true,
    "http_bind_addr": "127.0.0.1",
    "http_bind_port": 8252
  }
}
```

## Tools 一览

### yvonne_encrypt

加密数据。

**参数**：
```json
{
  "key_id": "ai-encrypt-key",
  "plaintext": "base64-encoded-plaintext"
}
```

**返回**（成功）：
```json
{
  "content": [
    {"type": "text", "text": "AQAA...base64-ciphertext..."}
  ]
}
```

**返回**（失败）：
```json
{
  "content": [
    {"type": "text", "text": "ERROR: encrypt failed: <reason>"}
  ],
  "isError": true
}
```

**授权**：
- MCP token 必须正确
- `key_id` 必须在 `allowed_keys` 白名单中
- Vault 必须 Unsealed

**审计**：记录 `Action=Encrypt, Actor=mcp-agent, Resource=<key_id>`

### yvonne_decrypt

解密数据（受限）。

**参数**：
```json
{
  "key_id": "ai-decrypt-key",
  "ciphertext": "base64-encoded-ciphertext"
}
```

**返回**（成功）：
```json
{
  "content": [
    {"type": "text", "text": "base64-encoded-plaintext"}
  ]
}
```

**授权**：
- MCP token 必须正确
- `key_id` 必须在 `allowed_keys` 白名单中（**强制，不可绕过**）
- Vault 必须 Unsealed

**审计**：记录 `Action=Decrypt, Actor=mcp-agent, Resource=<key_id>`

**向后兼容**：密文版本前缀自动路由（Active/Deactivated 可解，Destroyed 拒绝）。

## 鉴权

### MCP Token

MCP 使用独立 `mcp_token`（与 HTTP/gRPC 的 AppRole/JWT Token 隔离），通过 `CallToolRequest.Params.Meta["mcp_token"]` 传递。

**安全特性**：
- `crypto/subtle.ConstantTimeCompare`（防计时攻击）
- 未配置 token 时拒绝所有调用
- Token 不匹配返回 `ERROR: unauthorized`（不暴露具体原因）

### 配置

```json
{
  "mcp": {
    "token": "your-secret-mcp-token-32-bytes-minimum",
    "allowed_keys": ["ai-encrypt-key", "ai-decrypt-key"]
  }
}
```

**建议**：
- Token 至少 32 字节随机串
- 定期轮转（通过配置 reload）
- 不同环境用不同 Token

## 安全约束

### Decrypt 白名单强制

MCP Decrypt 强制校验 `allowed_keys`，即使 AI agent 传入其他 key_id 也拒绝：

```go
// 内部逻辑（internal/mcp/server.go）
if !s.isKeyAllowed(args.KeyID) {
    return errorResult("key not in MCP whitelist"), nil, nil
}
```

**配置示例**：
```json
{
  "allowed_keys": ["ai-decrypt-key"]
}
```

- `ai-decrypt-key` ✅ 允许
- `payment-key` ❌ 拒绝（不在白名单）
- `*` ✅ 通配符（允许所有，**不推荐生产使用**）

### 不暴露的操作

以下操作**绝不暴露给 AI agent**：

| 操作 | 原因 |
|---|---|
| `EmergencySeal` | AI 可触发 DoS，brick 整个 vault |
| `Unseal` | 需人工 Shamir 仪式 |
| `CreateKey` | 防止 AI 创建未授权密钥 |
| `RotateKey` | 防止 AI 频繁轮转影响业务 |
| `ShredKey` | 防止 AI 物理销毁密钥（不可逆） |
| `SoftDeleteKey` | 防止 AI 隐藏数据 |
| `RestoreKey` | 防止 AI 恢复已删除的敏感数据 |
| `ImportKey` | 防止 AI 注入外部密钥 |
| `AuditQuery` | 审计日志含敏感操作历史 |

### 审计

每次 MCP 调用都记录到审计日志：

```
2026-06-26T10:30:00Z | MCPDecrypt | mcp-agent | ai-decrypt-key | v1 | success
2026-06-26T10:31:00Z | MCPEncrypt | mcp-agent | ai-encrypt-key | v1 | success
2026-06-26T10:32:00Z | MCPEncrypt | mcp-agent | payment-key   |    | error: key not in whitelist
```

审计日志不可篡改（HMAC 链式签名），可用于事后追溯 AI 行为。

### Sealed 拒绝

Vault Sealed/EmergencySealed 时，MCP 调用返回错误：
```
ERROR: encrypt failed: service: vault is sealed
```

AI agent 应捕获此错误并提示用户执行 Unseal 仪式。

## 客户端配置

### Claude Desktop（Streamable HTTP）

`~/Library/Application Support/Claude/claude_desktop_config.json`：
```json
{
  "mcpServers": {
    "yvonne-kms": {
      "url": "http://127.0.0.1:8252/mcp",
      "headers": {
        "X-MCP-Token": "your-secret-mcp-token"
      }
    }
  }
}
```

### Claude Desktop（stdio）

```json
{
  "mcpServers": {
    "yvonne-kms": {
      "command": "yvonne",
      "args": ["server", "--config", "/etc/yvonne/config.json"],
      "env": {
        "YVONNE_MCP_STDIO": "1"
      }
    }
  }
}
```

### 自定义 MCP 客户端（Go）

```go
package main

import (
    "context"
    "log"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    client := mcp.NewClient(&mcp.Implementation{
        Name:    "my-ai-agent",
        Version: "1.0.0",
    }, nil)

    // Streamable HTTP
    transport := mcp.NewStreamableHTTPTransport("http://127.0.0.1:8252/mcp")
    session, err := client.Connect(context.Background(), transport, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer session.Close()

    // List tools
    tools, _ := session.ListTools(context.Background(), nil)
    for _, tool := range tools.Tools {
        log.Printf("Tool: %s - %s", tool.Name, tool.Description)
    }

    // Call encrypt
    result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
        Name: "yvonne_encrypt",
        Arguments: map[string]any{
            "key_id":    "ai-encrypt-key",
            "plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Result: %+v", result)
}
```

## 配置参考

### 完整 MCP 配置

```json
{
  "server": {
    "mcp": {
      "enabled": true,
      "stdio": false,
      "http_bind_addr": "127.0.0.1",
      "http_bind_port": 8252,
      "token": "your-32-byte-secret-mcp-token",
      "allowed_keys": [
        "ai-encrypt-key",
        "ai-decrypt-key"
      ]
    }
  }
}
```

### 生产环境配置

```json
{
  "mode": "cluster",
  "server": {
    "mcp": {
      "enabled": true,
      "stdio": false,
      "http_bind_addr": "127.0.0.1",
      "http_bind_port": 8252,
      "token": "${YVONNE_MCP_TOKEN}",
      "allowed_keys": ["ai-prod-key-1", "ai-prod-key-2"]
    }
  }
}
```

**生产建议**：
- `bind_addr` 必须 `127.0.0.1`（反向代理 + mTLS 暴露）
- `token` 从环境变量注入，不硬编码
- `allowed_keys` 明确列出，不用 `*`
- 配合反向代理加 IP 白名单

### 最小配置（Dev 模式）

```json
{
  "mode": "dev",
  "server": {
    "mcp": {
      "enabled": true,
      "http_bind_addr": "127.0.0.1",
      "http_bind_port": 8252,
      "token": "dev-token",
      "allowed_keys": ["*"]
    }
  }
}
```

## FAQ

### Q: MCP 和 gRPC 有什么区别？

| 维度 | gRPC | MCP |
|---|---|---|
| 目标受众 | 后端微服务 | AI agent |
| 暴露面 | 全量 14 个端点 | 仅 Encrypt + 受限 Decrypt |
| 认证 | 复用 AppRole/JWT | 独立 MCP Token |
| 协议 | HTTP/2 + protobuf | JSON-RPC |
| 鉴权粒度 | Policy（action + key） | Token + key 白名单 |

### Q: AI agent 能解密任意数据吗？

**不能**。Decrypt 强制校验 `allowed_keys` 白名单。即使 AI 拿到其他 key 的密文，也无法通过 MCP 解密（需白名单内的 key_id）。

### Q: MCP Token 泄漏了怎么办？

1. 立即修改配置中的 `mcp.token`
2. 重启 Yvonne（或 reload 配置）
3. 审查审计日志中 `Actor=mcp-agent` 的调用记录
4. 如有可疑解密，轮转相关密钥（`allowed_keys` 中的 key）

### Q: 能限制 AI 只加密不解密吗？

可以。`allowed_keys` 只配加密用的 key，不配解密用的 key：

```json
{
  "allowed_keys": ["ai-encrypt-only"]
}
```

此时 `yvonne_decrypt` 对任何 key 都返回 `key not in MCP whitelist`。

### Q: stdio 和 HTTP 能同时用吗？

可以。配置 `stdio: true` + `http_bind_port: 8252`，两种传输共享同一 MCP server。

### Q: 如何审计 AI 的操作？

```bash
# 查询 MCP 相关审计日志
curl -X POST http://127.0.0.1:8400/api/v1/audit/query \
  -H "Authorization: Bearer admin-token" \
  -d '{"actor": "mcp-agent", "limit": 100}'
```

所有 MCP 调用的 `Actor` 字段为 `mcp-agent`，可按此过滤。

### Q: 多个 AI agent 能同时连接吗？

- **Streamable HTTP**：支持多客户端并发
- **stdio**：单客户端（子进程模式），每个 AI agent 启动独立 Yvonne 进程

生产环境推荐 HTTP 模式。

## 相关文档

- [gRPC API 文档](grpc-api.md)
- [HTTP API 文档](api.md)
- [配置参考](../README.md#配置)
- [安全模型](../SECURITY.md)
