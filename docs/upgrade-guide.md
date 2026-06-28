# Yvonne KMS 升级指南

> 版本：0.4.x → 1.0 → 1.1 | 最后更新：2026-06-28

本文档说明 Yvonne KMS 各版本间的升级路径、breaking changes、停服时间和回滚方案。

## 目录

- [升级路线图](#升级路线图)
- [Breaking Changes 矩阵](#breaking-changes-矩阵)
- [升级步骤](#升级步骤)
- [停服时间评估](#停服时间评估)
- [回滚方案](#回滚方案)
- [密文格式兼容性](#密文格式兼容性)
- [数据库 Schema 变更](#数据库-schema-变更)
- [mTLS 配置（v1.0 新增）](#mtls-配置v10-新增)
- [国密模式配置（v1.1 新增）](#国密模式配置v11-新增)

## 升级路线图

```
v0.1.x (alpha) → v0.2.x (beta) → v0.3.x (RC) → v0.4.x (RC2) → v1.0 (GA) → v1.1 (国密闭环)
```

| 版本 | 核心变更 | 兼容性 |
|---|---|---|
| v0.1 → v0.2 | Shamir + 审计链 + BoltDB | ❌ 不兼容（alpha 阶段） |
| v0.2 → v0.3 | HSM + 国密 + SecureBuffer RWMutex | ✅ 向前兼容 |
| v0.3 → v0.4 | gRPC + MCP + Service 层 + K8s | ✅ 向前兼容 |
| v0.4 → v1.0 | GA 稳定版，mTLS + API 冻结 | ✅ 向前兼容 |
| v1.0 → v1.1 | 国密闭环（SM2/JWT SM2/HMAC-SM3/PKCS#11） | ✅ 向前兼容 |

## Breaking Changes 矩阵

### v1.0.x → v1.1.0

| 维度 | 是否 Breaking | 详情 |
|---|---|---|
| **HTTP API** | ❌ 无 | 端点/请求/响应格式不变 |
| **gRPC API** | ❌ 无 | proto 定义不变 |
| **密文格式** | ❌ 无 | `[4B Version BE][12B Nonce][CT+Tag]` 不变 |
| **数据库 Schema** | ❌ 无 | `yvonne_kv_str` 表结构不变（新增 updated_at 列，DO 块自动添加） |
| **配置文件** | ⚠️ 新增字段 | `crypto.strict` 为可选，旧配置无需修改 |
| **KeyMetadata** | ⚠️ 新增字段 | `Algorithm` + `KeyUsage` 为 omitempty，旧数据兼容 |
| **编译** | ⚠️ 新增 tag | `-tags gmsm` 启用国密，默认编译无影响 |

**结论：v1.0.x → v1.1.0 零停服升级，无需数据迁移。**

## mTLS 配置（v1.0 新增）

v1.0 新增 mTLS 客户端证书认证，**默认不启用**（`client_auth: "none"`），向后兼容。

### 启用 mTLS（生产推荐）

```json
{
  "server": {
    "tls": {
      "enabled": true,
      "cert_file": "/etc/yvonne/server.crt",
      "key_file": "/etc/yvonne/server.key",
      "min_version": "TLS1.3",
      "client_auth": "require",
      "client_ca_file": "/etc/yvonne/ca.crt"
    }
  }
}
```

### client_auth 模式

| 模式 | 行为 | 适用场景 |
|---|---|---|
| `none`（默认） | 不校验客户端证书 | Dev 模式 / 内网 |
| `optional` | 有证书则校验，无证书放行 | 灰度迁移 |
| `require` | 强制客户端证书 | **生产推荐** |

### gRPC mTLS

gRPC server 复用 `server.grpc.tls` 配置，支持独立的 mTLS：
```json
{
  "server": {
    "grpc": {
      "tls": {
        "enabled": true,
        "cert_file": "/etc/yvonne/grpc.crt",
        "key_file": "/etc/yvonne/grpc.key",
        "client_auth": "require",
        "client_ca_file": "/etc/yvonne/ca.crt"
      }
    }
  }
}
```

### v0.3.x → v0.4.x

| 维度 | 是否 Breaking | 详情 |
|---|---|---|
| **HTTP API** | ❌ 无 | 新增 gRPC/MCP，HTTP 不变 |
| **密文格式** | ❌ 无 | 版本化密文格式不变 |
| **数据库 Schema** | ❌ 无 | 新增 `meta:latest:{keyID}` 索引（向前兼容，回退扫描） |
| **配置文件** | ⚠️ 新增字段 | `grpc`/`mcp` 为可选 |

### v0.2.x → v0.3.x

| 维度 | 是否 Breaking | 详情 |
|---|---|---|
| **密文格式** | ❌ 无 | AES-256-GCM 版本化密文不变 |
| **数据库 Schema** | ❌ 无 | 表结构不变 |
| **配置文件** | ⚠️ 新增字段 | `admin.admin_token` 为可选 |
| **SecureBuffer** | ✅ 内部 | 加 RWMutex，API 不变但行为更安全 |

## 升级步骤

### v0.4.x → v1.0（GA）零停服升级

```bash
# 1. 备份（热备，不停服）
pg_dump yvonne > backup-$(date +%Y%m%d).sql

# 2. 拉取新镜像
docker pull yvonne/kms:1.0

# 3. 滚动更新（K8s）
kubectl set image statefulset/yvonne yvonne=yvonne/kms:1.0
# StatefulSet 逐个 Pod 滚动，每个 Pod 优雅停机 30s

# 4. 验证
kubectl exec yvonne-0 -- yvonne health
curl http://yvonne:8400/api/v1/sys/health
```

**停服时间：0 秒**（滚动更新，旧 Pod 处理完请求后才停）。

### v0.3.x → v0.4.x

```bash
# 1. 备份
pg_dump yvonne > backup.sql

# 2. 停服（可选，滚动更新可零停服）
kubectl scale statefulset yvonne --replicas=0

# 3. 更新镜像
kubectl set image statefulset/yvonne yvonne=yvonne/kms:0.4.0

# 4. 启动
kubectl scale statefulset yvonne --replicas=3

# 5. 验证（meta:latest 索引自动补建）
kubectl exec yvonne-0 -- curl localhost:8400/api/v1/sys/health
```

**停服时间：0 秒**（滚动更新）或 ~30 秒（停服更新）。

### v0.2.x → v0.3.x

同上流程。`meta:latest:` 索引在首次访问时自动补建（回退扫描兼容）。

## 停服时间评估

| 升级路径 | 停服时间 | 原因 |
|---|---|---|
| v0.4.x → v1.0 | **0 秒** | 滚动更新 + 无 schema 变更 |
| v0.3.x → v0.4.x | **0 秒** | 滚动更新 + 索引自动补建 |
| v0.2.x → v0.3.x | **0 秒** | 滚动更新 + 向前兼容 |
| v0.1.x → v0.2.x | **需停服** | alpha 阶段，不保证兼容 |

## 回滚方案

### v1.0 → v0.4.x 回滚

```bash
# 1. 回滚镜像
kubectl rollout undo statefulset/yvonne

# 2. 验证
kubectl get pods -l app=yvonne
curl http://yvonne:8400/api/v1/sys/health
```

**回滚条件**：
- v1.0 未引入新 DB schema（满足）
- v1.0 未修改密文格式（满足）
- v1.0 未删除旧配置字段（满足）

### 数据库回滚

```bash
# 恢复备份
psql yvonne < backup-20260626.sql
```

## 密文格式兼容性

### 版本化密文格式（v0.2+ 不变）

```
[Version (uint32, 4 bytes, BigEndian)] [Nonce (12 bytes)] [Ciphertext + AuthTag (变长)]
```

- **v0.2 ~ v1.0**：格式完全不变
- 旧密文（v0.2 创建）在 v1.0 中可正常解密
- 新密文（v1.0 创建）在 v0.2 中也可解密（版本号兼容）

### DEK 加密格式（KEK 层）

- **softwareKEK**（AES-256-GCM）：`[12B Nonce][Ciphertext+AuthTag]`，v0.2+ 不变
- **hsmKEK**：由 HSM 决定，v0.3+ 引入，与 softwareKEK 隔离

## 数据库 Schema 变更

### v1.0 Schema（与 v0.4 相同）

```sql
CREATE TABLE yvonne_kv_str (
    k TEXT PRIMARY KEY,
    v BYTEA NOT NULL
);
```

### Key 命名约定

| Key 前缀 | 用途 | 引入版本 |
|---|---|---|
| `key:{keyID}:v:{version}` | 密钥元数据 | v0.2 |
| `meta:latest:{keyID}` | 最新版本索引（O(1) 查询） | v0.3（回退兼容） |
| `seal:wrapped_master_key` | 加密的 MasterKey | v0.2 |

### 无需迁移脚本的原因

1. **KV 模式**：所有数据存在 `yvonne_kv_str` 单表，无关系 schema
2. **向前兼容**：新索引（`meta:latest:`）缺失时回退扫描
3. **密文自路由**：版本号在密文头部，不依赖 DB schema

## 配置文件兼容性

### v0.4.x 配置在 v1.0 中完全有效

```json
{
  "mode": "cluster",
  "server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 8400,
    "grpc": { "enabled": true },
    "mcp": { "enabled": false }
  }
}
```

v1.0 可能新增可选字段，但旧配置无需修改。

### 新增字段（可选）

| 字段 | 版本 | 默认值 | 说明 |
|---|---|---|---|
| `server.grpc.enabled` | v0.4 | false | gRPC server |
| `server.mcp.enabled` | v0.4 | false | MCP server |
| `server.mcp.token` | v0.4 | "" | MCP 鉴权 token |
| `auth.k8s.enabled` | v0.4.1 | false | K8s SA 认证 |

## GA 前检查清单

- [x] 密文格式 v0.2~v1.0 不变
- [x] DB schema v0.4~v1.0 不变
- [x] HTTP API v0.4~v1.0 不变
- [x] gRPC proto v0.4~v1.0 不变
- [x] 配置文件向前兼容
- [x] 升级零停服（滚动更新）
- [x] 回滚方案验证
- [x] `meta:latest:` 索引回退兼容
- [x] SecureBuffer RWMutex 向前兼容
- [x] EmergencySeal 缓存清空（v0.3+）

## FAQ

### Q: 升级时密钥正在轮转怎么办？

K8s 滚动更新逐个 Pod 替换。`pg_advisory_lock` 确保只有一个 Pod 执行轮转。旧 Pod 收到 SIGTERM 后完成 in-flight 轮转再退出，新 Pod 启动后接管。

### Q: 升级后 `meta:latest:` 索引不存在会怎样？

首次访问时自动回退到 O(N) 扫描，并自动写入索引。后续访问 O(1)。用户无感知。

### Q: 能跳版本升级吗（如 v0.2 → v1.0）？

可以。每个版本都向前兼容，密文格式不变。建议先备份再升级。

### Q: HSM 模式升级有额外注意吗？

HSM 的 CMK 存储在 HSM 硬件中，与 Yvonne 版本无关。升级 Yvonne 软件不影响 HSM 中的 CMK。

## 国密模式配置（v1.1 新增）

v1.1 新增国密闭环支持，**默认不启用**，向后兼容。

### 启用国密模式

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  },
  "auth": {
    "jwt": {
      "signing_method": "SM2",
      "verifying_key_path": "/etc/yvonne/sm2-pub.pem",
      "issuer": "yvonne-kms"
    }
  }
}
```

### 国密编译

```bash
# 国密模式编译（SM2/SM3/SM4 + HMAC-SM3 审计 + JWT SM2）
go build -tags gmsm

# 国密 + HSM
go build -tags 'gmsm,hsm,pkcs11'
```

### 国密 vs 标准

| 维度 | 标准模式 | 国密模式 |
|---|---|---|
| 对称加密 | AES-256-GCM | SM4-GCM |
| 密码杂凑 | SHA-256 | SM3 |
| 审计链 HMAC | HMAC-SHA256 | HMAC-SM3 |
| JWT 签名 | RS256/ES256/HS256 | SM2 |
| 公钥密码 | RSA/ECDSA | SM2 |
| 编译 tag | 无需 | `-tags gmsm` |
| 严格模式 | 不适用 | `crypto.strict: true` |

### 从 v1.0 升级到 v1.1 国密模式

1. 重新编译：`go build -tags gmsm`
2. 配置 `crypto.suite: "gmsm"`
3. 轮转现有密钥（新版本用 SM4）
4. 旧 AES 密文仍可解密（向后兼容）
5. 参考 [AES→SM4 迁移指南](aes-to-sm4-migration.md)
