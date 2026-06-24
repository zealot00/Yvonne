# Yvonne KMS

生产级密钥管理系统（KMS），面向 GxP / SOC2 合规场景，采用零信任架构与 Shamir 门限解封。

## 设计原则

- **绝对冷酷 (Absolute Zero)**：防范内存泄露、侧信道攻击、反编译窃取。
- **合规先行 (Compliance Driven)**：满足 GxP、SOC2 外部审计，权限最小化与操作完全可追溯。
- **不信任原则 (Zero Trust)**：哪怕拿到服务器 root 权限，也无法直接获取明文主密钥。

## 核心特性

| 模块 | 说明 |
|---|---|
| 内存防御 (`internal/memguard`) | `SecureBuffer` 容器 + `clear()` + `runtime.KeepAlive()` 防 DCE；CSPRNG 统一入口 |
| 加密引擎 (`internal/crypto`) | AES-256-GCM 信封加密；RSA-4096 PSS / ECDSA P-256 签名验签 |
| 封印状态机 (`internal/seal`) | Shamir GF(2^8) 门限分割；Local PKI 自动解封；**紧急封印**（不可逆冰冻） |
| 生命周期 (`internal/lifecycle`) | DEK 状态机 Active→Deactivated→Destroyed；Rotate/Shred 事务+行级锁；**本地缓存+LISTEN/NOTIFY 集群失效** |
| 存储 (`internal/storage`) | MemoryStore + PostgresKVStore（pgxpool 连接池，SELECT FOR UPDATE，LISTEN/NOTIFY） |
| 审计 (`internal/audit`) | 独立 AuditKey（CSPRNG 生成）+ HMAC-SHA256 签名；防篡改日志流 |
| 可观测性 (`internal/metrics`) | Prometheus 文本格式；API P99 耗时、解密失败计数、Go runtime memstats |
| 网络层 (`internal/api`) | AuditMiddleware 强制审计；Payload Escaping Control；Sealed 503；**RBAC 认证授权** |
| 认证授权 (`internal/auth`) | AppRole Token 认证 + Policy（通配符 Key + Action）；subtle.ConstantTimeCompare |

---

## 快速入门

### 1. 环境要求

- Go 1.21+
- PostgreSQL 14+（仅 Cluster 模式）

### 2. 编译

```bash
make build
# 或
go build -o bin/yvonne ./cmd/yvonne
```

### 3. Dev 模式（30 秒体验）

```bash
./bin/yvonne dev
```

Dev 模式特性：
- 强制 `storage=memory`（数据不持久化，重启丢失）
- 自动生成 32 字节临时 Master Key，直接进入 Unsealed 状态
- 启动时打印红字警告：`WARNING: Yvonne is running in DEV MODE...`

自定义端口：
```bash
./bin/yvonne dev --port 9000 --addr 0.0.0.0
```

### 4. 首次 API 调用

```bash
# 健康检查
curl http://127.0.0.1:8200/api/v1/sys/health

# 创建业务密钥
curl -X POST http://127.0.0.1:8200/api/v1/keys \
  -d '{"key_id":"my-app-key"}'

# 加密
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -d '{"key_id":"my-app-key","plaintext":"aGVsbG8gd29ybGQ="}'

# 解密
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"my-app-key","ciphertext":"<上一步返回的ciphertext>"}'
```

---

## 运行模式

### Dev 模式（开发者零配置）

```bash
./bin/yvonne dev [--port 8200] [--addr 127.0.0.1]
```

| 特性 | Dev 模式 |
|---|---|
| 存储 | MemoryStore（内存，重启丢失） |
| Master Key | 自动生成 32 字节随机密钥 |
| 解封 | 自动（DirectUnseal） |
| 持久化 | 无 |
| 适用场景 | 本地开发、单元测试 |

### Cluster 模式（生产部署）

#### 配置文件 `config.json`

```json
{
  "mode": "cluster",
  "server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 8200,
    "tls": {
      "enabled": true,
      "min_version": "TLS1.3",
      "cert_file": "/etc/yvonne/tls.crt",
      "key_file": "/etc/yvonne/tls.key"
    },
    "admin": {
      "enabled": true,
      "bind_addr": "127.0.0.1",
      "bind_port": 8250
    }
  },
  "storage": {
    "type": "postgres",
    "dsn": "postgres://yvonne:password@db.internal:5432/yvonne?sslmode=require"
  },
  "unseal": {
    "type": "shamir",
    "total_shares": 5,
    "threshold": 3,
    "auto_reseal_after": "30m"
  },
  "logging": {
    "level": "info",
    "format": "json",
    "output": "stdout",
    "redact_secrets": true
  }
}
```

#### 启动

```bash
./bin/yvonne server --config config.json
```

| 特性 | Cluster 模式 |
|---|---|
| 存储 | PostgreSQL（pgxpool 连接池） |
| Master Key | Shamir 重组 或 Local PKI 自动解封 |
| 解封 | 需手动提交 Share 或 PEM 自动解封 |
| 持久化 | 是 |
| 适用场景 | 生产环境 |

#### Cluster 模式严格校验

- `storage.type` 必须 `postgres`（禁 `memory`）
- `unseal.type` 必须 `shamir` 或 `local_pki`（禁 `auto`）
- `logging.redact_secrets` 必须 `true`
- 任何校验失败 → panic 拒绝启动

### Local PKI 自动解封模式

适合无需人工值守的生产环境。

#### 步骤 1：生成 RSA-4096 密钥对

```bash
./bin/yvonne unseal-keygen --out /var/run/yvonne/unseal.pem
```

输出：
```
generating RSA-4096 key pair (this may take a moment)...
private key written to /var/run/yvonne/unseal.pem (mode 0600)
# Public key (use this to encrypt the Master Key for initial setup):
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA...
-----END RSA PUBLIC KEY-----
```

#### 步骤 2：初始化 Wrapped Master Key

用公钥加密 Master Key，存入 DB（key: `master-key-wrapped`）。可编写一次性初始化脚本调用 `seal.EncryptMasterKeyWithPublicKey`。

#### 步骤 3：配置并启动

```json
{
  "mode": "cluster",
  "storage": { "type": "postgres", "dsn": "..." },
  "unseal": {
    "type": "local_pki",
    "pki_key_path": "/var/run/yvonne/unseal.pem"
  }
}
```

启动时 Yvonne 会：
1. 读取 PEM 文件 → RSA 私钥
2. 从 DB 读取 Wrapped Master Key
3. RSA-OAEP SHA-256 解密
4. 封装为 SecureBuffer → DirectUnseal
5. **阅后即焚**：清零 PEM 内存 + `os.Remove` 物理删除 PEM 文件

### 环境变量覆盖

优先级：env > config file > default

| 环境变量 | 覆盖字段 |
|---|---|
| `YVONNE_MODE` | `mode` |
| `YVONNE_STORAGE_TYPE` | `storage.type` |
| `YVONNE_STORAGE_DSN` | `storage.dsn` |
| `YVONNE_UNSEAL_TYPE` | `unseal.type` |
| `YVONNE_UNSEAL_THRESHOLD` | `unseal.threshold` |

### Docker 部署

```bash
# 启动 PostgreSQL
docker run -d --name yvonne-pg \
  -e POSTGRES_USER=yvonne \
  -e POSTGRES_PASSWORD=yvonne_pass \
  -e POSTGRES_DB=yvonne \
  -p 5432:5432 postgres:16

# 启动 Yvonne
YVONNE_STORAGE_DSN="postgres://yvonne:yvonne_pass@localhost:5432/yvonne?sslmode=disable" \
  ./bin/yvonne server --config config.cluster.example.json
```

---

## CLI 命令

| 命令 | 说明 |
|---|---|
| `yvonne dev` | 开发模式（零配置，内存存储） |
| `yvonne server --config <path>` | 生产模式（需配置文件） |
| `yvonne unseal-keygen --out <path>` | 生成 RSA-4096 PKI 解封密钥对 |

```bash
yvonne dev --port 9000 --addr 0.0.0.0
yvonne server --config /etc/yvonne/config.json
yvonne unseal-keygen --out /var/run/yvonne/unseal.pem
```

---

## API 文档

所有 API 统一返回 JSON：`{"ok": bool, "data": ..., "error": ...}`。

**Sealed 状态行为**：所有非 `/sys` 路由返回 `HTTP 503 Service Unavailable`。

### 1. 系统管理 API

#### `GET /api/v1/sys/health`

健康检查。Sealed 状态也可用。

```bash
curl http://127.0.0.1:8200/api/v1/sys/health
```

**响应**：
```json
{
  "ok": true,
  "data": {
    "status": "alive",
    "sealed": false,
    "state": "unsealed"
  }
}
```

| 字段 | 说明 |
|---|---|
| `status` | 固定 `"alive"` |
| `sealed` | 是否处于封印状态 |
| `state` | `"sealed"` / `"unsealed"` / `"sealing"` |

#### `POST /api/v1/sys/unseal`

提交单份 Shamir 碎片。达到 `threshold` 份数时自动触发重组。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/unseal \
  -d '{"share":"<base64-encoded-share>"}'
```

**请求体**：
| 字段 | 类型 | 说明 |
|---|---|---|
| `share` | string (base64) | 单份 Shamir 碎片 |

**响应（未达阈值）**：
```json
{ "ok": true, "data": { "unsealed": false } }
```

**响应（达阈值，解封成功）**：
```json
{ "ok": true, "data": { "unsealed": true } }
```

**响应（已解封后再提交）**：
```json
{
  "ok": true,
  "data": {
    "unsealed": true,
    "note": "already unsealed, extra share rejected"
  }
}
```

#### `POST /api/v1/sys/panic` — 紧急封印（不可逆）

触发紧急封印，系统进入深度冰冻状态。调用后：
- Master Key 被物理粉碎（Wipe）
- 所有碎片缓存被清除
- 拒绝一切 API 请求（包括 unseal）
- 必须 kill 进程 + 冷启动 + Shamir 解封才能恢复

需要独立的 Admin Token 验证（非普通 AppRole Token）。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/panic \
  -d '{"admin_token":"<admin-token>","confirm":true}'
```

**响应**：
```json
{
  "ok": true,
  "data": {
    "emergency_sealed": true,
    "message": "vault is now emergency sealed. all operations refused until process restart + shamir unseal."
  }
}
```

> **不可逆操作**：进程生命周期内无法恢复。审计日志记录 `Action=EmergencySeal`。

### 2. 密钥生命周期 API

> 以下 API 需要 Unsealed 状态，否则返回 503。

#### `POST /api/v1/keys` — 创建业务密钥

生成新的 DEK（Data Encryption Key），用 Master Key 加密后存储。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys \
  -d '{"key_id":"user-pii-key"}'
```

**请求体**：
| 字段 | 类型 | 说明 |
|---|---|---|
| `key_id` | string | 业务密钥标识符（如 `user-pii-key`） |

**响应**：
```json
{
  "ok": true,
  "data": {
    "key_id": "user-pii-key",
    "version": 1,
    "plaintext_dek": "base64-encoded-32-byte-dek"
  }
}
```

| 字段 | 说明 |
|---|---|
| `version` | 密钥版本号（初始为 1） |
| `plaintext_dek` | Base64 编码的明文 DEK（32 字节）。**调用方必须安全存储，用后擦除** |

> **安全警告**：`plaintext_dek` 仅在创建/轮转时返回一次。KMS 不保存明文 DEK，仅保存被 Master Key 加密后的密文。调用方丢失后无法恢复。

#### `POST /api/v1/keys/{key_id}/rotate` — 轮转密钥

将当前 Active 版本标记为 Deactivated，生成新 Active 版本。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/user-pii-key/rotate
```

**响应**：
```json
{
  "ok": true,
  "data": {
    "key_id": "user-pii-key",
    "version": 2,
    "plaintext_dek": "base64-encoded-new-dek"
  }
}
```

**轮转后状态**：
- V1: `Deactivated`（仅限解密历史数据）
- V2: `Active`（可用于新加密）

> **向后兼容**：轮转后用 V1 加密的旧密文仍可解密（decrypt 时根据密文头部的版本号自动选择对应 DEK）。

#### `DELETE /api/v1/keys/{key_id}/shred` — 物理粉碎密钥

执行 Crypto-Shredding：先 UPDATE 密文为 NULL，再 DELETE 行。

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/user-pii-key/shred \
  -d '{"version": 1}'
```

**请求体**：
| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | int | 要粉碎的版本号 |

**响应**：
```json
{
  "ok": true,
  "data": {
    "key_id": "user-pii-key",
    "version": 1,
    "shred": true
  }
}
```

> **不可逆操作**：Shred 后该版本的密文 DEK 被物理擦除，用该版本加密的密文将永远无法解密。

### 3. 密码学运算 API

> 以下 API 需要 Unsealed 状态，否则返回 503。

#### `POST /api/v1/encrypt` — 信封加密

用指定 key_id 的最新 Active 版本 DEK 加密业务明文。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -d '{"key_id":"user-pii-key","plaintext":"aGVsbG8gd29ybGQ="}'
```

**请求体**：
| 字段 | 类型 | 说明 |
|---|---|---|
| `key_id` | string | 业务密钥标识符 |
| `plaintext` | string (base64) | 待加密的明文 |

**响应**：
```json
{
  "ok": true,
  "data": {
    "ciphertext": "AAF64GAfE4vYPvzLc92mxNrg282P7zbb0/pX0EQp86gs+1MTa5VWN0c=",
    "version": 1
  }
}
```

| 字段 | 说明 |
|---|---|
| `ciphertext` | Base64 编码的密文。格式：`[2字节版本号][12字节Nonce][密文+16字节AuthTag]` |
| `version` | 使用的 DEK 版本号（解密时需指定） |

**密文格式**：
```
[00 01]  [Nonce 12 bytes]  [Ciphertext + AuthTag]
 版本1     随机Nonce           AES-256-GCM 输出
```

#### `POST /api/v1/decrypt` — 信封解密

用指定 key_id 的对应版本 DEK 解密密文。版本号从密文头部自动提取。

```bash
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"user-pii-key","ciphertext":"AAF64GAfE4vYPvzLc92mxNrg282P7zbb0/pX0EQp86gs+1MTa5VWN0c="}'
```

**请求体**：
| 字段 | 类型 | 说明 |
|---|---|---|
| `key_id` | string | 业务密钥标识符 |
| `ciphertext` | string (base64) | 加密接口返回的密文 |

**响应**：
```json
{
  "ok": true,
  "data": {
    "plaintext": "aGVsbG8gd29ybGQ=",
    "version": 1
  }
}
```

> **安全**：明文经 HTTP 响应回传后即视为"离开 KMS 边界"，由调用方负责生命周期。KMS 内部明文已通过 SecureBuffer + Wipe 清理。

### 4. 可观测性 API

#### `GET /metrics` — Prometheus 指标

```bash
curl http://127.0.0.1:8200/metrics
```

**核心指标**：

| 指标 | 类型 | 说明 |
|---|---|---|
| `yvonne_api_request_duration_seconds` | histogram | API 请求耗时（bucket: 0.005s..10s） |
| `yvonne_decrypt_failures_total` | counter | 解密失败次数（激增意味着暴力试探篡改密文） |
| `yvonne_encrypt_failures_total` | counter | 加密失败次数 |
| `yvonne_unseal_failures_total` | counter | Unseal 失败次数 |
| `yvonne_api_requests_total{action="..."}` | counter | 按 action 分类的总请求数 |
| `go_memstats_alloc_bytes` | gauge | Go 堆内存分配（防 OOM） |
| `go_memstats_heap_objects` | gauge | 堆对象数（防内存泄露） |
| `go_goroutines` | gauge | Goroutine 数（防 goroutine 泄露） |

**Prometheus P99 计算**：
```promql
histogram_quantile(0.99, rate(yvonne_api_request_duration_seconds_bucket[5m]))
```

---

## API 端点速查表

| 方法 | 路径 | 说明 | Sealed 可用 |
|---|---|---|---|
| GET | `/api/v1/sys/health` | 健康检查 | ✅ |
| POST | `/api/v1/sys/unseal` | 提交 Shamir 碎片 | ✅ |
| POST | `/api/v1/sys/panic` | 紧急封印（不可逆冰冻） | ✅ |
| POST | `/api/v1/keys` | 创建业务密钥（AES/RSA/ECDSA） | ❌ 503 |
| POST | `/api/v1/keys/{key_id}/rotate` | 轮转密钥 | ❌ 503 |
| DELETE | `/api/v1/keys/{key_id}/shred` | 物理粉碎密钥 | ❌ 503 |
| POST | `/api/v1/encrypt` | 信封加密 | ❌ 503 |
| POST | `/api/v1/decrypt` | 信封解密 | ❌ 503 |
| GET | `/metrics` | Prometheus 指标 | ✅ |

---

## 完整使用示例

### 场景：保护用户 PII 数据

```bash
# 1. 启动 Yvonne（Dev 模式快速演示）
./bin/yvonne dev --port 8200

# 2. 创建专用密钥
curl -s -X POST http://127.0.0.1:8200/api/v1/keys \
  -d '{"key_id":"user-pii-key"}'
# → {"ok":true,"data":{"key_id":"user-pii-key","version":1,"plaintext_dek":"..."}}

# 3. 加密用户邮箱（base64 编码后发送）
EMAIL_B64=$(echo -n "alice@example.com" | base64)
curl -s -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -d "{\"key_id\":\"user-pii-key\",\"plaintext\":\"$EMAIL_B64\"}"
# → {"ok":true,"data":{"ciphertext":"AAF...","version":1}}

# 4. 解密（从 DB 取出密文后解密）
curl -s -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"user-pii-key","ciphertext":"AAF..."}'
# → {"ok":true,"data":{"plaintext":"YWxpY2VAZXhhbXBsZS5jb20=","version":1}}
# base64 解码 → "alice@example.com"

# 5. 定期轮转密钥（合规要求）
curl -s -X POST http://127.0.0.1:8200/api/v1/keys/user-pii-key/rotate
# → {"ok":true,"data":{"key_id":"user-pii-key","version":2,"plaintext_dek":"..."}}

# 6. 旧密文仍可解密（向后兼容）
curl -s -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"user-pii-key","ciphertext":"AAF...(V1密文)"}'
# → {"ok":true,"data":{"plaintext":"...","version":1}}

# 7. 合规销毁旧版本（Crypto-Shredding）
curl -s -X DELETE http://127.0.0.1:8200/api/v1/keys/user-pii-key/shred \
  -d '{"version":1}'
# → {"ok":true,"data":{"key_id":"user-pii-key","version":1,"shred":true}}
# V1 密文此后永远无法解密
```

### 审计日志格式

每个 API 请求（无论成功失败）都会在 stdout 输出带 HMAC-SHA256 签名的审计日志：

```json
{
  "payload": "{\"trace_id\":\"5ccf7d52...\",\"timestamp\":\"2026-06-24T11:04:33Z\",\"actor\":\"127.0.0.1:53651\",\"action\":\"Encrypt\",\"key_id\":\"\",\"status\":\"failure\"}",
  "signature": "f82054a53a156a3b0a9ba308c604cee765c5c4703b6b15056fada9926f87dc8d"
}
```

| 字段 | 说明 |
|---|---|
| `payload` | 原始 LogEntry JSON（脱敏，不含明文/密文） |
| `signature` | HMAC-SHA256(payload, AuditKey) 的 hex 编码 |

**审计日志不记录**：明文、密文、Master Key、DEK、Shamir 碎片内容。仅记录元数据（谁、何时、对哪个 Key、做了什么操作、结果）。

---

## 安全特性

| 特性 | 实现 |
|---|---|
| SecureBuffer | `clear()` + `runtime.KeepAlive()` 防 DCE；`WithKey` 闭包防堆逃逸 |
| CSPRNG 统一入口 | 全局 `memguard.GenerateSecureRandom`，禁 `math/rand`，禁绕过 `crypto/rand.Read` |
| Crypto-Shredding | Shred 先 UPDATE NULL 再 DELETE；MemoryStore 先 clear 再 delete |
| 事务+行级锁 | Rotate/Shred 用 `SELECT FOR UPDATE` 防并发数据错乱 |
| HMAC-SHA256 审计 | 独立 AuditKey，每条日志签名，防篡改 |
| Payload Escaping | HTTP body 读后立刻 clear+KeepAlive，明文不进 GC |
| subtle.ConstantTimeCompare | Master Key / Token 比较防计时侧信道 |
| Shamir GF(2^8) | 手写有限域运算，不可约多项式 0x11b，生成元 0x03 |
| RBAC 认证授权 | AppRole Token + Policy（通配符 Key + Action）；默认拒绝；越权 403 |
| 集群缓存失效 | Postgres LISTEN/NOTIFY；断线重连清空整个缓存池 |
| 紧急封印 | `EmergencySeal` 不可逆冰冻；Wipe Master Key + 碎片；拒绝一切 API |
| 非对称私钥安全 | PKCS#8 DER → SecureBuffer → clear 明文 → 信封加密 |

## 安全红线

Yvonne 强制执行以下安全编码红线，并通过 `scripts/security-check.sh` 自动化检查（11 项）：

| # | 检查项 | 说明 |
|---|---|---|
| 1 | `clear()` + `runtime.KeepAlive()` 配对 | 防 DCE 优化掉内存擦除 |
| 2 | 禁止返回 `[]byte` 的方法 Getter | 敏感数据必须通过 `WithKey` 闭包访问 |
| 3 | Error/日志不拼接敏感变量值 | 防泄露到日志采集系统 |
| 4 | 系统熵源统一走 `GenerateSecureRandom` | 禁 `math/rand`，禁绕过 `crypto/rand.Read` |
| 5 | 明文密钥参数用 `*memguard.SecureBuffer` | 防 `[]byte` 逃逸到 GC 堆 |
| 6 | 敏感变量比较用 `subtle.ConstantTimeCompare` | 禁 `==` / `!=` / `strings.EqualFold` |
| 7 | `ProvideShare` 达阈值后擦除 `collectedShares` | 防内存快照泄露碎片 |
| 8 | Shamir 运算严格在 GF(2^8) 内 | 禁普通 `+` `-` `*` `/` 用于域元素 |
| 9 | `Combine` 返回 `*memguard.SecureBuffer` | 明文不流浪为普通 `[]byte` |
| 10 | `MemoryStore.Delete` 先 `clear` 后 `delete` | Crypto-Shredding 物理粉碎 |
| 11 | API Handler `io.ReadAll` 结果 `clear+KeepAlive` | Payload Escaping Control |

### 运行安全自检

```bash
bash scripts/security-check.sh
```

---

## 开发

### 运行测试

```bash
# 单元测试
make test
# 或
go test ./... -race -count=1

# PostgreSQL 集成测试（需可用 Postgres）
YVONNE_PG_DSN="postgres://yvonne:yvonne_pass@localhost:5432/yvonne_test?sslmode=disable" \
  go test ./internal/storage/ -tags=integration -race -v -timeout 120s
```

### 项目结构

```
yvonne/
├── cmd/yvonne/              # CLI 入口（server/dev/unseal-keygen）
├── internal/
│   ├── memguard/            # SecureBuffer + CSPRNG
│   ├── crypto/              # AES-256-GCM 信封加密 + RSA-4096 PSS / ECDSA P-256 签名
│   ├── seal/                # Shamir + 封印状态机 + Local PKI + 紧急封印
│   ├── lifecycle/           # DEK 生命周期 + 本地缓存 + LISTEN/NOTIFY 集群失效
│   ├── storage/             # KVStore（Memory + Postgres + 事务 + LISTEN/NOTIFY）
│   ├── audit/               # HMAC-SHA256 防篡改审计
│   ├── metrics/             # Prometheus 指标
│   ├── api/                 # HTTP 路由 + 中间件 + handler + 紧急封印
│   ├── auth/                # RBAC 认证授权（AppRole Token + Policy）
│   ├── bootstrap/           # Dev/Cluster 依赖注入工厂
│   ├── config/              # 配置定义与加载
│   └── admin/               # Web 管理页面（embed）
├── scripts/security-check.sh  # 11 项安全自检
├── coverage.html            # 覆盖率报告
├── config.dev.example.json
├── config.cluster.example.json
└── Makefile
```

### 内部接口抽象

```go
// 存储层
type KVStore interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    Delete(ctx context.Context, key string) error
    WithTx(ctx context.Context, fn func(txStore KVStore) error) error
}

// 可选行级锁
type RowLocker interface {
    GetForUpdate(ctx context.Context, key string) ([]byte, error)
}

// 解封层
type Unsealer interface {
    IsSealed() bool
    ProvideShare(share []byte) (unsealed bool, err error)
    MasterKeyRef(action func(key *memguard.SecureBuffer) error) error
    Seal(ctx context.Context)
    State() State
    Threshold() int
    TotalShares() int
}

// 审计层
type Auditor interface {
    Record(entry LogEntry) error
    Close()
}
```

## 许可证

私有项目，版权所有。
