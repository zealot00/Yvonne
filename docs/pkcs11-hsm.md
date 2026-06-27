# PKCS#11 HSM 集成

> Yvonne KMS v1.2+ | 通过 PKCS#11 标准接口连接 HSM 硬件

## 概述

Yvonne KMS 支持 PKCS#11 标准接口连接 HSM（硬件安全模块），CMK 存储在 HSM 芯片内，明文永不离开芯片。所有 DEK 加解密操作通过 HSM 内的 AES-256-GCM 执行。

### 支持的 HSM

| HSM | 状态 | 说明 |
|---|---|---|
| SoftHSM2 | ✅ 测试可用 | 开源软件 HSM，CI/开发用 |
| Thales Luna | ✅ 兼容 | 通过 PKCS#11 标准接口 |
| Ravelin HSM | ✅ 兼容 | 通过 PKCS#11 标准接口 |
| 其他 PKCS#11 HSM | ✅ 兼容 | 遵循 PKCS#11 标准 |

## 编译

```bash
# 默认编译（无 HSM）
go build

# Mock HSM（测试用）
go build -tags hsm

# PKCS#11 HSM（真实硬件）
go build -tags 'hsm,pkcs11'

# PKCS#11 + 国密
go build -tags 'hsm,pkcs11,gmsm'
```

## 配置

### 配置文件

```json
{
  "mode": "cluster",
  "unseal": {
    "type": "hsm",
    "hsm_backend": "pkcs11",
    "hsm_key_id": "yvonne-cmk",
    "lib_path": "/usr/lib/softhsm/libsofthsm2.so",
    "slot": 0,
    "pin": "1234"
  }
}
```

### 环境变量（敏感信息不落盘）

```bash
export YVONNE_UNSEAL_HSM_PIN="your-hsm-pin"
```

## SoftHSM2 安装与初始化

### macOS

```bash
brew install softhsm

# 初始化测试 slot
softhsm2-util --init-token --slot 0 --label "yvonne" --so-pin 1234 --pin 1234

# 验证
softhsm2-util --show-slots
```

### Ubuntu/Debian

```bash
apt install softhsm2

# 配置 token 目录
echo "directories.tokendir = /var/lib/softhsm/tokens/" > /etc/softhsm/softhsm2.conf
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# 初始化
softhsm2-util --init-token --slot 0 --label "yvonne" --so-pin 1234 --pin 1234
```

### Docker

```dockerfile
RUN apt-get update && apt-get install -y softhsm2
RUN softhsm2-util --init-token --slot 0 --label "yvonne" --so-pin 1234 --pin 1234
```

## 测试

```bash
# 设置环境变量
export YVONNE_PKCS11_LIB=/usr/local/lib/softhsm/libsofthsm2.so
export YVONNE_PKCS11_SLOT=0
export YVONNE_PKCS11_PIN=1234

# 运行 PKCS#11 测试
go test -tags 'hsm,pkcs11' -race -v -timeout 60s ./internal/seal/ -run TestPKCS11
```

## 密钥管理

### 自动生成

首次启动时，若 HSM 中不存在指定 KeyID 的密钥，Yvonne 自动生成 AES-256 密钥。

### 密钥复用

同一 KeyID 可被多个 Yvonne 实例共享（多节点 HA 场景）。

### 密钥轮转

HSM 内的 CMK 轮转需通过 HSM 管理工具执行（非 Yvonne API），轮转后需重启 Yvonne。

## 安全保证

| 保证 | 实现 |
|---|---|
| CMK 不离开芯片 | PKCS#11 `C_GenerateKey` + `C_EncryptInit`，明文密钥不返回 |
| 内存安全 | Go 进程仅持有 HSM 密钥句柄，无明文 CMK |
| 并发安全 | crypto11 内部 session pool 管理 |
| 审计 | 所有 Wrap/Unwrap 操作记录审计日志 |

## 架构

```
┌──────────────────┐
│  Yvonne 进程      │
│  ┌────────────┐  │
│  │ hsmKEK     │  │
│  │   ↓        │  │
│  │ pkcs11Backend  │
│  │   ↓        │  │
│  └────────┬───┘  │
└───────────┼──────┘
            │ PKCS#11 API
            ▼
┌──────────────────┐
│  HSM 芯片        │
│  ┌────────────┐  │
│  │ AES-256 CMK│  │ ← 明文不可导出
│  │ Wrap/Unwrap│  │
│  └────────────┘  │
└──────────────────┘
```

## 故障排除

### `PKCS#11 library not found`

确认 `lib_path` 指向正确的 `.so` / `.dylib` / `.dll` 文件。

### `CKR_PIN_INCORRECT`

确认 PIN 与 `softhsm2-util --init-token` 设置的一致。

### `CKR_SLOT_ID_INVALID`

运行 `softhsm2-util --show-slots` 确认 slot 编号。

### `CKR_KEY_HANDLE_INVALID`

HSM 中不存在指定 KeyID 的密钥。Yvonne 首次启动会自动生成，若失败检查 HSM 权限。
