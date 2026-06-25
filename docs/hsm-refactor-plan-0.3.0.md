# Yvonne KMS 0.3.0 HSM BackendRef 适配重构计划

## 背景与目标

当前 HSM 模式不可用：`HSMUnsealer.MasterKeyRef` 返回 error（设计上拒绝暴露明文 CMK），而主业务路径全部依赖此闭包。HSM 模式应通过 `CryptoBackend.Wrap/Unwrap` 工作，让 CMK 明文永不离开芯片。

**核心思路**：引入 `KEK`（Key Encryption Key）抽象接口，统一软件 CMK 和 HSM backend。7 个生产调用点从 `MasterKeyRef` 改为 `KEKRef`。`softwareKEK` 内部调 `crypto.EncryptGCM`/`DecryptGCM`，密文格式与现状字节级一致（零数据迁移）。

## 新增要求（用户追加）

### 要求 A：HSM 依赖可插拔

HSM 相关代码通过 **build tag** 隔离，默认编译不包含 HSM 依赖：

- `//go:build hsm` — HSM 后端实现（PKCS#11/TPM/Mock）
- `//go:build !hsm` — stub 实现（返回 "HSM not compiled in"）
- 默认 `go build` 产出无 HSM 依赖的二进制
- `go build -tags hsm` 启用 HSM 支持
- bootstrap 的 `case "hsm"` 在 `!hsm` 编译时返回明确 error

### 要求 B：国密算法支持（SM2/SM3/SM4）

引入 `CryptoSuite`（密码套件）抽象，运行时可选标准算法或国密算法：

| 类别 | 标准算法 | 国密算法 |
|---|---|---|
| 对称加密 | AES-256-GCM | SM4-GCM |
| 哈希 | SHA-256 | SM3 |
| HMAC | HMAC-SHA256 | HMAC-SM3 |
| 非对称签名 | ECDSA P-256 | SM2 |
| 密钥包装 | RSA-4096 OAEP | SM2 包装 |

通过配置 `crypto.suite: "standard" | "gmsm"` 选择，默认 standard（向后兼容）。

## 架构设计

### 1. KEK 抽象接口（新建 `internal/seal/kek.go`）

```go
type KEKType string
const (
    KEKTypeSoftware KEKType = "software" // Shamir/LocalPKI/Dev
    KEKTypeHSM      KEKType = "hsm"
)

type KEK interface {
    WrapDEK(plaintextDEK *memguard.SecureBuffer) (ciphertext []byte, err error)
    UnwrapDEK(ciphertext []byte) (plaintextDEK *memguard.SecureBuffer, err error)
    Type() KEKType
}
```

两个实现：
- `softwareKEK`：包装 `*memguard.SecureBuffer`，内部调 `crypto.EncryptGCM`/`DecryptGCM`。密文格式 `[12B Nonce][Ciphertext+AuthTag]` 与现有完全一致（向后兼容）。
- `hsmKEK`：包装 `CryptoBackend`，DEK 加解密下发到 HSM 芯片执行。CMK 明文永不离开芯片。

### 2. Unsealer 接口扩展（`internal/seal/unsealer.go`）

新增 `KEKRef` 方法，保留 `MasterKeyRef`（向后兼容，HSM 返回 error）：

```go
type Unsealer interface {
    // ... 既有方法不变 ...
    MasterKeyRef(action func(key *memguard.SecureBuffer) error) error // 保留
    KEKRef(action func(kek KEK) error) error                          // 新增
}
```

三个实现者加 `KEKRef`：
- `VaultState`（state.go）：返回 `NewSoftwareKEK(v.masterKey)`
- `HSMUnsealer`（hsm_unsealer.go）：返回 `NewHSMKEK(h.backend)`
- `mockUnsealer`（daemon_mock_test.go）：返回 `NewSoftwareKEK(m.masterKey)`

### 3. lifecycle.Manager 签名迁移（`internal/lifecycle/manager.go` + `transit.go`）

5 个方法的 `masterKey *memguard.SecureBuffer` → `kek seal.KEK`：

| 方法 | 内部改动 |
|---|---|
| `CreateKey` | `crypto.GenerateDataKey(masterKey)` → `memguard.NewSecureBufferFromRandom(32)` + `kek.WrapDEK` |
| `RotateKey` | 同上 |
| `GenerateDataKey` | `crypto.DecryptGCM(masterKey, ...)` → `kek.UnwrapDEK(...)` |
| `CreateAsymmetricKey` | `crypto.EncryptGCM(masterKey, der)` → `kek.WrapDEK(derSB)` |
| `ImportKey` | `crypto.EncryptGCM(masterKey, dek)` → `kek.WrapDEK(dekSB)` |

**crypto 包无需改动**：`EncryptGCM`/`DecryptGCM` 作为低层原语被 `softwareKEK` 内部调用。`EncryptVersioned`/`DecryptVersioned` 接收 DEK（与 CMK 无关）。

### 4. KeyMetadata 标注 KEK 类型（`internal/lifecycle/manager.go`）

```go
type KeyMetadata struct {
    // ... 既有字段 ...
    KEKType string `json:"kek_type,omitempty"` // "software"|"hsm"，空值=software（旧数据兼容）
}
```

解密时检测不匹配 → 返回明确的 `ErrKEKTypeMismatch`。

### 5. 7 个调用点统一改写

`r.seal.MasterKeyRef(func(mk *SecureBuffer) error {...})` → `r.seal.KEKRef(func(kek seal.KEK) error {...})`

| # | 文件:行 | 改动 |
|---|---|---|
| 1 | `internal/api/handler_keys.go:74` | `CreateKey(ctx, id, kek, 0)` |
| 2 | `internal/api/handler_keys.go:174` | `RotateKey(ctx, id, kek)` |
| 3 | `internal/api/handler_keys.go:382` | `GenerateDataKey(ctx, id, kek)` |
| 4 | `internal/api/handler_v1.go:105` | `kek.UnwrapDEK(meta.EncryptedMaterial)` 替代 `crypto.DecryptGCM(mk, ...)` |
| 5 | `internal/api/handler_v1.go:219` | 同上 |
| 6 | `internal/api/handler_byok.go:104` | `ImportKey(ctx, ..., kek)` |
| 7 | `internal/lifecycle/daemon.go:164` | `RotateKey(ctx, id, kek)` |

### 6. bootstrap.go HSM 装配（`internal/bootstrap/bootstrap.go`）

- `vault` 变量类型 `*seal.VaultState` → `seal.Unsealer`
- `switch cfg.Unseal.Type` 新增 `case "hsm"`：调 `buildHSMBackend` → `NewHSMUnsealer`
- 0.3.0 `buildHSMBackend` 仅返回 `MockHSMBackend`；未来扩展 PKCS#11/TPM

### 7. config 扩展（`internal/config/yvonne_config.go`）

```go
type UnsealModeConf struct {
    // ... 既有字段 ...
    HSMBackend    string `json:"hsm_backend,omitempty"`     // "mock"（0.3.0）| "pkcs11"（未来）
    HSMKeyID      string `json:"hsm_key_id,omitempty"`      // 未来 PKCS#11
    PKCS11LibPath string `json:"pkcs11_lib_path,omitempty"` // 未来
    PKCS11Slot    int    `json:"pkcs11_slot,omitempty"`     // 未来
    PKCS11PIN     string `json:"pkcs11_pin,omitempty"`      // 未来（脱敏打印）
}
```

`validateClusterConfig` 加 `case "hsm"`。

### 8. admin.Server 适配（`internal/admin/server.go`）

`seal *seal.VaultState` → `seal seal.Unsealer`（HSM 模式无 VaultState）。

## 向后兼容策略

| 维度 | 策略 |
|---|---|
| `MasterKeyRef` | 保留在接口；HSM 返回 error；标记 `// Deprecated` |
| `crypto.EncryptGCM`/`DecryptGCM` | 保留为低层 API；`softwareKEK` 内部调用 |
| 现有 DEK 密文 | `softwareKEK` 产出与现状字节级一致，零数据迁移 |
| `KeyMetadata.KEKType` | `omitempty`，空值默认 software |
| Shamir/LocalPKI/Dev | `VaultState.KEKRef` 返回 `softwareKEK`，行为不变 |

## 分阶段实施（4 个里程碑，可独立提交）

### 里程碑 1：KEK 抽象层（无行为变更）
**文件**：
- 新建 `internal/seal/kek.go`（KEK 接口 + softwareKEK + hsmKEK）
- `internal/seal/unsealer.go`（加 KEKRef）
- `internal/seal/state.go`（VaultState 加 KEKRef）
- `internal/seal/hsm_unsealer.go`（HSMUnsealer 加 KEKRef）
- `internal/lifecycle/daemon_mock_test.go`（mockUnsealer 加 KEKRef）
- 新建 `internal/seal/kek_test.go`

**验证**：全量测试通过；7 个调用点未改；HSM 模式 KEKRef 可用但无调用方。

### 里程碑 2：lifecycle.Manager 签名迁移
**文件**：
- `internal/lifecycle/manager.go`（5 方法签名 + KeyMetadata 加 KEKType + import seal）
- `internal/lifecycle/transit.go`（ImportKey 签名）
- `internal/lifecycle/lifecycle_test.go`（迁移到 newSoftwareKEK helper + HSM 测试）

**验证**：lifecycle 测试全通过；software 模式密文格式不变。

### 里程碑 3：7 个调用点迁移 + admin 适配
**文件**：
- `internal/api/handler_keys.go`（调用点 1/2/3）
- `internal/api/handler_v1.go`（调用点 4/5）
- `internal/api/handler_byok.go`（调用点 6）
- `internal/lifecycle/daemon.go`（调用点 7）
- `internal/admin/server.go`（接口类型）
- `internal/admin/admin_test.go` + `internal/api/*_test.go`（适配）

**验证**：所有 handler 测试通过；MasterKeyRef 在主路径不再被调用。

### 里程碑 4：bootstrap HSM 装配 + config
**文件**：
- `internal/bootstrap/bootstrap.go`（vault 改 Unsealer + "hsm" case + buildHSMBackend）
- `internal/config/yvonne_config.go`（UnsealModeConf 加 HSM 字段 + validateClusterConfig）
- 新增 bootstrap HSM 端到端测试

**验证**：`unseal.type=hsm` 可启动；完整密钥生命周期在 HSM 模式下工作。

## 测试策略

| 层级 | 测试内容 |
|---|---|
| `seal/kek_test.go` | softwareKEK/hsmKEK round-trip + 篡改检测 |
| `seal/seal_test.go` | VaultState.KEKRef Unsealed/Sealed 状态 |
| `seal/hsm_test.go` | HSMUnsealer.KEKRef 会话建立/断开 |
| `lifecycle/lifecycle_test.go` | HSM 模式 CreateKey/RotateKey/GDK/ImportKey + KEKType 记录 |
| `api/*_test.go` | HSM 模式全链路 create→encrypt→decrypt→rotate→shred |
| bootstrap | `unseal.type=hsm` 启动 + 完整生命周期 |

## 0.3.0 之后的路线

- PKCS#11 backend（`internal/seal/pkcs11_backend.go`，build tag `pkcs11`）+ SoftHSM 集成测试
- TPM 2.0 backend（`internal/seal/tpm_backend.go`，build tag `tpm && linux`）— 对接 TPM 待办
- 软件→HSM 迁移工具（re-wrap DEK：softwareKEK.UnwrapDEK → hsmKEK.WrapDEK）
- 产物签名（cosign/sigstore）

---

## 补充设计：HSM 依赖可插拔

### Build Tag 隔离策略

HSM 后端代码通过 Go build tag 隔离，默认编译**零 HSM 依赖**：

```
internal/seal/
├── kek.go                  // KEK 接口 + softwareKEK（无 build tag，始终编译）
├── hsm.go                  // CryptoBackend 接口定义（无 build tag）
├── hsm_unsealer.go         // HSMUnsealer + BackendRef（无 build tag，仅接口层）
├── hsm_mock.go             // MockHSMBackend（//go:build hsm || test，测试可用）
├── hsm_stub.go             // stub：buildHSMBackend 返回 error（//go:build !hsm）
├── pkcs11_backend.go       // PKCS#11 实现（//go:build hsm && pkcs11）
└── tpm_backend.go          // TPM 实现（//go:build hsm && tpm && linux）
```

### 编译矩阵

| 命令 | HSM 支持 | 适用场景 |
|---|---|---|
| `go build` | ❌ 无 | 默认（轻量，无 CGO，无 HSM 库依赖） |
| `go build -tags hsm` | ✅ Mock | 测试 HSM 路径（无真实硬件） |
| `go build -tags 'hsm,pkcs11'` | ✅ PKCS#11 | 生产 HSM（需 PKCS#11 库） |
| `go build -tags 'hsm,tpm'` | ✅ TPM | TPM 2.0 硬件（Linux） |

### hsm_stub.go（默认编译时）

```go
//go:build !hsm

package seal

import "errors"

func buildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
    return nil, errors.New("seal: HSM support not compiled in (rebuild with -tags hsm)")
}
```

### hsm_mock.go（HSM tag 或测试时）

```go
//go:build hsm || test

package seal

func buildHSMBackend(cfg HSMConfig) (CryptoBackend, error) {
    return NewMockHSMBackend()
}
```

### bootstrap 适配

`buildClusterMode` 中的 `case "hsm"` 始终存在（无 build tag），但调用的 `buildHSMBackend` 由 build tag 决定实现。默认编译时 `unseal.type=hsm` 会返回明确 error，不会 panic。

### 依赖隔离

- `go.mod` 中 HSM 相关依赖（如 PKCS#11 CGO 绑定）用 build tag 隔离，不污染默认编译
- 国密库同理（见下文）

---

## 补充设计：国密算法支持（SM2/SM3/SM4）

### CryptoSuite 抽象

新建 `internal/crypto/suite.go`，定义密码套件接口：

```go
package crypto

type Suite string

const (
    SuiteStandard Suite = "standard" // AES-256-GCM + SHA-256 + ECDSA P-256
    SuiteGMSM     Suite = "gmsm"     // SM4-GCM + SM3 + SM2
)

// Cipher 套件：对称加密抽象
type Cipher interface {
    Encrypt(key *memguard.SecureBuffer, plaintext []byte) ([]byte, error)
    Decrypt(key *memguard.SecureBuffer, ciphertext []byte) (*memguard.SecureBuffer, error)
    KeySize() int // 32 (AES-256) 或 16 (SM4)
}

// Hash 套件：哈希抽象
type Hash interface {
    Sum(data []byte) []byte
    Size() int // 32 (SHA-256) 或 32 (SM3)
    HMAC(key, data []byte) []byte
}
```

### 两个实现

**标准套件**（`internal/crypto/suite_standard.go`，无 build tag）：
- `StandardCipher`：AES-256-GCM（现有 `EncryptGCM`/`DecryptGCM`）
- `StandardHash`：SHA-256 + HMAC-SHA256（现有 `crypto/sha256` + `crypto/hmac`）

**国密套件**（`internal/crypto/suite_gmsm.go`，`//go:build gmsm`）：
- `GMSMCipher`：SM4-GCM
- `GMSMHash`：SM3 + HMAC-SM3
- 依赖 `github.com/tjfoc/gmsm`（或 `github.com/emmansun/gmsm`）

### 编译矩阵

| 命令 | 国密支持 | 适用场景 |
|---|---|---|
| `go build` | ❌ 无 | 默认（标准算法） |
| `go build -tags gmsm` | ✅ 国密 | 国密合规场景 |

### 配置

```json
{
  "crypto": {
    "suite": "gmsm"
  }
}
```

- `crypto.suite = "standard"`（默认）：用 `StandardCipher` + `StandardHash`
- `crypto.suite = "gmsm"`：用 `GMSMCipher` + `GMSMHash`（需 `-tags gmsm` 编译）
- 启动时检测：`suite=gmsm` 但编译无 gmsm tag → panic

### 影响面分析

| 模块 | 改动 |
|---|---|
| `crypto/gcm.go` | `EncryptGCM`/`DecryptGCM` 改为 `StandardCipher` 的方法 |
| `crypto/envelope.go` | `GenerateDataKey` 接收 `Cipher` 接口 |
| `seal/kek.go` | `softwareKEK` 接收 `Cipher` 实例（而非硬编码 AES-GCM） |
| `audit/logger.go` | 哈希链用 `Hash` 接口（HMAC-SHA256 或 HMAC-SM3） |
| `KeyMetadata` | 新增 `CipherType` 字段（`"aes-256-gcm"` 或 `"sm4-gcm"`） |
| `config` | 新增 `CryptoConfig.Suite` 字段 |

### 向后兼容

- `crypto.suite` 默认 `"standard"`，现有行为不变
- 现有 `EncryptGCM`/`DecryptGCM` 函数保留（包装 `StandardCipher`）
- `KeyMetadata.CipherType` omitempty，空值默认 AES-256-GCM

### 国密合规说明

- SM2/SM3/SM4 符合 GB/T 32918、GB/T 32905、GB/T 32907
- 国密套件 + HSM 模式 = 满足金融/政务场景的"商密合规"
- 审计日志哈希链用 HMAC-SM3，符合 GM/T 0054
- README 需补充国密合规声明（非正式认证，仅算法实现）

### 实施优先级

国密支持作为 **0.3.0 的可选里程碑**（不阻塞 HSM 重构）：
1. 里程碑 1-4（HSM 重构）先完成
2. 里程碑 5：CryptoSuite 抽象 + 标准套件迁移
3. 里程碑 6：国密套件实现（`-tags gmsm`）+ 测试

## 更新后的里程碑总览

| 里程碑 | 内容 | 依赖 |
|---|---|---|
| 1 | KEK 抽象层 | 无 |
| 2 | lifecycle.Manager 签名迁移 | 1 |
| 3 | 7 调用点 + admin 适配 | 2 |
| 4 | bootstrap HSM 装配（build tag 隔离） | 3 |
| 5 | CryptoSuite 抽象 + 标准套件迁移 | 4 |
| 6 | 国密套件（SM2/SM3/SM4，`-tags gmsm`） | 5 |

