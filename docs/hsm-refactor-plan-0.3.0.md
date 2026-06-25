# Yvonne KMS 0.3.0 HSM BackendRef 适配重构计划

## 背景与目标

当前 HSM 模式不可用：`HSMUnsealer.MasterKeyRef` 返回 error（设计上拒绝暴露明文 CMK），而主业务路径全部依赖此闭包。HSM 模式应通过 `CryptoBackend.Wrap/Unwrap` 工作，让 CMK 明文永不离开芯片。

**核心思路**：引入 `KEK`（Key Encryption Key）抽象接口，统一软件 CMK 和 HSM backend。7 个生产调用点从 `MasterKeyRef` 改为 `KEKRef`。`softwareKEK` 内部调 `crypto.EncryptGCM`/`DecryptGCM`，密文格式与现状字节级一致（零数据迁移）。

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
