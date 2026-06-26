# Yvonne KMS SDK 示例集

> 完整可运行的 Go 代码示例，覆盖 KMS 全生命周期场景。

## 快速开始

```bash
# 启动 Dev 模式（含演示密钥）
yvonne dev --demo --port 8200

# 运行示例
go run sdk/examples/quickstart/main.go
```

## 示例列表

| 示例 | 说明 | 文件 |
|---|---|---|
| [快速开始](#快速开始) | 加密+解密+轮转 | `sdk/examples/quickstart/main.go` |
| [信封加密](#信封加密) | GDK 客户端加密 | `sdk/examples/envelope/main.go` |
| [密钥生命周期](#密钥生命周期) | 创建+轮转+软删+粉碎 | `sdk/examples/lifecycle/main.go` |
| [错误处理](#错误处理) | 权限拒绝+Sealed+NotFound | `sdk/examples/errors/main.go` |
| [批量加密](#批量加密) | 循环加密+性能参考 | `sdk/examples/benchmark/main.go` |

---

## 快速开始

```go
package main

import (
    "context"
    "fmt"
    "log"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8200", "") // Dev 模式无 token
    ctx := context.Background()

    // 1. 健康检查
    health, _ := client.Health(ctx)
    fmt.Printf("State: %s\n", health.State)

    // 2. 创建密钥
    createResp, _ := client.CreateKey(ctx, &yvonne.CreateKeyRequest{
        KeyID: "my-key",
    })
    fmt.Printf("Created: %s v%d\n", createResp.KeyID, createResp.Version)

    // 3. 加密
    encResp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID:     "my-key",
        Plaintext: []byte("Hello Yvonne!"),
    })
    fmt.Printf("Encrypted: v%d, %d bytes\n", encResp.Version, len(encResp.Ciphertext))

    // 4. 解密
    decResp, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
        KeyID:      "my-key",
        Ciphertext: encResp.Ciphertext,
    })
    fmt.Printf("Decrypted: %s\n", string(decResp.Plaintext))
}
```

## 信封加密

```go
package main

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8200", "")
    ctx := context.Background()

    // 1. 从 KMS 获取数据密钥（GDK）
    gdk, _ := client.GenerateDataKey(ctx, "envelope-key")
    fmt.Printf("Got DEK: %d bytes, ciphertext: %d bytes\n",
        len(gdk.PlaintextDEK), len(gdk.CiphertextDEK))

    // 2. 用 DEK 加密大文件（本地，不经过 KMS）
    plaintext := []byte("large file content...")
    ciphertext := encryptAESGCM(gdk.PlaintextDEK, plaintext)

    // 3. 存储：密文 DEK + 加密数据（KMS 不接触明文）
    fmt.Printf("Stored: DEK ciphertext (%d bytes) + data (%d bytes)\n",
        len(gdk.CiphertextDEK), len(ciphertext))

    // 4. 解密时：用 KMS 解密 DEK，再用 DEK 解密数据
    // （此处省略，用 client.Decrypt 解密 gdk.CiphertextDEK）
}

func encryptAESGCM(key, plaintext []byte) []byte {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    return gcm.Seal(nonce, nonce, plaintext, nil)
}
```

## 密钥生命周期

```go
package main

import (
    "context"
    "fmt"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8200", "")
    ctx := context.Background()

    // 创建
    client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "lifecycle-key"})
    fmt.Println("✅ Created v1")

    // 轮转
    rotResp, _ := client.RotateKey(ctx, "lifecycle-key")
    fmt.Printf("✅ Rotated to v%d\n", rotResp.Version)

    // 旧密文仍可解密（向后兼容）
    encV1, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID: "lifecycle-key",
        Plaintext: []byte("old data"),
    })
    decV1, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
        KeyID: "lifecycle-key",
        Ciphertext: encV1.Ciphertext,
    })
    fmt.Printf("✅ v1 ciphertext still decrypts: %s\n", string(decV1.Plaintext))

    // 物理粉碎 v1
    client.ShredKey(ctx, "lifecycle-key", 1)
    fmt.Println("✅ Shredded v1")

    // v1 密文现在无法解密
    _, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
        KeyID: "lifecycle-key",
        Ciphertext: encV1.Ciphertext,
    })
    if err != nil {
        fmt.Printf("✅ v1 ciphertext correctly rejected: %v\n", err)
    }
}
```

## 错误处理

```go
package main

import (
    "context"
    "fmt"
    "log"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8200", "invalid-token")
    ctx := context.Background()

    _, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID: "any-key",
        Plaintext: []byte("test"),
    })
    if err != nil {
        // SDK 错误格式："yvonne: HTTP 401: authentication failed"
        // 或 "yvonne: HTTP 403: access denied: role ..."
        log.Printf("Error: %v\n", err)

        // 按状态码分类处理
        if isHTTPError(err, 401) {
            fmt.Println("Token 无效或过期，请检查凭证")
        } else if isHTTPError(err, 403) {
            fmt.Println("权限不足，检查 Policy AllowedKeys/AllowedActions")
        } else if isHTTPError(err, 503) {
            fmt.Println("Vault Sealed 或数据库不可用（degraded 模式）")
        }
    }
}

func isHTTPError(err error, code int) bool {
    return strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", code))
}
```

## 批量加密

```go
package main

import (
    "context"
    "fmt"
    "time"

    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.New("http://127.0.0.1:8200", "")
    ctx := context.Background()

    client.CreateKey(ctx, &yvonne.CreateKeyRequest{KeyID: "bench-key"})

    plaintext := []byte("benchmark data 1024 bytes...")
    count := 1000

    start := time.Now()
    for i := 0; i < count; i++ {
        _, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
            KeyID: "bench-key",
            Plaintext: plaintext,
        })
        if err != nil {
            fmt.Printf("Error at %d: %v\n", i, err)
            return
        }
    }
    elapsed := time.Since(start)
    fmt.Printf("Encrypted %d items in %v (%.0f ops/sec)\n",
        count, elapsed, float64(count)/elapsed.Seconds())
}
```
