// 示例：快速开始 — 加密+解密+轮转全流程。
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
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Health: %v", err)
	}
	fmt.Printf("State: %s\n", health.State)

	// 2. 创建密钥
	createResp, err := client.CreateKey(ctx, &yvonne.CreateKeyRequest{
		KeyID: "quickstart-key",
	})
	if err != nil {
		log.Fatalf("CreateKey: %v", err)
	}
	fmt.Printf("Created: %s v%d\n", createResp.KeyID, createResp.Version)

	// 3. 加密
	encResp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
		KeyID:     "quickstart-key",
		Plaintext: []byte("Hello Yvonne!"),
	})
	if err != nil {
		log.Fatalf("Encrypt: %v", err)
	}
	fmt.Printf("Encrypted: v%d, %d bytes\n", encResp.Version, len(encResp.Ciphertext))

	// 4. 解密
	decResp, err := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "quickstart-key",
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		log.Fatalf("Decrypt: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", string(decResp.Plaintext))

	// 5. 轮转
	rotResp, err := client.RotateKey(ctx, "quickstart-key")
	if err != nil {
		log.Fatalf("RotateKey: %v", err)
	}
	fmt.Printf("Rotated to v%d\n", rotResp.Version)

	// 6. 旧密文仍可解密（向后兼容）
	decOld, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
		KeyID:      "quickstart-key",
		Ciphertext: encResp.Ciphertext,
	})
	fmt.Printf("v1 still decrypts: %s\n", string(decOld.Plaintext))

	fmt.Println("\n✅ Quickstart complete!")
}
