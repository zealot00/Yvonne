package config

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// generateRSAKey 生成 RSA 测试密钥。
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}
