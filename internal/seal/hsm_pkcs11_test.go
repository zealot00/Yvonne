//go:build hsm && pkcs11

// SoftHSM CI 测试。
//
// 前置：SoftHSM2 已安装 + slot 已初始化。
//
// 安装 SoftHSM2：
//
//	brew install softhsm          # macOS
//	apt install softhsm2          # Ubuntu/Debian
//
// 初始化测试 slot：
//
//	softhsm2-util --init-token --slot 0 --label "yvonne-test" --so-pin 1234 --pin 1234
//
// 运行：
//
//	YVONNE_PKCS11_LIB=/usr/local/lib/softhsm/libsofthsm2.so \
//	YVONNE_PKCS11_SLOT=0 \
//	YVONNE_PKCS11_PIN=1234 \
//	go test -tags 'hsm,pkcs11' -race -v -timeout 60s ./internal/seal/ -run TestPKCS11
package seal

import (
	"os"
	"testing"
)

// pkcs11TestConfig 从环境变量读取测试配置。
func pkcs11TestConfig(t *testing.T) (libPath string, slot int, pin string) {
	t.Helper()
	libPath = os.Getenv("YVONNE_PKCS11_LIB")
	if libPath == "" {
		t.Skip("YVONNE_PKCS11_LIB not set, skipping PKCS#11 test")
	}
	slot = 0
	if s := os.Getenv("YVONNE_PKCS11_SLOT"); s != "" {
		// 简化：直接用 slot 号。
	}
	pin = os.Getenv("YVONNE_PKCS11_PIN")
	if pin == "" {
		pin = "1234" // SoftHSM 默认
	}
	return
}

// TestPKCS11_NewBackend 创建 PKCS#11 后端。
func TestPKCS11_NewBackend(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-test-key")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	t.Log("✅ PKCS#11 backend created")
}

// TestPKCS11_WrapUnwrap 加解密往返。
func TestPKCS11_WrapUnwrap(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-wrap-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	plaintext := []byte("hello PKCS#11 HSM test data")

	// Wrap。
	ciphertext, err := backend.Wrap(plaintext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(ciphertext) < 28 { // 12 nonce + 16 tag 最小
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}
	t.Logf("Wrapped: %d bytes", len(ciphertext))

	// Unwrap。
	decrypted, err := backend.Unwrap(ciphertext)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
	t.Log("✅ Wrap/Unwrap round-trip passed")
}

// TestPKCS11_TamperedCiphertext 篡改检测。
func TestPKCS11_TamperedCiphertext(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-tamper-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	ciphertext, _ := backend.Wrap([]byte("tamper test"))

	// 篡改最后一字节。
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = backend.Unwrap(ciphertext)
	if err == nil {
		t.Fatal("tampered ciphertext should fail")
	}
	t.Log("✅ Tampered ciphertext correctly rejected")
}

// TestPKCS11_KeyReuse 密钥复用（同一 KeyID 多次创建后端复用密钥）。
func TestPKCS11_KeyReuse(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)
	keyID := "yvonne-pkcs11-reuse-test"

	// 第一次创建后端（自动生成密钥）。
	backend1, err := NewPKCS11Backend(libPath, slot, pin, keyID)
	if err != nil {
		t.Fatalf("NewPKCS11Backend 1: %v", err)
	}

	plaintext := []byte("reuse test")
	ciphertext, _ := backend1.Wrap(plaintext)

	// 关闭后端。
	if closer, ok := backend1.(interface{ Close() error }); ok {
		closer.Close()
	}

	// 第二次创建后端（复用已有密钥）。
	backend2, err := NewPKCS11Backend(libPath, slot, pin, keyID)
	if err != nil {
		t.Fatalf("NewPKCS11Backend 2: %v", err)
	}
	defer func() {
		if closer, ok := backend2.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	// 用新后端解密旧密文。
	decrypted, err := backend2.Unwrap(ciphertext)
	if err != nil {
		t.Fatalf("Unwrap with reused key: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("reuse key decrypt mismatch")
	}
	t.Log("✅ Key reuse across backend restart works")
}

// TestPKCS11_Concurrent 并发安全。
func TestPKCS11_Concurrent(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-concurrent-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			ct, e := backend.Wrap([]byte("concurrent"))
			if e != nil {
				done <- e
				return
			}
			_, e = backend.Unwrap(ct)
			done <- e
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent error: %v", err)
		}
	}
	t.Log("✅ 10 concurrent Wrap/Unwrap operations passed")
}

// === 签名验签测试 ===

// TestPKCS11_GenerateSigningKey_RSA 生成 RSA-2048 签名密钥。
func TestPKCS11_GenerateSigningKey_RSA(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-rsa-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer, ok := backend.(SignerBackend)
	if !ok {
		t.Fatal("backend should implement SignerBackend")
	}

	pubPEM, err := signer.GenerateSigningKey("rsa-sign-key", "rsa-2048")
	if err != nil {
		t.Fatalf("GenerateSigningKey RSA: %v", err)
	}
	if len(pubPEM) == 0 {
		t.Fatal("public key PEM should not be empty")
	}
	t.Logf("✅ Generated RSA-2048 signing key, public key: %d bytes PEM", len(pubPEM))
}

// TestPKCS11_GenerateSigningKey_ECDSA 生成 ECDSA-P256 签名密钥。
func TestPKCS11_GenerateSigningKey_ECDSA(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-ecdsa-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)

	pubPEM, err := signer.GenerateSigningKey("ecdsa-sign-key", "ecdsa-p256")
	if err != nil {
		t.Fatalf("GenerateSigningKey ECDSA: %v", err)
	}
	if len(pubPEM) == 0 {
		t.Fatal("public key PEM should not be empty")
	}
	t.Logf("✅ Generated ECDSA-P256 signing key, public key: %d bytes PEM", len(pubPEM))
}

// TestPKCS11_SignVerify_RSA RSA 签名+验签往返。
func TestPKCS11_SignVerify_RSA(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-signrsa-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)

	// 生成密钥。
	keyID := "rsa-sign-verify-test"
	_, err = signer.GenerateSigningKey(keyID, "rsa-2048")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	// 签名。
	msg := []byte("message to sign via HSM RSA")
	sig, err := signer.Sign(keyID, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}
	t.Logf("✅ RSA signed: %d bytes", len(sig))

	// 验签。
	ok, err := signer.Verify(keyID, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("signature verification failed")
	}
	t.Log("✅ RSA signature verified")
}

// TestPKCS11_SignVerify_ECDSA ECDSA 签名+验签往返。
func TestPKCS11_SignVerify_ECDSA(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-signecdsa-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)

	keyID := "ecdsa-sign-verify-test"
	_, err = signer.GenerateSigningKey(keyID, "ecdsa-p256")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	msg := []byte("message to sign via HSM ECDSA")
	sig, err := signer.Sign(keyID, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("✅ ECDSA signed: %d bytes", len(sig))

	ok, err := signer.Verify(keyID, msg, sig)
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	t.Log("✅ ECDSA signature verified")
}

// TestPKCS11_VerifyTampered 篡改消息后验签失败。
func TestPKCS11_VerifyTampered(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-tamper-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)
	keyID := "tamper-sign-test"

	signer.GenerateSigningKey(keyID, "rsa-2048")

	msg := []byte("original message")
	sig, _ := signer.Sign(keyID, msg)

	// 篡改消息。
	ok, _ := signer.Verify(keyID, []byte("tampered message"), sig)
	if ok {
		t.Fatal("tampered message should fail verification")
	}
	t.Log("✅ Tampered message correctly rejected")
}

// TestPKCS11_GetPublicKey 导出公钥。
func TestPKCS11_GetPublicKey(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-getpub-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)
	keyID := "getpub-test"

	// 生成时返回公钥。
	pubPEM1, err := signer.GenerateSigningKey(keyID, "ecdsa-p256")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	// GetPublicKey 再次导出。
	pubPEM2, err := signer.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	// 两次公钥应一致。
	if string(pubPEM1) != string(pubPEM2) {
		t.Fatal("public key should be consistent")
	}
	t.Log("✅ GetPublicKey returns consistent public key")
}

// TestPKCS11_SignKeyNotFound 签名不存在的密钥。
func TestPKCS11_SignKeyNotFound(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-notfound-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)

	_, err = signer.Sign("nonexistent-key", []byte("test"))
	if err == nil {
		t.Fatal("sign with nonexistent key should fail")
	}
	t.Logf("✅ Correctly rejected: %v", err)
}

// TestPKCS11_GenerateUnsupportedAlgo 不支持的算法。
func TestPKCS11_GenerateUnsupportedAlgo(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-unsup-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)

	_, err = signer.GenerateSigningKey("bad-algo-key", "ed25519")
	if err == nil {
		t.Fatal("unsupported algo should fail")
	}
	t.Logf("✅ Correctly rejected unsupported algo: %v", err)
}

// TestPKCS11_ConcurrentSign 并发签名。
func TestPKCS11_ConcurrentSign(t *testing.T) {
	libPath, slot, pin := pkcs11TestConfig(t)

	backend, err := NewPKCS11Backend(libPath, slot, pin, "yvonne-pkcs11-sym-concsign-test")
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	defer func() {
		if closer, ok := backend.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	signer := backend.(SignerBackend)
	keyID := "concurrent-sign-test"
	signer.GenerateSigningKey(keyID, "rsa-2048")

	msg := []byte("concurrent signing test")
	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			sig, e := signer.Sign(keyID, msg)
			if e != nil {
				done <- e
				return
			}
			_, e = signer.Verify(keyID, msg, sig)
			done <- e
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent sign error: %v", err)
		}
	}
	t.Log("✅ 10 concurrent sign/verify operations passed")
}
