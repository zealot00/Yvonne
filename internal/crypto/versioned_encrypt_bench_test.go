package crypto

import (
	"sync"
	"testing"

	"yvonne/internal/memguard"
)

// --- 优化对比：EncryptGCM+Encode vs EncryptVersioned ---

func BenchmarkEncryptGCM_PlusEncode_64B(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64)
	b.SetBytes(int64(4 + 12 + 64 + 16))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := EncryptGCM(key, plaintext)
		// EncryptGCM 返回 [nonce][ct]，需拆分后 Encode。
		nonce := ct[:12]
		body := ct[12:]
		_ = EncodeVersionedCiphertext(1, nonce, body)
	}
}

func BenchmarkEncryptVersioned_64B(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64)
	b.SetBytes(int64(4 + 12 + 64 + 16))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptVersioned(key, 1, plaintext)
	}
}

func BenchmarkEncryptVersioned_1KB(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(1024)
	b.SetBytes(int64(4 + 12 + 1024 + 16))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptVersioned(key, 1, plaintext)
	}
}

func BenchmarkEncryptVersioned_64KB(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64 * 1024)
	b.SetBytes(int64(4 + 12 + 64*1024 + 16))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptVersioned(key, 1, plaintext)
	}
}

// --- DecryptVersioned 基准测试 ---

func BenchmarkDecryptVersioned_64B(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64)
	ct, _ := EncryptVersioned(key, 1, plaintext)
	b.SetBytes(int64(len(ct)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb, _, _ := DecryptVersioned(key, ct)
		sb.Wipe()
	}
}

func BenchmarkDecryptVersioned_1KB(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(1024)
	ct, _ := EncryptVersioned(key, 1, plaintext)
	b.SetBytes(int64(len(ct)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb, _, _ := DecryptVersioned(key, ct)
		sb.Wipe()
	}
}

// --- 并发基准测试 ---

func BenchmarkEncryptVersioned_Parallel_64B(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64)
	b.SetBytes(int64(4 + 12 + 64 + 16))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = EncryptVersioned(key, 1, plaintext)
		}
	})
}

func BenchmarkDecryptVersioned_Parallel_64B(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(64)
	ct, _ := EncryptVersioned(key, 1, plaintext)
	b.SetBytes(int64(len(ct)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sb, _, _ := DecryptVersioned(key, ct)
			sb.Wipe()
		}
	})
}

// --- 高并发模拟（多 goroutine 同时加解密）---

func BenchmarkEncryptDecrypt_Parallel_RoundTrip(b *testing.B) {
	key := newBenchKey(b)
	plaintext := makePayload(256)
	b.SetBytes(int64(4 + 12 + 256 + 16))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ct, _ := EncryptVersioned(key, 1, plaintext)
			sb, _, _ := DecryptVersioned(key, ct)
			sb.Wipe()
		}
	})
}

// --- 辅助函数 ---

func newBenchKey(b *testing.B) *memguard.SecureBuffer {
	b.Helper()
	key, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	b.Cleanup(func() { key.Wipe() })
	return key
}

// 确保 sync 包被引用（并发基准测试用）。
var _ = sync.WaitGroup{}
