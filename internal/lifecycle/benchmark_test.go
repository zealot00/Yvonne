package lifecycle

import (
	"context"
	"testing"

	"yvonne/internal/crypto"
	"yvonne/internal/memguard"
	"yvonne/internal/seal"
	"yvonne/internal/storage"
)

// BenchmarkKEK_Software_WrapUnwrap 软件 KEK（AES-256-GCM）wrap+unwrap 往返。
func BenchmarkKEK_Software_WrapUnwrap(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ct, err := kek.WrapDEK(plainDEK)
		if err != nil {
			b.Fatal(err)
		}
		dec, err := kek.UnwrapDEK(ct)
		if err != nil {
			b.Fatal(err)
		}
		dec.Wipe()
	}
}

// BenchmarkKEK_HSM_WrapUnwrap HSM KEK（MockHSMBackend）wrap+unwrap 往返。
// 注意：MockHSMBackend 用 AES-256-GCM 模拟，真实 HSM 延迟更高（10-100x）。
func BenchmarkKEK_HSM_WrapUnwrap(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ct, err := kek.WrapDEK(plainDEK)
		if err != nil {
			b.Fatal(err)
		}
		dec, err := kek.UnwrapDEK(ct)
		if err != nil {
			b.Fatal(err)
		}
		dec.Wipe()
	}
}

// BenchmarkKEK_Software_WrapOnly 软件 KEK 仅 wrap（加密）。
func BenchmarkKEK_Software_WrapOnly(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kek.WrapDEK(plainDEK)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKEK_HSM_WrapOnly HSM KEK 仅 wrap（加密）。
func BenchmarkKEK_HSM_WrapOnly(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := kek.WrapDEK(plainDEK)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKEK_Software_UnwrapOnly 软件 KEK 仅 unwrap（解密）。
func BenchmarkKEK_Software_UnwrapOnly(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()
	ct, _ := kek.WrapDEK(plainDEK)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dec, err := kek.UnwrapDEK(ct)
		if err != nil {
			b.Fatal(err)
		}
		dec.Wipe()
	}
}

// BenchmarkKEK_HSM_UnwrapOnly HSM KEK 仅 unwrap（解密）。
func BenchmarkKEK_HSM_UnwrapOnly(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)

	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()
	ct, _ := kek.WrapDEK(plainDEK)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dec, err := kek.UnwrapDEK(ct)
		if err != nil {
			b.Fatal(err)
		}
		dec.Wipe()
	}
}

// === 完整生命周期基准 ===

// BenchmarkLifecycle_Software_CreateKey 软件 KEK CreateKey。
func BenchmarkLifecycle_Software_CreateKey(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mgr := NewManager(storage.NewMemoryStore())
		_, pdek, err := mgr.CreateKey(context.Background(), "bench-key", kek, 0)
		if err != nil {
			b.Fatal(err)
		}
		pdek.Wipe()
	}
}

// BenchmarkLifecycle_HSM_CreateKey HSM KEK CreateKey。
func BenchmarkLifecycle_HSM_CreateKey(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mgr := NewManager(storage.NewMemoryStore())
		_, pdek, err := mgr.CreateKey(context.Background(), "bench-key", kek, 0)
		if err != nil {
			b.Fatal(err)
		}
		pdek.Wipe()
	}
}

// BenchmarkLifecycle_Software_RotateKey 软件 KEK RotateKey。
func BenchmarkLifecycle_Software_RotateKey(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	mgr := NewManager(storage.NewMemoryStore())
	mgr.CreateKey(context.Background(), "bench-rotate", kek, 0)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, pdek, err := mgr.RotateKey(context.Background(), "bench-rotate", kek)
		if err != nil {
			b.Fatal(err)
		}
		pdek.Wipe()
	}
}

// BenchmarkLifecycle_HSM_RotateKey HSM KEK RotateKey。
func BenchmarkLifecycle_HSM_RotateKey(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)
	mgr := NewManager(storage.NewMemoryStore())
	mgr.CreateKey(context.Background(), "bench-rotate", kek, 0)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, pdek, err := mgr.RotateKey(context.Background(), "bench-rotate", kek)
		if err != nil {
			b.Fatal(err)
		}
		pdek.Wipe()
	}
}

// BenchmarkLifecycle_Software_GDK 软件 KEK GenerateDataKey。
func BenchmarkLifecycle_Software_GDK(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	mgr := NewManager(storage.NewMemoryStore())
	mgr.CreateKey(context.Background(), "bench-gdk", kek, 0)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plainDEK, _, err := mgr.GenerateDataKey(context.Background(), "bench-gdk", kek)
		if err != nil {
			b.Fatal(err)
		}
		plainDEK.Wipe()
	}
}

// BenchmarkLifecycle_HSM_GDK HSM KEK GenerateDataKey。
func BenchmarkLifecycle_HSM_GDK(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)
	mgr := NewManager(storage.NewMemoryStore())
	mgr.CreateKey(context.Background(), "bench-gdk", kek, 0)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plainDEK, _, err := mgr.GenerateDataKey(context.Background(), "bench-gdk", kek)
		if err != nil {
			b.Fatal(err)
		}
		plainDEK.Wipe()
	}
}

// === 业务数据加解密基准（DEK 层，与 KEK 无关）===

// BenchmarkEncryptVersioned 版本化加密（DEK 加密业务数据）。
func BenchmarkEncryptVersioned(b *testing.B) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := crypto.EncryptVersioned(dek, 1, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptVersioned 版本化解密（DEK 解密业务数据）。
func BenchmarkDecryptVersioned(b *testing.B) {
	dek, _ := memguard.NewSecureBufferFromRandom(32)
	defer dek.Wipe()
	plaintext := make([]byte, 1024)
	ct, _ := crypto.EncryptVersioned(dek, 1, plaintext)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sb, _, err := crypto.DecryptVersioned(dek, ct)
		if err != nil {
			b.Fatal(err)
		}
		sb.Wipe()
	}
}

// === 并发基准 ===

// BenchmarkKEK_HSM_ConcurrentWrapUnwrap HSM KEK 并发 wrap+unwrap。
func BenchmarkKEK_HSM_ConcurrentWrapUnwrap(b *testing.B) {
	backend, _ := seal.NewMockHSMBackend()
	defer backend.Close()
	kek := seal.NewHSMKEK(backend)
	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ct, err := kek.WrapDEK(plainDEK)
			if err != nil {
				b.Fatal(err)
			}
			dec, err := kek.UnwrapDEK(ct)
			if err != nil {
				b.Fatal(err)
			}
			dec.Wipe()
		}
	})
}

// BenchmarkKEK_Software_ConcurrentWrapUnwrap 软件 KEK 并发 wrap+unwrap。
func BenchmarkKEK_Software_ConcurrentWrapUnwrap(b *testing.B) {
	mk, _ := memguard.NewSecureBufferFromRandom(32)
	defer mk.Wipe()
	kek := seal.NewSoftwareKEK(mk)
	plainDEK, _ := memguard.NewSecureBufferFromRandom(32)
	defer plainDEK.Wipe()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ct, err := kek.WrapDEK(plainDEK)
			if err != nil {
				b.Fatal(err)
			}
			dec, err := kek.UnwrapDEK(ct)
			if err != nil {
				b.Fatal(err)
			}
			dec.Wipe()
		}
	})
}
