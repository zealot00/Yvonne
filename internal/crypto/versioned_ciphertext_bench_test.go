package crypto

import (
	"encoding/binary"
	"testing"
)

// 生成指定大小的随机密文体（避免基准测试被零值优化）。
func makePayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

// --- EncodeVersionedCiphertext 基准测试 ---

func BenchmarkEncodeVersionedCiphertext_64B(b *testing.B) {
	version := uint32(1)
	nonce := makePayload(12)
	ct := makePayload(64)
	b.SetBytes(int64(4 + 12 + 64))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeVersionedCiphertext(version, nonce, ct)
	}
}

func BenchmarkEncodeVersionedCiphertext_1KB(b *testing.B) {
	version := uint32(1)
	nonce := makePayload(12)
	ct := makePayload(1024)
	b.SetBytes(int64(4 + 12 + 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeVersionedCiphertext(version, nonce, ct)
	}
}

func BenchmarkEncodeVersionedCiphertext_64KB(b *testing.B) {
	version := uint32(1)
	nonce := makePayload(12)
	ct := makePayload(64 * 1024)
	b.SetBytes(int64(4 + 12 + 64*1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeVersionedCiphertext(version, nonce, ct)
	}
}

// --- DecodeVersionedCiphertext 基准测试 ---

func BenchmarkDecodeVersionedCiphertext_64B(b *testing.B) {
	raw := EncodeVersionedCiphertext(1, makePayload(12), makePayload(64))
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = DecodeVersionedCiphertext(raw)
	}
}

func BenchmarkDecodeVersionedCiphertext_1KB(b *testing.B) {
	raw := EncodeVersionedCiphertext(1, makePayload(12), makePayload(1024))
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = DecodeVersionedCiphertext(raw)
	}
}

func BenchmarkDecodeVersionedCiphertext_64KB(b *testing.B) {
	raw := EncodeVersionedCiphertext(1, makePayload(12), makePayload(64*1024))
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = DecodeVersionedCiphertext(raw)
	}
}

// --- ExtractVersion 基准测试 ---

func BenchmarkExtractVersion(b *testing.B) {
	raw := EncodeVersionedCiphertext(42, makePayload(12), makePayload(64))
	b.SetBytes(4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractVersion(raw)
	}
}

// --- 对比：手动 binary.BigEndian vs EncodeVersionedCiphertext ---

func BenchmarkManualBigEndian(b *testing.B) {
	raw := make([]byte, 4+12+64)
	nonce := makePayload(12)
	ct := makePayload(64)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(raw[:4], 1)
		copy(raw[4:16], nonce)
		copy(raw[16:], ct)
	}
}
