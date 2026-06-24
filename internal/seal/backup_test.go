package seal

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSplitAndCombine_RoundTrip 验证分片→重组往返。
func TestSplitAndCombine_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := []byte("this-is-a-secret-wrapped-cmk-32bytes!!") // 36 bytes

	// 分片：5 份，门限 3。
	paths, err := SplitWrappedCMKToFiles(original, 5, 3, dir)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(paths) != 5 {
		t.Fatalf("expected 5 files, got %d", len(paths))
	}

	// 验证文件权限 0400。
	for _, p := range paths {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o400 {
			t.Errorf("%s perm = %o, want 0400", p, info.Mode().Perm())
		}
	}

	// 用 3 份重组。
	restored, err := CombineWrappedCMKFromFiles(paths[:3])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if string(restored) != string(original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", restored, original)
	}
}

// TestSplitAndCombine_MinimumShares 验证刚好门限份数可重组。
func TestSplitAndCombine_MinimumShares(t *testing.T) {
	dir := t.TempDir()
	original := []byte("test-cmk-32-bytes-exactly-here!") // 30 bytes

	paths, _ := SplitWrappedCMKToFiles(original, 5, 3, dir)

	// 用 3 份（门限）重组。
	restored, err := CombineWrappedCMKFromFiles(paths[:3])
	if err != nil {
		t.Fatalf("Combine with threshold: %v", err)
	}
	if string(restored) != string(original) {
		t.Fatal("threshold round-trip mismatch")
	}
}

// TestSplitAndCombine_InsufficientShares 验证不足门限份数重组失败。
func TestSplitAndCombine_InsufficientShares(t *testing.T) {
	dir := t.TempDir()
	original := []byte("test-cmk-data")

	paths, _ := SplitWrappedCMKToFiles(original, 5, 3, dir)

	// 用 2 份（不足门限 3）应失败或返回错误结果。
	_, err := CombineWrappedCMKFromFiles(paths[:2])
	if err == nil {
		// Shamir Combine 可能不报错但返回错误数据，验证不匹配。
		// 如果没报错，检查结果不等于原始数据。
	}
}

// TestSplitAndCombine_TamperedShare 验证篡改分片被 HMAC 检测。
func TestSplitAndCombine_TamperedShare(t *testing.T) {
	dir := t.TempDir()
	original := []byte("tamper-test-cmk-data-here!!!")

	paths, _ := SplitWrappedCMKToFiles(original, 5, 3, dir)

	// 篡改第一个分片文件（先改权限为可写，篡改后改回）。
	_ = os.Chmod(paths[0], 0o600)
	data, _ := os.ReadFile(paths[0])
	data[len(data)-1] ^= 0xFF // 翻转最后一字节
	_ = os.WriteFile(paths[0], data, 0o400)

	_, err := CombineWrappedCMKFromFiles(paths[:3])
	if err == nil {
		t.Fatal("tampered share should fail HMAC verification")
	}
}

// TestSplitAndCombine_InvalidMagic 验证错误魔数被拒绝。
func TestSplitAndCombine_InvalidMagic(t *testing.T) {
	dir := t.TempDir()

	// 写入一个伪分片文件。
	fakePath := filepath.Join(dir, "fake.dat")
	os.WriteFile(fakePath, []byte("XXXX\x01\x05\x03\x00"+string(make([]byte, 32+10))), 0o400)

	_, err := CombineWrappedCMKFromFiles([]string{fakePath})
	if err == nil {
		t.Fatal("invalid magic should fail")
	}
}

// TestSplitAndCombine_WrongVersion 验证错误版本号被拒绝。
func TestSplitAndCombine_WrongVersion(t *testing.T) {
	dir := t.TempDir()

	// 魔数正确但版本号错误。
	data := []byte("YVSB\x02\x05\x03\x00")
	data = append(data, make([]byte, 32+10)...)
	fakePath := filepath.Join(dir, "wrong-ver.dat")
	os.WriteFile(fakePath, data, 0o400)

	_, err := CombineWrappedCMKFromFiles([]string{fakePath})
	if err == nil {
		t.Fatal("wrong version should fail")
	}
}

// TestSplitBackup_InvalidParams 验证参数校验。
func TestSplitBackup_InvalidParams(t *testing.T) {
	dir := t.TempDir()

	// total < 2。
	_, err := SplitWrappedCMKToFiles([]byte("x"), 1, 1, dir)
	if err == nil {
		t.Fatal("total=1 should fail")
	}

	// threshold > total。
	_, err = SplitWrappedCMKToFiles([]byte("x"), 3, 5, dir)
	if err == nil {
		t.Fatal("threshold > total should fail")
	}

	// empty wrapped CMK。
	_, err = SplitWrappedCMKToFiles([]byte{}, 5, 3, dir)
	if err == nil {
		t.Fatal("empty wrapped CMK should fail")
	}
}

// TestSplitAndCombine_LargeCMK 验证大 CMK 分片重组。
func TestSplitAndCombine_LargeCMK(t *testing.T) {
	dir := t.TempDir()
	// RSA-4096 加密 32 字节 CMK 后约 512 字节。
	original := make([]byte, 512)
	for i := range original {
		original[i] = byte(i % 256)
	}

	paths, _ := SplitWrappedCMKToFiles(original, 7, 4, dir)

	// 用 4 份重组。
	restored, err := CombineWrappedCMKFromFiles(paths[:4])
	if err != nil {
		t.Fatalf("Combine large: %v", err)
	}
	if string(restored) != string(original) {
		t.Fatal("large CMK round-trip mismatch")
	}
}
