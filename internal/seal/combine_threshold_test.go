package seal

import (
	"testing"

	"yvonne/internal/memguard"
)

// TestCombineWithThreshold_Sufficient 验证达到 threshold 成功。
func TestCombineWithThreshold_Sufficient(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// 3 份达 threshold，应成功。
	combined, err := CombineWithThreshold(shares[:3], 3)
	if err != nil {
		t.Fatalf("CombineWithThreshold: %v", err)
	}
	defer combined.Wipe()

	// 验证还原正确。
	var orig, got []byte
	_ = secret.WithKey(func(k []byte) error { orig = make([]byte, len(k)); copy(orig, k); return nil })
	_ = combined.WithKey(func(k []byte) error { got = make([]byte, len(k)); copy(got, k); return nil })
	defer func() {
		for i := range orig {
			orig[i] = 0
		}
		for i := range got {
			got[i] = 0
		}
	}()

	if string(orig) != string(got) {
		t.Fatal("combined secret mismatch")
	}
}

// TestCombineWithThreshold_Insufficient 验证不足 threshold 失败。
func TestCombineWithThreshold_Insufficient(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// 2 份不足 threshold=3，应失败。
	_, err = CombineWithThreshold(shares[:2], 3)
	if err == nil {
		t.Fatal("CombineWithThreshold with 2 < 3 should fail")
	}
}

// TestCombineWithThreshold_ZeroThresholdNoCheck 验证 threshold=0 不校验。
func TestCombineWithThreshold_ZeroThresholdNoCheck(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 5, 3)

	// threshold=0 退化为 Combine，2 份也允许（虽然结果无意义但不报错）。
	_, err := CombineWithThreshold(shares[:2], 0)
	if err != nil {
		t.Fatalf("threshold=0 should not check: %v", err)
	}
}

// TestCombine_BackwardCompat 验证原 Combine 保持兼容。
func TestCombine_BackwardCompat(t *testing.T) {
	secret, _ := memguard.NewSecureBufferFromRandom(32)
	defer secret.Wipe()

	shares, _ := Split(secret, 3, 2)

	// Combine 不校验 threshold，2 份即可。
	combined, err := Combine(shares[:2])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	combined.Wipe()
}
