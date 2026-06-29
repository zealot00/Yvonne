// Package seal - Shamir 分片冷备份（方案 C）。
//
// 将 Wrapped CMK 用 Shamir 分成 N 份，每份写入独立 USB 盘。
// 恢复时需 K 份重组，单盘丢失无风险。
//
// 文件格式（每个 USB 盘一个文件）：
//
//	[4字节魔数 "YVSB"]
//	[1字节版本号 0x01]
//	[1字节总份数 N]
//	[1字节门限 K]
//	[1字节当前序号 index 0-based]
//	[32字节 HMAC-SHA256(share, integrityKey) 完整性校验]
//	[变长 Share 数据]
//
// 安全：
//   - HMAC 校验防止 USB 盘数据损坏/篡改。
//   - 重组需 K 份，单盘丢失不泄露 CMK。
//   - integrityKey 是固定常量，仅防损坏/误用，不提供密码学保密（Shamir 分片本身提供保密）。
package seal

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"yvonne/internal/memguard"
)

// backupMagic 是冷备份文件的魔数。
var backupMagic = []byte("YVSB")

// backupVersion 是冷备份格式版本号。
const backupVersion byte = 0x01

// backupIntegrityKey 是冷备份 HMAC 校验用的固定密钥。
// 注意：这不是密码学密钥，仅用于检测 USB 盘数据损坏/误用。
// 真正的安全性来自 Shamir 分片本身（需 K 份才能重组）。
var backupIntegrityKey = []byte("yvonne-cold-backup-integrity-check-v1")

// BackupShare 是单个 USB 盘上的分片文件元数据。
type BackupShare struct {
	Version   byte
	Total     byte
	Threshold byte
	ShareIdx  byte // 序号
	HMAC      []byte
	Share     []byte
}

// SplitWrappedCMKToFiles 将 Wrapped CMK 用 Shamir 分成 N 份，
// 每份写入独立文件（对应一个 USB 盘）。
//
// 参数：
//   - wrappedCMK: 待分片的 Wrapped CMK 密文
//   - total: 总份数（如 5 个 USB 盘）
//   - threshold: 门限（如 3，需 3 份才能重组）
//   - outDir: 输出目录（每个文件名为 backup-001.dat, backup-002.dat, ...）
//
// 返回：生成的文件路径列表。
func SplitWrappedCMKToFiles(wrappedCMK []byte, total, threshold int, outDir string) ([]string, error) {
	if total < 2 || total > 255 {
		return nil, fmt.Errorf("seal: total must be 2-255, got %d", total)
	}
	if threshold < 2 || threshold > total {
		return nil, fmt.Errorf("seal: threshold must be 2-%d, got %d", total, threshold)
	}
	if len(wrappedCMK) == 0 {
		return nil, errors.New("seal: empty wrapped CMK")
	}

	// 1. 将 wrappedCMK 装入 SecureBuffer（拷贝一份，避免 NewSecureBuffer 清零入参影响调用方）。
	cmkCopy := make([]byte, len(wrappedCMK))
	copy(cmkCopy, wrappedCMK)
	sb := memguard.NewSecureBuffer(cmkCopy)
	defer sb.Wipe()

	// 2. Shamir 分片。
	shares, err := Split(sb, total, threshold)
	if err != nil {
		return nil, fmt.Errorf("seal: shamir split: %w", err)
	}

	// 校验 Shamir 参数在 byte 范围内（防 G115 整数溢出）。
	if total < 1 || total > 255 {
		return nil, fmt.Errorf("seal: total must be 1-255, got %d", total)
	}
	if threshold < 1 || threshold > 255 {
		return nil, fmt.Errorf("seal: threshold must be 1-255, got %d", threshold)
	}

	// 3. 创建输出目录（0700）。
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, fmt.Errorf("seal: mkdir: %w", err)
	}

	// 4. 每份写入独立文件。
	var paths []string
	for i, shareBytes := range shares {
		// 计算 HMAC。
		mac := hmac.New(sha256.New, backupIntegrityKey)
		mac.Write(shareBytes)
		hmacSum := mac.Sum(nil)

		// 构造文件内容。
		data := encodeBackupShare(byte(total), byte(threshold), byte(i), hmacSum, shareBytes)

		// 写入文件（0400 只读）。
		filename := filepath.Join(outDir, fmt.Sprintf("backup-%03d.dat", i+1))
		if err := os.WriteFile(filename, data, 0o400); err != nil {
			return nil, fmt.Errorf("seal: write share %d: %w", i+1, err)
		}
		paths = append(paths, filename)
	}

	return paths, nil
}

// CombineWrappedCMKFromFiles 从多个 USB 盘文件中读取分片，
// 校验 HMAC，然后用 Shamir 重组 Wrapped CMK。
//
// 参数：
//   - paths: 分片文件路径列表（至少 threshold 份）
//
// 返回：重组后的 Wrapped CMK 密文。
func CombineWrappedCMKFromFiles(paths []string) ([]byte, error) {
	if len(paths) < 2 {
		return nil, errors.New("seal: need at least 2 share files")
	}

	var shares [][]byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("seal: read %s: %w", path, err)
		}

		share, err := decodeBackupShare(data)
		if err != nil {
			return nil, fmt.Errorf("seal: decode %s: %w", path, err)
		}

		// 校验 HMAC。
		mac := hmac.New(sha256.New, backupIntegrityKey)
		mac.Write(share.Share)
		expectedMAC := mac.Sum(nil)
		if !hmac.Equal(share.HMAC, expectedMAC) {
			return nil, fmt.Errorf("seal: HMAC verification failed for %s (data corrupted or tampered)", path)
		}

		shares = append(shares, share.Share)
	}

	// Shamir 重组。
	sb, err := Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("seal: shamir combine: %w", err)
	}
	defer sb.Wipe()

	// 取出明文。
	var result []byte
	_ = sb.WithKey(func(data []byte) error {
		result = make([]byte, len(data))
		copy(result, data)
		return nil
	})
	return result, nil
}

// encodeBackupShare 序列化分片为二进制格式。
func encodeBackupShare(total, threshold, index byte, hmacSum, share []byte) []byte {
	headerSize := 4 + 1 + 1 + 1 + 1 + 32 // magic + version + total + threshold + index + hmac
	out := make([]byte, headerSize+len(share))

	copy(out[0:4], backupMagic)
	out[4] = backupVersion
	out[5] = total
	out[6] = threshold
	out[7] = index
	copy(out[8:40], hmacSum)
	copy(out[40:], share)

	return out
}

// decodeBackupShare 反序列化分片。
func decodeBackupShare(data []byte) (*BackupShare, error) {
	headerSize := 4 + 1 + 1 + 1 + 1 + 32
	if len(data) < headerSize {
		return nil, fmt.Errorf("seal: file too short: %d bytes, need at least %d", len(data), headerSize)
	}

	// 校验魔数。
	if string(data[0:4]) != string(backupMagic) {
		return nil, errors.New("seal: invalid magic (not a Yvonne backup file)")
	}

	// 校验版本。
	if data[4] != backupVersion {
		return nil, fmt.Errorf("seal: unsupported backup version %d", data[4])
	}

	share := &BackupShare{
		Version:   data[4],
		Total:     data[5],
		Threshold: data[6],
		ShareIdx:  data[7],
		HMAC:      make([]byte, 32),
		Share:     make([]byte, len(data)-headerSize),
	}
	copy(share.HMAC, data[8:40])
	copy(share.Share, data[40:])

	return share, nil
}
