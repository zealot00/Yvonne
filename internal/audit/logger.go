// Package audit - 双写审计日志引擎（哈希链 + 文件 + Syslog）。
//
// 架构（锁粒度拆分）：
//
//	Record(entry)
//	  │
//	  ├─ [1] chainMu.Lock() ── 哈希链计算（严格串行，微秒级）
//	  │     computeAndAdvance(key, payload) → signature
//	  │     chainMu.Unlock()
//	  │
//	  ├─ [2] 序列化 signedEnvelope（无锁）
//	  │
//	  ├─ [3] fileRotator.Write() ── 文件写入（自有锁，file.Sync 高危操作）
//	  │
//	  └─ [4] syslogWriter.Write() ── 异步 channel（零阻塞）
//
// 关键设计：
//   - 哈希链计算用独立锁 chainMu，仅保护 lastSignature 读写（微秒级）。
//   - 文件 I/O 用 fileRotator 自己的锁，不与哈希链锁耦合。
//   - Syslog 写入异步 channel，零阻塞。
//   - 并发 Record 调用时，哈希链串行排队，但 I/O 可并行。
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"yvonne/internal/memguard"
)

// LogEntry 是审计日志的元数据结构（合规实体）。
//
// 脱敏红线：本结构体绝不包含明文/密文/碎片/密钥。
type LogEntry struct {
	TraceID   string    `json:"trace_id"`
	Timestamp time.Time `json:"timestamp"`        // ISO8601
	ClientIP  string    `json:"client_ip"`        // 调用方 IP
	Actor     string    `json:"actor"`            // AppRole ID / 用户 ID
	Resource  string    `json:"resource"`         // 操作的资源（如 key_id）
	Action    string    `json:"action"`           // Encrypt/Decrypt/Rotate/ShredKey/SysUnseal...
	Result    string    `json:"result"`           // success / failure / denied
	KeyID     string    `json:"key_id,omitempty"` // 向后兼容
	Status    string    `json:"status,omitempty"` // 向后兼容
}

// signedEnvelope 是落盘的最终格式：原 JSON payload + 签名 + 前一条签名 + 链条序号。
//
// PrevSignature 使每条日志自包含链条上下文，可独立验证（无需按序重放）。
// 第一条日志的 PrevSignature = SHA256(AuditKey)（初始锚定）。
type signedEnvelope struct {
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`      // HMAC-SHA256(key, prevSig + payload)
	PrevSignature string `json:"prev_signature"` // 前一条日志的 signature（链头锚定为 SHA256(AuditKey)）
	ChainSeq      uint64 `json:"chain_seq"`      // 链条序号（递增）
}

// AuditLogger 是防篡改双写审计日志引擎。
//
// 组合：
//   - hashChain: 哈希链计算（chainMu 保护，严格串行）
//   - FileRotator: 本地文件轮转（自有锁）
//   - SyslogWriter: 异步 Syslog（channel 解耦，可为 nil）
type AuditLogger struct {
	chain    *hashChain
	chainMu  sync.Mutex    // 仅保护哈希链计算（微秒级）
	chainSeq atomic.Uint64 // 链条序号

	auditKey       *memguard.SecureBuffer
	fileRotator    *FileRotator  // 可为 nil（测试用 io.Writer）
	syslogWriter   *SyslogWriter // 可为 nil（无 syslog）
	fallbackWriter io.Writer     // 无 fileRotator 时的回退（如 os.Stdout / buffer）

	// 链头锚定持久化文件路径（如 /var/log/yvonne/audit.chain）。
	// 进程重启后从此文件恢复 lastSignature，保证链条不断裂。
	anchorFile string

	// 无 fileRotator 时用 fallbackWriter + fallbackMu。
	fallbackMu sync.Mutex
}

// NewAuditLogger 创建 AuditLogger（基础版，仅 fallback writer）。
// 启动时通过 CSPRNG 生成 32 字节 AuditKey。
// writer 为 nil 时用 io.Discard。
func NewAuditLogger(writer io.Writer) (*AuditLogger, error) {
	key, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		return nil, fmt.Errorf("audit: generate audit key: %w", err)
	}
	if writer == nil {
		writer = io.Discard
	}

	// 初始化哈希链。
	var chainKey []byte
	_ = key.WithKey(func(k []byte) error {
		chainKey = make([]byte, len(k))
		copy(chainKey, k)
		return nil
	})

	return &AuditLogger{
		auditKey:       key,
		chain:          newHashChain(chainKey),
		fallbackWriter: writer,
	}, nil
}

// NewAuditLoggerWithHash 创建 AuditLogger（自定义 hash 函数，用于国密 HMAC-SM3）。
func NewAuditLoggerWithHash(writer io.Writer, newHash func() hash.Hash, anchorHash func([]byte) []byte) (*AuditLogger, error) {
	key, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		return nil, fmt.Errorf("audit: generate audit key: %w", err)
	}
	if writer == nil {
		writer = io.Discard
	}

	var chainKey []byte
	_ = key.WithKey(func(k []byte) error {
		chainKey = make([]byte, len(k))
		copy(chainKey, k)
		return nil
	})

	return &AuditLogger{
		auditKey:       key,
		chain:          newHashChainWithHash(chainKey, newHash, anchorHash),
		fallbackWriter: writer,
	}, nil
}

// NewDualWriteLogger 创建双写 AuditLogger（文件 + Syslog）。
//
// dir: 日志目录（如 /var/log/yvonne）。
// filename: 当前日志文件名（如 audit.log）。
// retentionDays: 历史日志留存天数（如 180）。
//
// syslogWriter 为 nil 时仅写文件。
func NewDualWriteLogger(dir, filename string, retentionDays int, sw *SyslogWriter) (*AuditLogger, error) {
	key, err := memguard.NewSecureBufferFromRandom(32)
	if err != nil {
		return nil, fmt.Errorf("audit: generate audit key: %w", err)
	}

	// 初始化哈希链。
	var chainKey []byte
	_ = key.WithKey(func(k []byte) error {
		chainKey = make([]byte, len(k))
		copy(chainKey, k)
		return nil
	})

	// 创建文件轮转器。
	rotator, err := NewFileRotator(dir, filename)
	if err != nil {
		key.Wipe()
		return nil, err
	}

	// 链头锚定文件：启动时恢复 lastSignature，保证重启后链条不断裂。
	anchorPath := filepath.Join(dir, "audit.chain")
	chain := newHashChain(chainKey)
	if err := loadAnchor(anchorPath, chain); err != nil {
		// BUG-10 修复：anchor 文件损坏/丢失时不再静默重置。
		// 区分首次启动（文件不存在）和损坏（存在但格式错误）。
		if os.IsNotExist(err) {
			// 首次启动：正常，用初始值。
			log.Printf("audit: anchor file not found, starting fresh chain")
		} else {
			// 文件存在但损坏：返回 error，拒绝启动（防哈希链断裂）。
			return nil, fmt.Errorf("audit: anchor file corrupted: %w (manual intervention required)", err)
		}
	}

	// 启动 180 天清理 goroutine。
	rotator.StartPruneLoop(retentionDays, func(deletedCount int) {
		// 清理动作本身记录为审计日志。
		_ = (&AuditLogger{
			auditKey:     key,
			chain:        chain,
			fileRotator:  rotator,
			syslogWriter: sw,
			anchorFile:   anchorPath,
		}).Record(LogEntry{
			Timestamp: time.Now().UTC(),
			Action:    "AUDIT_LOG_PRUNE",
			Result:    fmt.Sprintf("deleted %d files", deletedCount),
		})
	})

	return &AuditLogger{
		auditKey:     key,
		chain:        chain,
		fileRotator:  rotator,
		syslogWriter: sw,
		anchorFile:   anchorPath,
	}, nil
}

// Record 记录一条审计日志。
//
// 锁粒度拆分：
//  1. chainMu.Lock() — 哈希链计算（微秒级，严格串行）
//  2. 序列化 envelope（无锁）
//  3. 文件写入（fileRotator 自有锁）
//  4. Syslog 异步写入（channel，零阻塞）
//
// I/O 操作不持有 chainMu，高并发加解密时无性能瓶颈。
func (l *AuditLogger) Record(entry LogEntry) error {
	// 填充时间戳（如未设置）。
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// 1. 序列化为 JSON payload。
	payloadBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}

	// 2. 哈希链计算（chainMu 保护，严格串行，微秒级）。
	var sig, prevSig string
	var seq uint64
	l.chainMu.Lock()
	_ = l.auditKey.WithKey(func(key []byte) error {
		sig, prevSig = l.chain.computeAndAdvance(key, payloadBytes)
		return nil
	})
	seq = l.chainSeq.Add(1)
	l.chainMu.Unlock()

	// 2b. 持久化链头锚定（原子写入，保证重启后链条不断裂）。
	// 锚定写入失败不阻断日志记录（日志本身已含 PrevSignature，可自验证）。
	_ = l.saveAnchor()

	// 3. 序列化最终信封（无锁）。PrevSignature 使每条日志可独立验证。
	envelope := signedEnvelope{
		Payload:       string(payloadBytes),
		Signature:     sig,
		PrevSignature: prevSig,
		ChainSeq:      seq,
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("audit: marshal envelope: %w", err)
	}

	// 4. 写入文件（fileRotator 自有锁，不持 chainMu）。
	if l.fileRotator != nil {
		if err := l.fileRotator.Write(out, entry.Action); err != nil {
			return fmt.Errorf("audit: file write: %w", err)
		}
	} else {
		// 回退到 fallback writer。
		l.fallbackMu.Lock()
		_, writeErr := l.fallbackWriter.Write(append(out, '\n'))
		l.fallbackMu.Unlock()
		if writeErr != nil {
			return fmt.Errorf("audit: fallback write: %w", writeErr)
		}
	}

	// 5. 异步写入 Syslog（channel，零阻塞）。
	if l.syslogWriter != nil {
		l.syslogWriter.Write(append(out, '\n'))
	}

	return nil
}

// VerifySignature 用 AuditKey 验证给定 payload 与 signature 是否匹配（旧式独立 HMAC，非链式）。
// 使用 subtle.ConstantTimeCompare 防计时侧信道。
// 注意：此方法不验证哈希链，仅验证独立 HMAC。链式验证用 VerifyChainSignature。
func (l *AuditLogger) VerifySignature(payload []byte, wantHexSig string) (bool, error) {
	var wantSig []byte
	err := l.auditKey.WithKey(func(key []byte) error {
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		got := mac.Sum(nil)
		want, decErr := hex.DecodeString(wantHexSig)
		if decErr != nil {
			return decErr
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return errors.New("audit: signature mismatch")
		}
		wantSig = got
		return nil
	})
	if err != nil {
		return false, err
	}
	return wantSig != nil, nil
}

// VerifyChainSignature 验证哈希链签名。
// 算法：expected = HMAC-SHA256(key, prevSig + payload)
// prevSigHex 是前一条日志的签名（hex），第一条日志用 InitialChainSignatureHex()。
func (l *AuditLogger) VerifyChainSignature(payload []byte, prevSigHex, wantHexSig string) (bool, error) {
	var verified bool
	err := l.auditKey.WithKey(func(key []byte) error {
		prevSig, e := hex.DecodeString(prevSigHex)
		if e != nil {
			return e
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(prevSig)
		mac.Write(payload)
		got := mac.Sum(nil)
		want, e := hex.DecodeString(wantHexSig)
		if e != nil {
			return e
		}
		if subtle.ConstantTimeCompare(got, want) == 1 {
			verified = true
		}
		return nil
	})
	return verified, err
}

// InitialChainSignatureHex 返回哈希链初始签名 SHA256(AuditKey)（hex）。
func (l *AuditLogger) InitialChainSignatureHex() string {
	var hexStr string
	_ = l.auditKey.WithKey(func(key []byte) error {
		h := sha256.Sum256(key)
		hexStr = hex.EncodeToString(h[:])
		return nil
	})
	return hexStr
}

// Close Wipe AuditKey + 关闭文件轮转 + 关闭 Syslog。
func (l *AuditLogger) Close() {
	if l.auditKey != nil {
		l.auditKey.Wipe()
		l.auditKey = nil
	}
	if l.fileRotator != nil {
		_ = l.fileRotator.Close()
	}
	if l.syslogWriter != nil {
		_ = l.syslogWriter.Close()
	}
}

// LastSignatureHex 返回哈希链末端签名（测试用）。
func (l *AuditLogger) LastSignatureHex() string {
	return l.chain.LastSignatureHex()
}

// loadAnchor 从文件恢复链条末端签名。
// 文件不存在或损坏时返回 error（调用方用初始值兜底）。
//
// 文件格式：单行 hex 编码的 lastSignature。
// 权限 0600，仅 owner 可读写。
func loadAnchor(path string, chain *hashChain) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	if len(sig) != 32 {
		return fmt.Errorf("audit: anchor signature length = %d, want 32", len(sig))
	}
	chain.SetLastSignature(sig)
	return nil
}

// saveAnchor 持久化链条末端签名到文件。
// 每次 Record 后调用（0600 权限，原子写入）。
func (l *AuditLogger) saveAnchor() error {
	if l.anchorFile == "" {
		return nil
	}
	sig := l.chain.LastSignatureHex()
	// 原子写入：先写临时文件再 rename。
	tmp := l.anchorFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(sig), 0o600); err != nil {
		return fmt.Errorf("audit: write anchor tmp: %w", err)
	}
	if err := os.Rename(tmp, l.anchorFile); err != nil {
		return fmt.Errorf("audit: rename anchor: %w", err)
	}
	return nil
}
