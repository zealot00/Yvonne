// Package audit - 本地文件安全轮转与清理。
//
// 特性：
//   - 文件权限 0600，目录权限 0700
//   - 按天滚动：audit.log → audit-YYYYMMDD.log
//   - 180 天留存清理（后台 goroutine）
//   - 高危操作（Rotate/Shred/SysUnseal）file.Sync() 强刷盘
//
// 纯 Go 标准库实现，无第三方依赖。
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileRotator 是带轮转与清理的文件审计日志写入器。
type FileRotator struct {
	mu       sync.Mutex
	dir      string
	filename string // 当前日志文件名（如 audit.log）
	file     *os.File
	today    string // YYYYMMDD，用于检测跨天轮转

	pruneStop chan struct{} // 停止清理 goroutine
}

// HighRiskActions 是需要 file.Sync() 强刷盘的高危操作集合。
var highRiskActions = map[string]bool{
	"Rotate":          true,
	"ShredKey":        true,
	"SysUnseal":       true,
	"EmergencySeal":   true,
	"AUDIT_LOG_PRUNE": true,
}

// NewFileRotator 创建文件轮转器。
//
// dir: 日志目录（如 /var/log/yvonne）。
// filename: 当前日志文件名（如 audit.log）。
//
// 创建目录（0700）与初始文件（0600）。
func NewFileRotator(dir, filename string) (*FileRotator, error) {
	// 创建目录（0700）。
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create log dir: %w", err)
	}

	r := &FileRotator{
		dir:       dir,
		filename:  filename,
		today:     time.Now().UTC().Format("20060102"),
		pruneStop: make(chan struct{}),
	}

	// 打开/创建当前日志文件。
	if err := r.openCurrent(); err != nil {
		return nil, err
	}

	return r, nil
}

// openCurrent 打开当前日志文件（0600）。
func (r *FileRotator) openCurrent() error {
	path := filepath.Join(r.dir, r.filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open log file: %w", err)
	}
	r.file = f
	r.today = time.Now().UTC().Format("20060102")
	return nil
}

// Write 写入日志数据。自动检测跨天轮转。
// 高危操作调用 file.Sync()。
// BUG-9 修复：清洗 CRLF 注入（防日志注入攻击）。
func (r *FileRotator) Write(data []byte, action string) error {
	// 防御性清洗：移除 CR/LF，防日志注入。
	data = sanitizeCRLF(data)
	r.mu.Lock()
	defer r.mu.Unlock()

	// 检测跨天轮转。
	today := time.Now().UTC().Format("20060102")
	if today != r.today {
		if err := r.rotateLocked(); err != nil {
			return err
		}
	}

	if _, err := r.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("audit: file write: %w", err)
	}

	// 高危操作强刷盘。
	if highRiskActions[action] {
		if err := r.file.Sync(); err != nil {
			return fmt.Errorf("audit: file sync: %w", err)
		}
	}

	return nil
}

// rotateLocked 执行轮转（调用方持锁）。
func (r *FileRotator) rotateLocked() error {
	if r.file != nil {
		_ = r.file.Close()
	}

	// 重命名当前文件为 audit-YYYYMMDD.log。
	archivedName := fmt.Sprintf("audit-%s.log", r.today)
	archivedPath := filepath.Join(r.dir, archivedName)
	currentPath := filepath.Join(r.dir, r.filename)

	// 如果归档文件已存在（同一天多次轮转），直接覆盖。
	_ = os.Rename(currentPath, archivedPath)

	// 创建新文件。
	return r.openCurrent()
}

// Rotate 强制轮转（用于测试）。
func (r *FileRotator) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateLocked()
}

// StartPruneLoop 启动 180 天留存清理 goroutine。
// 每天执行一次，物理删除超过 180 天的 audit-YYYYMMDD.log。
// 清理动作本身记录为 AUDIT_LOG_PRUNE 审计日志。
//
// onPrune 回调用于将清理动作写入审计链（避免循环依赖）。
func (r *FileRotator) StartPruneLoop(retentionDays int, onPrune func(deletedCount int)) {
	go r.pruneLoop(retentionDays, onPrune)
}

func (r *FileRotator) pruneLoop(retentionDays int, onPrune func(deletedCount int)) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-r.pruneStop:
			return
		case <-ticker.C:
			deleted := r.pruneOldFiles(retentionDays)
			if onPrune != nil && deleted > 0 {
				onPrune(deleted)
			}
		}
	}
}

// pruneOldFiles 删除超过 retentionDays 天的归档日志。
func (r *FileRotator) pruneOldFiles(retentionDays int) int {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return 0
	}

	deleted := 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 11 || name[:6] != "audit-" || name[len(name)-4:] != ".log" {
			continue
		}
		// 解析日期：audit-YYYYMMDD.log → YYYYMMDD。
		dateStr := name[6 : len(name)-4]
		fileDate, err := time.Parse("20060102", dateStr)
		if err != nil {
			continue
		}
		if fileDate.Before(cutoff) {
			path := filepath.Join(r.dir, name)
			if err := os.Remove(path); err == nil {
				deleted++
			}
		}
	}
	return deleted
}

// Close 关闭文件 + 停止清理 goroutine。
func (r *FileRotator) Close() error {
	close(r.pruneStop)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// sanitizeCRLF 清洗 CR/LF 字符，防日志注入（BUG-9）。
// JSON 序列化已转义控制字符，但防御性清洗确保万无一失。
func sanitizeCRLF(data []byte) []byte {
	cleaned := make([]byte, len(data))
	for i, b := range data {
		if b == '\r' || b == '\n' {
			cleaned[i] = ' ' // 替换为空格
		} else {
			cleaned[i] = b
		}
	}
	return cleaned
}
