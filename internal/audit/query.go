// Package audit - 审计日志查询。
//
// 从审计日志文件中读取并过滤日志条目。
// 支持按时间范围、Actor、Action 过滤。
// 自动验证哈希链完整性。
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// QueryFilter 是审计日志查询过滤条件。
type QueryFilter struct {
	StartTime *time.Time // 起始时间（包含），nil=不限制
	EndTime   *time.Time // 结束时间（包含），nil=不限制
	Actor     string     // 精确匹配 Actor，空=不限
	Action    string     // 精确匹配 Action，空=不限
	Limit     int        // 返回最多 N 条（0=默认 100，-1=全部）
}

// QueryResult 是查询结果条目。
type QueryResult struct {
	Envelope signedEnvelope `json:"envelope"`
	Entry    LogEntry       `json:"entry"`
	Valid    bool           `json:"valid"` // 哈希链验证结果
}

// Query 从审计日志文件中查询日志条目。
//
// 从 dir 目录下的 audit-*.log 归档文件 + 当前 audit.log 中读取。
// 按 ChainSeq 排序，可选验证哈希链。
//
// 安全：仅返回 LogEntry 元数据 + 签名信息，绝不返回明文/密文。
func (l *AuditLogger) Query(dir string, filter QueryFilter) ([]QueryResult, error) {
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	// 1. 收集所有审计日志文件（归档 + 当前）。
	files, err := collectAuditFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: query: collect files: %w", err)
	}

	// 2. 逐文件读取 + 解析 + 过滤。
	var results []QueryResult
	for _, file := range files {
		entries, err := parseAuditFile(file, filter)
		if err != nil {
			continue // 跳过损坏文件
		}
		results = append(results, entries...)
	}

	// 3. 按 ChainSeq 排序。
	sort.Slice(results, func(i, j int) bool {
		return results[i].Envelope.ChainSeq < results[j].Envelope.ChainSeq
	})

	// 4. 限制返回数量。
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[len(results)-filter.Limit:]
	}

	// 5. 验证哈希链（如果有 AuditKey）。
	if l.auditKey != nil {
		for i := range results {
			results[i].Valid = l.verifyChainEntry(results[i].Envelope)
		}
	}

	return results, nil
}

// verifyChainEntry 验证单条日志的哈希链签名。
func (l *AuditLogger) verifyChainEntry(env signedEnvelope) bool {
	verified, err := l.VerifyChainSignature([]byte(env.Payload), env.PrevSignature, env.Signature)
	return err == nil && verified
}

// collectAuditFiles 收集目录下的所有审计日志文件（归档 + 当前）。
func collectAuditFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		// 当前日志文件 + 归档文件 audit-YYYYMMDD.log。
		if name == "audit.log" || (strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".log")) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files, nil
}

// parseAuditFile 解析单个审计日志文件，应用过滤条件。
func parseAuditFile(path string, filter QueryFilter) ([]QueryResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []QueryResult
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer per line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var env signedEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue // 跳过损坏行
		}

		// 解析 LogEntry。
		var entry LogEntry
		if err := json.Unmarshal([]byte(env.Payload), &entry); err != nil {
			continue
		}

		// 应用过滤条件。
		if !matchFilter(entry, filter) {
			continue
		}

		results = append(results, QueryResult{
			Envelope: env,
			Entry:    entry,
			Valid:    false, // 后续批量验证
		})
	}

	return results, scanner.Err()
}

// matchFilter 检查日志条目是否匹配过滤条件。
func matchFilter(entry LogEntry, filter QueryFilter) bool {
	if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
		return false
	}
	if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
		return false
	}
	if filter.Actor != "" && entry.Actor != filter.Actor {
		return false
	}
	if filter.Action != "" && entry.Action != filter.Action {
		return false
	}
	return true
}
