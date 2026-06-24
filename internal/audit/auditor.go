// Package audit - Auditor 接口抽象。
//
// 蓝图要求内部包间依赖仅限接口抽象。Auditor 定义审计层的行为契约，
// api/bootstrap 依赖此接口而非 *AuditLogger 具体类型。
//
// *AuditLogger 隐式实现此接口。
package audit

// Auditor 是审计日志层的接口抽象。
type Auditor interface {
	// Record 记录一条审计日志。
	Record(entry LogEntry) error

	// Close 释放资源（Wipe AuditKey）。
	Close()
}
