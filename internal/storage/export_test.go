// export_test.go — 暴露内部函数供测试用。
package storage

// pgRedactDSN 暴露 redactDSN 供测试。
func pgRedactDSN(dsn string) string { return redactDSN(dsn) }

// pgRewriteDSNDatabase 暴露 rewriteDSNDatabase 供测试。
func pgRewriteDSNDatabase(dsn, newDB string) string { return rewriteDSNDatabase(dsn, newDB) }
