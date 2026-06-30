//go:build integration

// pg_mutex.go — PG E2E 测试序列化（防数据残留干扰）。
package api

import "sync"

// pgTestMu 确保 PG E2E 测试串行执行（共享同一 DB，防 TRUNCATE 竞争）。
var pgTestMu sync.Mutex
