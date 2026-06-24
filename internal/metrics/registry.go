// Package metrics 实现 Yvonne 的可观测性指标采集与暴露。
//
// 设计原则：
//   - 依赖极简：仅用 Go 标准库，不引入 prometheus/client_golang。
//   - 输出 Prometheus 文本格式（https://prometheus.io/docs/instrumenting/exposition_formats/）。
//   - 线程安全：所有指标操作用 atomic 或 sync.Mutex 保护。
//
// 指标清单：
//  1. yvonne_api_request_duration_seconds (histogram)
//     加解密 API 耗时，bucket 含 0.005..10s，可计算 P99。
//  2. yvonne_decrypt_failures_total (counter)
//     解密失败次数。激增意味着有人暴力试探篡改密文。
//  3. yvonne_encrypt_failures_total (counter)
//     加密失败次数。
//  4. go_* 系列
//     Go 运行时内存分配趋势（alloc_bytes、sys_bytes、heap_objects 等），
//     防止内存泄露导致 OOM。
//
// 用法：
//
//	m := metrics.NewRegistry()
//	m.RecordAPIRequest("Encrypt", 0.012, true)
//	http.Handle("/metrics", m)
package metrics

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry 是指标注册中心，实现 http.Handler 直接暴露 /metrics。
type Registry struct {
	mu sync.Mutex

	// Histogram: API 请求耗时。
	apiDuration *Histogram

	// Counters: 失败次数。
	decryptFailures atomic.Uint64
	encryptFailures atomic.Uint64
	unsealFailures  atomic.Uint64

	// 总请求数（按 action 分桶）。
	apiRequestsMu sync.Mutex
	apiRequests   map[string]uint64
}

// NewRegistry 创建空 Registry。
func NewRegistry() *Registry {
	return &Registry{
		apiDuration: NewHistogram(
			"yvonne_api_request_duration_seconds",
			"API request duration in seconds",
			[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		),
		apiRequests: make(map[string]uint64),
	}
}

// RecordAPIRequest 记录一次 API 请求。
// action: Encrypt/Decrypt/Unseal 等；duration: 耗时；success: 是否成功。
func (r *Registry) RecordAPIRequest(action string, duration time.Duration, success bool) {
	r.apiDuration.Observe(duration.Seconds())

	r.apiRequestsMu.Lock()
	r.apiRequests[action]++
	r.apiRequestsMu.Unlock()

	if !success {
		switch action {
		case "Decrypt":
			r.decryptFailures.Add(1)
		case "Encrypt":
			r.encryptFailures.Add(1)
		case "Unseal":
			r.unsealFailures.Add(1)
		}
	}
}

// ServeHTTP 输出 Prometheus 文本格式指标。
func (r *Registry) ServeHTTP(w io.Writer, req interface{}) {
	var sb strings.Builder

	// 1. API 请求耗时 Histogram。
	r.apiDuration.WritePrometheus(&sb)

	// 2. 失败计数器。
	writeCounter(&sb, "yvonne_decrypt_failures_total", "Total number of failed decrypt operations", r.decryptFailures.Load())
	writeCounter(&sb, "yvonne_encrypt_failures_total", "Total number of failed encrypt operations", r.encryptFailures.Load())
	writeCounter(&sb, "yvonne_unseal_failures_total", "Total number of failed unseal operations", r.unsealFailures.Load())

	// 3. 按 action 的总请求数。
	r.apiRequestsMu.Lock()
	for action, count := range r.apiRequests {
		writeCounter(&sb,
			fmt.Sprintf("yvonne_api_requests_total{action=%q}", action),
			"Total API requests by action",
			count)
	}
	r.apiRequestsMu.Unlock()

	// 4. Go 运行时内存指标。
	r.writeRuntimeMetrics(&sb)

	w.Write([]byte(sb.String()))
}

// writeRuntimeMetrics 输出 go_* 系列运行时指标。
func (r *Registry) writeRuntimeMetrics(sb *strings.Builder) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// 内存分配。
	writeGauge(sb, "go_memstats_alloc_bytes", "Number of bytes allocated and still in use", float64(ms.Alloc))
	writeGauge(sb, "go_memstats_total_alloc_bytes", "Total number of bytes allocated, even if freed", float64(ms.TotalAlloc))
	writeGauge(sb, "go_memstats_sys_bytes", "Number of bytes obtained from system", float64(ms.Sys))
	writeGauge(sb, "go_memstats_heap_alloc_bytes", "Heap bytes allocated and still in use", float64(ms.HeapAlloc))
	writeGauge(sb, "go_memstats_heap_sys_bytes", "Heap bytes obtained from system", float64(ms.HeapSys))
	writeGauge(sb, "go_memstats_heap_inuse_bytes", "Heap bytes in use", float64(ms.HeapInuse))
	writeGauge(sb, "go_memstats_heap_objects", "Number of allocated objects", float64(ms.HeapObjects))
	writeGauge(sb, "go_memstats_stack_inuse_bytes", "Stack bytes in use", float64(ms.StackInuse))
	writeGauge(sb, "go_memstats_stack_sys_bytes", "Stack bytes obtained from system", float64(ms.StackSys))
	writeGauge(sb, "go_memstats_gc_cpu_fraction", "The fraction of this program's available CPU time used by the GC since the program started", ms.GCCPUFraction)
	writeCounterRaw(sb, "go_memstats_lookups_total", "Total number of pointer lookups", uint64(ms.Lookups))
	writeCounterRaw(sb, "go_memstats_mallocs_total", "Total number of mallocs", ms.Mallocs)
	writeCounterRaw(sb, "go_memstats_frees_total", "Total number of frees", ms.Frees)

	// GC 指标。
	writeGauge(sb, "go_memstats_next_gc_bytes", "Number of heap bytes when next garbage collection will take place", float64(ms.NextGC))
	writeCounterRaw(sb, "go_memstats_gc_total", "Total number of GC runs", uint64(ms.NumGC))
	writeCounterRaw(sb, "go_memstats_gc_cpu_fraction_total", "GC CPU fraction (cumulative)", 0)

	// Goroutine 数量。
	writeGauge(sb, "go_goroutines", "Number of running goroutines", float64(runtime.NumGoroutine()))
}

// --- 内部写入辅助 ---

func writeCounter(sb *strings.Builder, name, help string, value uint64) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s counter\n%s %d\n\n",
		name, help, name, name, value)
}

func writeCounterRaw(sb *strings.Builder, name, help string, value uint64) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s counter\n%s %d\n\n",
		name, help, name, name, value)
}

func writeGauge(sb *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n\n",
		name, help, name, name, formatFloat(value))
}

func formatFloat(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "0"
	}
	// 用 %.6g 紧凑表示，避免科学计数法对 Prometheus 解析的兼容性问题。
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", f), "0"), ".")
}

// Histogram 是直方图指标，用于 P99 等分位数计算。
//
// 实现：用固定 bucket 边界 + 累计计数。Prometheus 服务端从 bucket 计数
// 用 histogram_quantile() 计算 P99。
type Histogram struct {
	mu      sync.Mutex
	name    string
	help    string
	buckets []float64 // 上界（le = less-than-or-equal）
	counts  []uint64  // 每个 bucket 的累计计数
	sum     float64
	count   uint64
}

// NewHistogram 创建 Histogram。
// buckets 必须升序排列。
func NewHistogram(name, help string, buckets []float64) *Histogram {
	return &Histogram{
		name:    name,
		help:    help,
		buckets: buckets,
		counts:  make([]uint64, len(buckets)+1), // +1 是 +Inf bucket
	}
}

// Observe 记录一个观测值。
// Prometheus histogram 是累计的：每个 bucket 的计数包含所有 <= 其上界的观测值。
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += value
	h.count++

	// 累计直方图：所有上界 >= value 的 bucket 都递增。
	for i, upper := range h.buckets {
		if value <= upper {
			h.counts[i]++
		}
	}
	// +Inf bucket 总是递增（所有值都 <= +Inf）。
	h.counts[len(h.buckets)]++
}

// WritePrometheus 输出 Prometheus 文本格式。
func (h *Histogram) WritePrometheus(sb *strings.Builder) {
	h.mu.Lock()
	defer h.mu.Unlock()

	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)

	// 每个 bucket 输出一行：name_bucket{le="upper"} count
	for i, upper := range h.buckets {
		fmt.Fprintf(sb, "%s_bucket{le=\"%s\"} %d\n",
			h.name, formatFloat(upper), h.counts[i])
	}
	// +Inf bucket。
	fmt.Fprintf(sb, "%s_bucket{le=\"+Inf\"} %d\n", h.name, h.counts[len(h.buckets)])

	// sum 与 count。
	fmt.Fprintf(sb, "%s_sum %s\n%s_count %d\n\n",
		h.name, formatFloat(h.sum), h.name, h.count)
}

// Snapshot 返回当前 histogram 的快照（用于测试）。
func (h *Histogram) Snapshot() (count uint64, sum float64, bucketCounts []uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	count = h.count
	sum = h.sum
	bucketCounts = make([]uint64, len(h.counts))
	copy(bucketCounts, h.counts)
	return
}
