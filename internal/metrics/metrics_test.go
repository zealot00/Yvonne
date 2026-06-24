package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRecordAPIRequest_UpdatesCounters 验证成功/失败请求的计数器递增。
func TestRecordAPIRequest_UpdatesCounters(t *testing.T) {
	r := NewRegistry()

	// 3 次 Decrypt，1 次失败。
	r.RecordAPIRequest("Decrypt", 10*time.Millisecond, true)
	r.RecordAPIRequest("Decrypt", 20*time.Millisecond, true)
	r.RecordAPIRequest("Decrypt", 30*time.Millisecond, false)

	// 2 次 Encrypt，全部成功。
	r.RecordAPIRequest("Encrypt", 5*time.Millisecond, true)
	r.RecordAPIRequest("Encrypt", 15*time.Millisecond, true)

	if r.decryptFailures.Load() != 1 {
		t.Fatalf("decryptFailures = %d, want 1", r.decryptFailures.Load())
	}
	if r.encryptFailures.Load() != 0 {
		t.Fatalf("encryptFailures = %d, want 0", r.encryptFailures.Load())
	}

	// 总请求数。
	r.apiRequestsMu.Lock()
	if r.apiRequests["Decrypt"] != 3 {
		t.Fatalf("Decrypt requests = %d, want 3", r.apiRequests["Decrypt"])
	}
	if r.apiRequests["Encrypt"] != 2 {
		t.Fatalf("Encrypt requests = %d, want 2", r.apiRequests["Encrypt"])
	}
	r.apiRequestsMu.Unlock()
}

// TestHistogram_Bucketing 验证 Histogram 分桶正确。
func TestHistogram_Bucketing(t *testing.T) {
	h := NewHistogram("test_hist", "test",
		[]float64{0.01, 0.1, 1.0})

	// 观测值：0.005, 0.05, 0.5, 2.0
	h.Observe(0.005) // <= 0.01
	h.Observe(0.05)  // <= 0.1
	h.Observe(0.5)   // <= 1.0
	h.Observe(2.0)   // > 1.0, 落入 +Inf

	count, sum, buckets := h.Snapshot()
	if count != 4 {
		t.Fatalf("count = %d, want 4", count)
	}
	// sum = 0.005 + 0.05 + 0.5 + 2.0 = 2.555
	if sum < 2.554 || sum > 2.556 {
		t.Fatalf("sum = %v, want ~2.555", sum)
	}
	// bucket[0] (le=0.01): 1 (累计：0.005)
	// bucket[1] (le=0.1):  2 (累计：0.005, 0.05)
	// bucket[2] (le=1.0):  3 (累计：0.005, 0.05, 0.5)
	// bucket[3] (+Inf):    4
	if buckets[0] != 1 {
		t.Fatalf("bucket le=0.01 = %d, want 1", buckets[0])
	}
	if buckets[1] != 2 {
		t.Fatalf("bucket le=0.1 = %d, want 2", buckets[1])
	}
	if buckets[2] != 3 {
		t.Fatalf("bucket le=1.0 = %d, want 3", buckets[2])
	}
	if buckets[3] != 4 {
		t.Fatalf("bucket +Inf = %d, want 4", buckets[3])
	}
}

// TestServeHTTP_PrometheusFormat 验证 /metrics 输出含关键指标。
func TestServeHTTP_PrometheusFormat(t *testing.T) {
	r := NewRegistry()
	r.RecordAPIRequest("Decrypt", 10*time.Millisecond, false)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.ServeHTTP(w, req)
	})
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()

	// 必须含核心指标。
	requiredMetrics := []string{
		"yvonne_api_request_duration_seconds",
		"yvonne_decrypt_failures_total",
		"yvonne_encrypt_failures_total",
		"go_memstats_alloc_bytes",
		"go_memstats_heap_objects",
		"go_goroutines",
	}
	for _, m := range requiredMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("metrics output missing %q\nbody:\n%s", m, body)
		}
	}

	// 必须含 TYPE 与 HELP 声明。
	if !strings.Contains(body, "# TYPE yvonne_api_request_duration_seconds histogram") {
		t.Error("missing TYPE declaration for histogram")
	}
	if !strings.Contains(body, "# TYPE yvonne_decrypt_failures_total counter") {
		t.Error("missing TYPE declaration for counter")
	}

	// 验证 decrypt_failures 值为 1。
	if !strings.Contains(body, "yvonne_decrypt_failures_total 1") {
		t.Error("decrypt_failures_total should be 1")
	}
}

// TestServeHTTP_RuntimeMetrics 验证 Go 运行时指标存在且非零。
func TestServeHTTP_RuntimeMetrics(t *testing.T) {
	r := NewRegistry()

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, nil)

	body := rec.Body.String()

	// alloc_bytes 应 > 0（程序启动后必有内存分配）。
	if !strings.Contains(body, "go_memstats_alloc_bytes ") {
		t.Fatal("missing go_memstats_alloc_bytes")
	}
	// heap_objects 应 > 0。
	if !strings.Contains(body, "go_memstats_heap_objects ") {
		t.Fatal("missing go_memstats_heap_objects")
	}
	// goroutines 应 > 0。
	if !strings.Contains(body, "go_goroutines ") {
		t.Fatal("missing go_goroutines")
	}
}

// TestConcurrentRecord 验证并发记录不 panic。
func TestConcurrentRecord(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	const n = 100

	for i := 0; i < n; i++ {
		go func() {
			r.RecordAPIRequest("Encrypt", 1*time.Millisecond, true)
			done <- struct{}{}
		}()
	}

	for i := 0; i < n; i++ {
		<-done
	}

	count, _, _ := r.apiDuration.Snapshot()
	if count != n {
		t.Fatalf("histogram count = %d, want %d", count, n)
	}
}
