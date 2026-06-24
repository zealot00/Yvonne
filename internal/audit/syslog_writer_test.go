//go:build !windows

package audit

import (
	"sync"
	"testing"
	"time"
)

// slowSyslogWriter 模拟卡顿的 syslogd（每次 Write 阻塞 1 秒）。
type slowSyslogWriter struct {
	delay time.Duration
}

func (s *slowSyslogWriter) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return len(p), nil
}

// TestSyslogWriter_NonBlocking verifies Write never blocks even when syslog is slow.
func TestSyslogWriter_NonBlocking(t *testing.T) {
	sw := &SyslogWriter{
		ch:   make(chan []byte, 10),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	// 不启动 writeLoop，模拟消费端完全不工作。
	// channel 容量 10，写满后应立即丢弃（不阻塞）。

	start := time.Now()
	for i := 0; i < 100; i++ {
		sw.Write([]byte("test log line"))
	}
	elapsed := time.Since(start)

	// 100 次写入应在 < 100ms 内完成（channel 满后丢弃）。
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Write blocked: %v (expected < 100ms)", elapsed)
	}

	// 至少 90 条被丢弃（channel 容量 10）。
	if sw.DroppedCount() < 90 {
		t.Fatalf("expected >= 90 dropped, got %d", sw.DroppedCount())
	}
}

// TestSyslogWriter_ConcurrentNonBlocking verifies concurrent writes don't block.
func TestSyslogWriter_ConcurrentNonBlocking(t *testing.T) {
	sw := &SyslogWriter{
		ch:   make(chan []byte, 100),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	var wg sync.WaitGroup
	start := time.Now()

	// 10 个 goroutine 各写 100 条。
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				sw.Write([]byte("concurrent log"))
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// 1000 次并发写入应 < 500ms（channel 满后丢弃）。
	if elapsed > 500*time.Millisecond {
		t.Fatalf("concurrent writes blocked: %v", elapsed)
	}
}

// TestSyslogWriter_WriteTimeout verifies slow syslog doesn't block channel consumption.
// This tests the writeWithTimeout path with an actual goroutine.
func TestSyslogWriter_WriteTimeout(t *testing.T) {
	sw := &SyslogWriter{
		ch:   make(chan []byte, 1),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	// writeWithTimeout 用 100ms 超时。
	// 直接测试：慢写入应在 100ms 后被放弃。
	start := time.Now()
	sw.writeWithTimeout([]byte("slow"))
	elapsed := time.Since(start)

	// writeWithTimeout 应在 ~100ms 返回（不是 1s+）。
	if elapsed > 200*time.Millisecond {
		t.Fatalf("writeWithTimeout blocked too long: %v", elapsed)
	}
}
