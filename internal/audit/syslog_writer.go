//go:build !windows

// Package audit - Syslog 异步双写接入（防阻塞加固版）。
//
// 防 blocking 约束（极度重要）：
//  1. 主线程通过非阻塞 channel send 投递日志，绝不直接调用 syslog.Write。
//  2. channel 满时丢弃日志（返回 immediately，零阻塞）。
//  3. 后台 goroutine 消费 channel，每次 syslog.Write 加超时保护，
//     防止 syslogd 卡顿（未断连但响应慢）拖死消费 goroutine。
//  4. syslogd 挂掉不影响本地文件写入（双写解耦）。
//
// 架构：
//
//	主线程 → [非阻塞 send] → buffered channel (4096) → [goroutine + timeout] → syslog
//
// 平台隔离：log/syslog 仅 Unix 可用，Windows 通过 build tag 隔离。
package audit

import (
	"fmt"
	"log/syslog"
	"os"
	"sync/atomic"
	"time"
)

// SyslogWriter 是异步 Syslog 写入器。
type SyslogWriter struct {
	writer *syslog.Writer
	ch     chan []byte
	stop   chan struct{}
	done   chan struct{}

	// 丢弃计数（监控用）。
	droppedCount atomic.Int64
}

// NewSyslogWriter 连接本地 syslog daemon。
// facility: syslog.LOG_AUTHPRIV|syslog.LOG_INFO
// tag: "yvonne-kms"
//
// 如果连接失败返回 error（调用方可选择忽略，仅用文件写入）。
func NewSyslogWriter(facility syslog.Priority, tag string) (*SyslogWriter, error) {
	w, err := syslog.New(facility, tag)
	if err != nil {
		return nil, fmt.Errorf("audit: connect syslog: %w", err)
	}

	sw := &SyslogWriter{
		writer: w,
		ch:     make(chan []byte, 4096), // 缓冲 4096 条，满则丢弃
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}

	go sw.writeLoop()

	return sw, nil
}

// writeLoop 异步消费 channel 写入 syslog。
// 每次写入加 100ms 超时，防止 syslogd 卡顿拖死 goroutine。
func (s *SyslogWriter) writeLoop() {
	defer close(s.done)

	for {
		select {
		case <-s.stop:
			// drain 剩余日志（尽力而为，不阻塞 Close）。
			s.drainRemaining()
			return
		case data := <-s.ch:
			s.writeWithTimeout(data)
		}
	}
}

// writeWithTimeout 带超时写入 syslog。
// 超时则放弃当前日志，继续处理下一条（不阻塞 channel 消费）。
func (s *SyslogWriter) writeWithTimeout(data []byte) {
	if s.writer == nil {
		s.droppedCount.Add(1)
		return
	}

	done := make(chan error, 1)

	go func() {
		_, err := s.writer.Write(data)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit: syslog write failed: %v\n", err)
		}
	case <-time.After(100 * time.Millisecond):
		// syslogd 卡顿，放弃当前日志。
		fmt.Fprintln(os.Stderr, "audit: syslog write timeout, log dropped")
		s.droppedCount.Add(1)
	}
}

// drainRemaining 在 Close 时尽力写完剩余日志（最多 1 秒）。
func (s *SyslogWriter) drainRemaining() {
	timeout := time.After(1 * time.Second)
	for {
		select {
		case data := <-s.ch:
			s.writeWithTimeout(data)
		case <-timeout:
			return
		default:
			return
		}
	}
}

// Write 异步写入。channel 满时丢弃（零阻塞调用方）。
//
// 返回值：永远返回 len(data), nil——因为异步写入，无法返回真实错误。
// 丢弃的日志通过 DroppedCount() 监控。
func (s *SyslogWriter) Write(data []byte) (int, error) {
	// 复制一份，避免调用方修改原始数据。
	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case s.ch <- cp:
		// 成功投递到 channel。
	default:
		// channel 满，丢弃日志。
		s.droppedCount.Add(1)
		fmt.Fprintln(os.Stderr, "audit: syslog buffer full, log dropped")
	}
	return len(data), nil
}

// DroppedCount 返回因 buffer 满或超时丢弃的日志数（监控用）。
func (s *SyslogWriter) DroppedCount() int64 {
	return s.droppedCount.Load()
}

// Close 停止 goroutine + 关闭 syslog 连接。
// 等待 goroutine 退出（最多 1 秒 drain 剩余日志）。
func (s *SyslogWriter) Close() error {
	close(s.stop)
	// 等待 goroutine 退出。
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		// goroutine 超时未退出，强制继续。
	}
	return s.writer.Close()
}
