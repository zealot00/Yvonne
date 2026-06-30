// Package observability - OTel tracing 单元测试。
package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// TestInitTracer_Disabled 不启用时返回 noop tracer。
func TestInitTracer_Disabled(t *testing.T) {
	cfg := TracerConfig{Enabled: false}
	tracer, shutdown, err := InitTracer(cfg)
	if err != nil {
		t.Fatalf("InitTracer disabled: %v", err)
	}
	defer shutdown()

	if tracer == nil {
		t.Fatal("tracer should not be nil (noop)")
	}

	// noop tracer 创建 span 不 panic。
	_, span := tracer.Start(context.Background(), "test-span")
	span.End()
	t.Log("✅ Noop tracer: span creation works")
}

// TestInitTracer_MissingEndpoint 启用但无 endpoint 拒绝。
func TestInitTracer_MissingEndpoint(t *testing.T) {
	cfg := TracerConfig{Enabled: true, Endpoint: ""}
	_, _, err := InitTracer(cfg)
	if err == nil {
		t.Fatal("should fail when endpoint missing")
	}
	t.Logf("✅ Missing endpoint rejected: %v", err)
}

// TestInitTracer_UnreachableEndpoint 不可达 endpoint 仍创建 tracer（gRPC 连接是 lazy 的）。
// 实际导出失败会在后台 batch 报错，但不影响 tracer 创建。
func TestInitTracer_UnreachableEndpoint(t *testing.T) {
	cfg := TracerConfig{
		Enabled:     true,
		Endpoint:    "localhost:19999", // 不可达端口
		ServiceName: "test-yvonne",
	}
	tracer, shutdown, err := InitTracer(cfg)
	if err != nil {
		t.Fatalf("InitTracer should succeed even with unreachable endpoint (lazy gRPC): %v", err)
	}
	defer shutdown()

	if tracer == nil {
		t.Fatal("tracer should not be nil")
	}
	// span 创建应成功（导出失败在后台）。
	_, span := tracer.Start(context.Background(), "test-span")
	span.End()
	t.Log("✅ Unreachable endpoint: tracer created (export will fail in background)")
}

// TestTracerFromContext 从 context 提取 tracer。
func TestTracerFromContext(t *testing.T) {
	// TracerFromContext 用全局 provider，测试时用 noop provider。
	tracer := TracerFromContext(context.Background())
	if tracer == nil {
		t.Fatal("tracer should not be nil")
	}

	// noop tracer 创建 span 不 panic。
	ctx, span := tracer.Start(context.Background(), "test")
	defer span.End()

	// noop tracer 的 span context 可能无 TraceID，验证不 panic 即可。
	_ = trace.SpanContextFromContext(ctx)
	t.Log("✅ TracerFromContext: span creation works")
}

// TestTraceIDPropagation 验证 TraceID 在 context 中传播。
func TestTraceIDPropagation(t *testing.T) {
	// 用独立 tracer（不依赖全局 provider）。
	tracer := otel.GetTracerProvider().Tracer("test-yvonne")

	ctx, parentSpan := tracer.Start(context.Background(), "parent")
	parentTraceID := trace.SpanContextFromContext(ctx).TraceID().String()

	// 创建子 span。
	childCtx, childSpan := tracer.Start(ctx, "child")
	childSpan.End()

	childTraceID := trace.SpanContextFromContext(childCtx).TraceID().String()

	// 父子 span 的 TraceID 应一致（或都为 noop 的 0）。
	if parentTraceID != childTraceID {
		t.Fatalf("TraceID mismatch: parent=%s, child=%s", parentTraceID, childTraceID)
	}
	parentSpan.End()
	t.Logf("✅ TraceID propagation: parent == child (TraceID=%s)", parentTraceID)
}
