// Package observability - OpenTelemetry tracing 初始化。
//
// 提供 TracerProvider 初始化 + OTLP exporter 配置。
// 当 observability.tracing.enabled=false 时不初始化（noop tracer）。
package observability

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TracerConfig 是 OTel tracer 配置。
type TracerConfig struct {
	Enabled     bool   `json:"enabled"      yaml:"enabled"`
	Endpoint    string `json:"endpoint"     yaml:"endpoint"`     // OTLP gRPC endpoint（如 localhost:4317）
	ServiceName string `json:"service_name" yaml:"service_name"` // 服务名（默认 yvonne-kms")
}

// InitTracer 初始化 OTel TracerProvider。
//
// 返回 shutdown 函数（defer 调用以优雅关闭）。
// 如果 cfg.Enabled=false，返回 noop tracer + noop shutdown。
func InitTracer(cfg TracerConfig) (trace.Tracer, func(), error) {
	if !cfg.Enabled {
		// Noop tracer（不导出任何 span）。
		noopShutdown := func() {}
		return otel.GetTracerProvider().Tracer("yvonne-noop"), noopShutdown, nil
	}

	if cfg.Endpoint == "" {
		return nil, nil, fmt.Errorf("observability: tracing endpoint is required when enabled")
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "yvonne-kms"
	}

	// 1. 创建 OTLP gRPC exporter。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("observability: create gRPC connection to %s: %w", cfg.Endpoint, err)
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, nil, fmt.Errorf("observability: create OTLP trace exporter: %w", err)
	}

	// 2. 创建 resource（服务标识）。
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String("1.3.0"),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("observability: create resource: %w", err)
	}

	// 3. 创建 TracerProvider。
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// 采样率：AlwaysSample（生产可改 ParentBased/TraceIDRatioBased）。
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// 4. 注册全局 TracerProvider + propagator。
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(serviceName)

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Printf("observability: tracer shutdown: %v", err)
		}
		_ = conn.Close()
	}

	log.Printf("OpenTelemetry tracing enabled: endpoint=%s, service=%s", cfg.Endpoint, serviceName)

	return tracer, shutdown, nil
}

// TracerFromContext 从 context 提取 tracer（用于 handler 内创建子 span）。
func TracerFromContext(ctx context.Context) trace.Tracer {
	return otel.GetTracerProvider().Tracer("yvonne-kms")
}
