package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds tracing configuration
type Config struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	ServiceName string `json:"service_name" yaml:"service_name"`
	Environment string `json:"environment" yaml:"environment"`
	Version     string `json:"version" yaml:"version"`

	// Exporter configuration
	ExporterType string `json:"exporter_type" yaml:"exporter_type"` // "jaeger", "stdout", "none"
	JaegerURL    string `json:"jaeger_url" yaml:"jaeger_url"`

	// Sampling configuration
	SampleRatio      float64 `json:"sample_ratio" yaml:"sample_ratio"`
	MaxSpansPerTrace int     `json:"max_spans_per_trace" yaml:"max_spans_per_trace"`

	// Additional settings
	EnableMetrics bool `json:"enable_metrics" yaml:"enable_metrics"`
	EnableLogs    bool `json:"enable_logs" yaml:"enable_logs"`
}

// DefaultConfig returns default tracing configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:          false,
		ServiceName:      "n8n-pro",
		Environment:      "development",
		Version:          "dev",
		ExporterType:     "stdout",
		JaegerURL:        "http://localhost:14268/api/traces",
		SampleRatio:      1.0,
		MaxSpansPerTrace: 1000,
		EnableMetrics:    false,
		EnableLogs:       true,
	}
}

// Provider holds the tracing provider instance
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer
	config         *Config
}

var globalProvider *Provider

// Initialize sets up the global tracing provider
func Initialize(config *Config) error {
	if !config.Enabled {
		// Set up a no-op tracer
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		return nil
	}

	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.Version),
			semconv.DeploymentEnvironmentKey.String(config.Environment),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create trace exporter based on configuration
	var exporter sdktrace.SpanExporter
	switch config.ExporterType {
	case "jaeger":
		exporter, err = jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerURL)))
		if err != nil {
			return fmt.Errorf("failed to create jaeger exporter: %w", err)
		}
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return fmt.Errorf("failed to create stdout exporter: %w", err)
		}
	case "none":
		// No exporter, spans will be collected but not exported
		exporter = &noopExporter{}
	default:
		return fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if config.SampleRatio <= 0 {
		sampler = sdktrace.NeverSample()
	} else if config.SampleRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(config.SampleRatio)
	}

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sampler),
		sdktrace.WithSpanLimits(sdktrace.SpanLimits{
			AttributeValueLengthLimit:   -1,
			AttributeCountLimit:         128,
			EventCountLimit:             128,
			LinkCountLimit:              128,
			AttributePerEventCountLimit: 128,
			AttributePerLinkCountLimit:  128,
		}),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator for distributed tracing
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create global provider instance
	globalProvider = &Provider{
		tracerProvider: tp,
		tracer:         tp.Tracer(config.ServiceName),
		config:         config,
	}

	return nil
}

// GetGlobalProvider returns the global tracing provider
func GetGlobalProvider() *Provider {
	return globalProvider
}

// Shutdown gracefully shuts down the tracing provider
func Shutdown(ctx context.Context) error {
	if globalProvider != nil && globalProvider.tracerProvider != nil {
		return globalProvider.tracerProvider.Shutdown(ctx)
	}
	return nil
}

// StartSpan creates a new span with the given name and options
func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if globalProvider == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return globalProvider.tracer.Start(ctx, spanName, opts...)
}

// TraceWorkflowExecution creates a span for workflow execution
func TraceWorkflowExecution(ctx context.Context, workflowID, executionID string) (context.Context, trace.Span) {
	ctx, span := StartSpan(ctx, "workflow.execute",
		trace.WithAttributes(
			attribute.String("workflow.id", workflowID),
			attribute.String("execution.id", executionID),
			attribute.String("component", "workflow-engine"),
		),
	)
	return ctx, span
}

// TraceNodeExecution creates a span for node execution
func TraceNodeExecution(ctx context.Context, nodeID, nodeType string) (context.Context, trace.Span) {
	ctx, span := StartSpan(ctx, "node.execute",
		trace.WithAttributes(
			attribute.String("node.id", nodeID),
			attribute.String("node.type", nodeType),
			attribute.String("component", "node-executor"),
		),
	)
	return ctx, span
}

// TraceAPIRequest creates a span for API requests
func TraceAPIRequest(ctx context.Context, method, path string) (context.Context, trace.Span) {
	ctx, span := StartSpan(ctx, "http.request",
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.route", path),
			attribute.String("component", "api"),
		),
	)
	return ctx, span
}

// TraceDBQuery creates a span for database queries
func TraceDBQuery(ctx context.Context, operation, table string) (context.Context, trace.Span) {
	ctx, span := StartSpan(ctx, "db.query",
		trace.WithAttributes(
			attribute.String("db.operation", operation),
			attribute.String("db.table", table),
			attribute.String("component", "database"),
		),
	)
	return ctx, span
}

// TraceWebhook creates a span for webhook execution
func TraceWebhook(ctx context.Context, webhookID, method string) (context.Context, trace.Span) {
	ctx, span := StartSpan(ctx, "webhook.execute",
		trace.WithAttributes(
			attribute.String("webhook.id", webhookID),
			attribute.String("http.method", method),
			attribute.String("component", "webhook"),
		),
	)
	return ctx, span
}

// AddSpanError adds error information to the current span
func AddSpanError(span trace.Span, err error) {
	if err != nil && span != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// AddSpanEvent adds an event to the current span
func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	if span != nil {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// SetSpanAttributes sets attributes on the current span
func SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	if span != nil {
		span.SetAttributes(attrs...)
	}
}

// SpanFromContext extracts the span from context
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// ContextWithSpan returns a new context with the span
func ContextWithSpan(ctx context.Context, span trace.Span) context.Context {
	return trace.ContextWithSpan(ctx, span)
}

// GetTraceID returns the trace ID from the current span
func GetTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// GetSpanID returns the span ID from the current span
func GetSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// WithTimeout creates a span with a timeout
func WithTimeout(ctx context.Context, spanName string, timeout time.Duration) (context.Context, trace.Span, context.CancelFunc) {
	ctx, span := StartSpan(ctx, spanName)
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Add timeout attribute
	span.SetAttributes(attribute.String("timeout", timeout.String()))

	return ctx, span, func() {
		cancel()
		span.End()
	}
}

// Middleware for HTTP requests
func HTTPMiddleware(next func(ctx context.Context) error) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		// Extract span from context or create new one
		span := trace.SpanFromContext(ctx)
		if !span.SpanContext().IsValid() {
			ctx, span = StartSpan(ctx, "http.handler")
			defer span.End()
		}

		// Execute the handler
		err := next(ctx)

		// Record error if any
		if err != nil {
			AddSpanError(span, err)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// noopExporter is a no-op span exporter
type noopExporter struct{}

func (e *noopExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return nil
}

func (e *noopExporter) Shutdown(ctx context.Context) error {
	return nil
}

// Common attribute keys for consistency
var (
	WorkflowIDKey   = attribute.Key("workflow.id")
	ExecutionIDKey  = attribute.Key("execution.id")
	NodeIDKey       = attribute.Key("node.id")
	NodeTypeKey     = attribute.Key("node.type")
	UserIDKey       = attribute.Key("user.id")
	TeamIDKey       = attribute.Key("team.id")
	ErrorTypeKey    = attribute.Key("error.type")
	ErrorMessageKey = attribute.Key("error.message")
	DurationKey     = attribute.Key("duration.ms")
	ComponentKey    = attribute.Key("component")
	OperationKey    = attribute.Key("operation")
)

// Helper functions for common attributes
func WorkflowAttributes(workflowID, executionID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		WorkflowIDKey.String(workflowID),
		ExecutionIDKey.String(executionID),
	}
}

func NodeAttributes(nodeID, nodeType string) []attribute.KeyValue {
	return []attribute.KeyValue{
		NodeIDKey.String(nodeID),
		NodeTypeKey.String(nodeType),
	}
}

func UserAttributes(userID, teamID string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 2)
	if userID != "" {
		attrs = append(attrs, UserIDKey.String(userID))
	}
	if teamID != "" {
		attrs = append(attrs, TeamIDKey.String(teamID))
	}
	return attrs
}

func ErrorAttributes(err error) []attribute.KeyValue {
	if err == nil {
		return nil
	}
	return []attribute.KeyValue{
		ErrorTypeKey.String(fmt.Sprintf("%T", err)),
		ErrorMessageKey.String(err.Error()),
	}
}

func DurationAttribute(duration time.Duration) attribute.KeyValue {
	return DurationKey.Int64(duration.Milliseconds())
}
