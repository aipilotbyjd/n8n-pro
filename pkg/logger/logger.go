package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"
)

// Logger represents a structured logger instance
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Fatal(msg string, args ...any)

	With(args ...any) Logger
	WithContext(ctx context.Context) Logger
	SetLevel(level string)

	DebugContext(ctx context.Context, msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)

	// Enhanced logging methods
	Trace(msg string, args ...any)
	TraceContext(ctx context.Context, msg string, args ...any)

	// Specialized logging methods
	Audit(event string, args ...any)
	Security(event string, args ...any)
	Performance(operation string, duration time.Duration, args ...any)

	// Context helpers
	WithRequestID(requestID string) Logger
	WithUserID(userID string) Logger
	WithTraceID(traceID string) Logger
	WithComponent(component string) Logger
	WithError(err error) Logger

	// Performance helpers
	StartTimer(operation string) func(...any)
}

// Config holds logger configuration
type Config struct {
	Level      string            `json:"level" yaml:"level"`
	Format     string            `json:"format" yaml:"format"` // "json" or "text"
	Output     string            `json:"output" yaml:"output"` // "stdout", "stderr", or file path
	AddSource  bool              `json:"add_source" yaml:"add_source"`
	TimeFormat string            `json:"time_format" yaml:"time_format"`
	Fields     map[string]string `json:"fields" yaml:"fields"` // Additional fields to include in all logs

	// Enhanced logging options
	EnableAuditLogs    bool   `json:"enable_audit_logs" yaml:"enable_audit_logs"`
	EnableSecurityLogs bool   `json:"enable_security_logs" yaml:"enable_security_logs"`
	EnablePerformance  bool   `json:"enable_performance" yaml:"enable_performance"`
	Component          string `json:"component" yaml:"component"`
	Environment        string `json:"environment" yaml:"environment"`

	// File rotation settings
	MaxSize    int  `json:"max_size" yaml:"max_size"`       // megabytes
	MaxAge     int  `json:"max_age" yaml:"max_age"`         // days
	MaxBackups int  `json:"max_backups" yaml:"max_backups"` 
	Compress   bool `json:"compress" yaml:"compress"`
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: time.RFC3339,
		Fields:     make(map[string]string),

		// Enhanced defaults
		EnableAuditLogs:    true,
		EnableSecurityLogs: true,
		EnablePerformance:  true,
		Component:          "n8n-pro",
		Environment:        "development",

		// File rotation defaults
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
		Compress:   true,
	}
}

// slogLogger implements the Logger interface using slog
type slogLogger struct {
	logger *slog.Logger
	level  *slog.LevelVar
	config *Config
}

// New creates a new logger instance with the provided service name
func New(service string) Logger {
	return NewWithConfig(service, DefaultConfig())
}

// NewWithConfig creates a new logger with custom configuration
func NewWithConfig(service string, config *Config) Logger {
	var output io.Writer
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// Assume it's a file path
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			// Fallback to stdout if file can't be opened
			output = os.Stdout
		} else {
			output = file
		}
	}

	// Parse log level
	level := parseLevel(config.Level)
	levelVar := &slog.LevelVar{}
	levelVar.Set(level)

	// Create handler options
	opts := &slog.HandlerOptions{
		Level:     levelVar,
		AddSource: config.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize time format
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(config.TimeFormat))
				}
			}
			return a
		},
	}

	// Create handler based on format
	var handler slog.Handler
	if config.Format == "json" {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	// Create base logger
	logger := slog.New(handler)

	// Add service name and any additional fields
	attrs := []any{"service", service}
	for key, value := range config.Fields {
		attrs = append(attrs, key, value)
	}

	if len(attrs) > 0 {
		logger = logger.With(attrs...)
	}

	return &slogLogger{
		logger: logger,
		level:  levelVar,
		config: config,
	}
}

// parseLevel converts string level to slog.Level
func parseLevel(levelStr string) slog.Level {
	switch levelStr {
	case "trace":
		return slog.Level(-8) // Custom trace level
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Debug logs a debug message
func (l *slogLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// Info logs an info message
func (l *slogLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Warn logs a warning message
func (l *slogLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

// Error logs an error message
func (l *slogLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

// Fatal logs a fatal message and exits the program
func (l *slogLogger) Fatal(msg string, args ...any) {
	l.logger.Error(msg, args...)
	os.Exit(1)
}

// Trace logs a trace message
func (l *slogLogger) Trace(msg string, args ...any) {
	l.logger.Log(context.Background(), slog.Level(-8), msg, args...)
}

// TraceContext logs a trace message with context
func (l *slogLogger) TraceContext(ctx context.Context, msg string, args ...any) {
	l.logger.Log(ctx, slog.Level(-8), msg, args...)
}

// Audit logs an audit event
func (l *slogLogger) Audit(event string, args ...any) {
	if !l.config.EnableAuditLogs {
		return
	}
	auditArgs := append([]any{"event_type", "audit", "audit_event", event}, args...)
	l.logger.Info("AUDIT: "+event, auditArgs...)
}

// Security logs a security event
func (l *slogLogger) Security(event string, args ...any) {
	if !l.config.EnableSecurityLogs {
		return
	}
	securityArgs := append([]any{"event_type", "security", "security_event", event}, args...)
	l.logger.Warn("SECURITY: "+event, securityArgs...)
}

// Performance logs a performance measurement
func (l *slogLogger) Performance(operation string, duration time.Duration, args ...any) {
	if !l.config.EnablePerformance {
		return
	}
	perfArgs := append([]any{
		"event_type", "performance",
		"operation", operation,
		"duration_ms", duration.Milliseconds(),
	}, args...)
	l.logger.Info("PERF: "+operation, perfArgs...)
}

// Context helper methods
func (l *slogLogger) WithRequestID(requestID string) Logger {
	return l.With("request_id", requestID)
}

func (l *slogLogger) WithUserID(userID string) Logger {
	return l.With("user_id", userID)
}

func (l *slogLogger) WithTraceID(traceID string) Logger {
	return l.With("trace_id", traceID)
}

func (l *slogLogger) WithComponent(component string) Logger {
	return l.With("component", component)
}

func (l *slogLogger) WithError(err error) Logger {
	if err == nil {
		return l
	}
	return l.With("error", err.Error())
}

// StartTimer returns a function to log the duration of an operation
func (l *slogLogger) StartTimer(operation string) func(...any) {
	start := time.Now()
	return func(args ...any) {
		duration := time.Since(start)
		l.Performance(operation, duration, args...)
	}
}

// With returns a new logger with additional context
func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{
		logger: l.logger.With(args...),
		level:  l.level,
		config: l.config,
	}
}

// WithContext returns a new logger with context
func (l *slogLogger) WithContext(ctx context.Context) Logger {
	args := make([]any, 0)

	// Extract request ID from context
	if requestID := ctx.Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			args = append(args, "request_id", id)
		}
	}

	// Extract user ID from context  
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			args = append(args, "user_id", id)
		}
	}

	// Extract trace ID from context
	if traceID := ctx.Value("trace_id"); traceID != nil {
		if id, ok := traceID.(string); ok {
			args = append(args, "trace_id", id)
		}
	}

	// Extract organization ID from context
	if orgID := ctx.Value("organization_id"); orgID != nil {
		if id, ok := orgID.(string); ok {
			args = append(args, "organization_id", id)
		}
	}

	// Extract session ID from context
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			args = append(args, "session_id", id)
		}
	}

	if len(args) > 0 {
		return l.With(args...)
	}

	return l
}

// SetLevel changes the logging level
func (l *slogLogger) SetLevel(level string) {
	l.level.Set(parseLevel(level))
}

// DebugContext logs a debug message with context
func (l *slogLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

// InfoContext logs an info message with context
func (l *slogLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

// WarnContext logs a warning message with context
func (l *slogLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

// ErrorContext logs an error message with context
func (l *slogLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

// Global logger instance
var globalLogger Logger

func init() {
	globalLogger = New("default")
}

// SetGlobal sets the global logger instance
func SetGlobal(logger Logger) {
	globalLogger = logger
}

// Global logging functions
func Debug(msg string, args ...any) {
	globalLogger.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	globalLogger.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	globalLogger.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	globalLogger.Error(msg, args...)
}

func Fatal(msg string, args ...any) {
	globalLogger.Fatal(msg, args...)
}

func With(args ...any) Logger {
	return globalLogger.With(args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	globalLogger.DebugContext(ctx, msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	globalLogger.InfoContext(ctx, msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	globalLogger.WarnContext(ctx, msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	globalLogger.ErrorContext(ctx, msg, args...)
}

// Enhanced global functions
func Trace(msg string, args ...any) {
	globalLogger.Trace(msg, args...)
}

func TraceContext(ctx context.Context, msg string, args ...any) {
	globalLogger.TraceContext(ctx, msg, args...)
}

func Audit(event string, args ...any) {
	globalLogger.Audit(event, args...)
}

func Security(event string, args ...any) {
	globalLogger.Security(event, args...)
}

func Performance(operation string, duration time.Duration, args ...any) {
	globalLogger.Performance(operation, duration, args...)
}

func WithRequestID(requestID string) Logger {
	return globalLogger.WithRequestID(requestID)
}

func WithUserID(userID string) Logger {
	return globalLogger.WithUserID(userID)
}

func WithTraceID(traceID string) Logger {
	return globalLogger.WithTraceID(traceID)
}

func WithComponent(component string) Logger {
	return globalLogger.WithComponent(component)
}

func StartTimer(operation string) func(...any) {
	return globalLogger.StartTimer(operation)
}

// Helper functions for common use cases
func WithError(err error) Logger {
	return globalLogger.With("error", err)
}

func WithField(key string, value any) Logger {
	return globalLogger.With(key, value)
}

func WithFields(fields map[string]any) Logger {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return globalLogger.With(args...)
}

// Middleware helpers
func LogRequest(method, path string, statusCode int, duration time.Duration) {
	globalLogger.Info("request processed",
		"method", method,
		"path", path,
		"status_code", statusCode,
		"duration_ms", duration.Milliseconds(),
	)
}

func LogError(operation string, err error, fields ...any) {
	args := []any{"operation", operation, "error", err}
	args = append(args, fields...)
	globalLogger.Error("operation failed", args...)
}

// GORM Logger integration

// GormLogger wraps our logger for GORM compatibility
type GormLogger struct {
	logger Logger
}

// NewGormLogger creates a new GORM-compatible logger
func NewGormLogger(logger Logger) *GormLogger {
	return &GormLogger{logger: logger}
}

// LogMode is a no-op for our implementation
func (gl *GormLogger) LogMode(level interface{}) interface{} {
	return gl
}

// Info logs info messages from GORM
func (gl *GormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	gl.logger.WithContext(ctx).Info(msg, "data", data)
}

// Warn logs warning messages from GORM
func (gl *GormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	gl.logger.WithContext(ctx).Warn(msg, "data", data)
}

// Error logs error messages from GORM
func (gl *GormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	gl.logger.WithContext(ctx).Error(msg, "data", data)
}

// Trace logs SQL queries from GORM
func (gl *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	elapsed := time.Since(begin)
	sql, rows := fc()
	
	logger := gl.logger.WithContext(ctx)
	if err != nil {
		logger.Error("SQL query failed",
			"sql", sql,
			"duration_ms", elapsed.Milliseconds(),
			"rows", rows,
			"error", err.Error(),
		)
	} else {
		logger.Debug("SQL query executed",
			"sql", sql,
			"duration_ms", elapsed.Milliseconds(),
			"rows", rows,
		)
	}
}
