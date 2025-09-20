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
}

// Config holds logger configuration
type Config struct {
	Level      string            `json:"level" yaml:"level"`
	Format     string            `json:"format" yaml:"format"` // "json" or "text"
	Output     string            `json:"output" yaml:"output"` // "stdout", "stderr", or file path
	AddSource  bool              `json:"add_source" yaml:"add_source"`
	TimeFormat string            `json:"time_format" yaml:"time_format"`
	Fields     map[string]string `json:"fields" yaml:"fields"` // Additional fields to include in all logs
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		AddSource:  false,
		TimeFormat: time.RFC3339,
		Fields:     make(map[string]string),
	}
}

// slogLogger implements the Logger interface using slog
type slogLogger struct {
	logger *slog.Logger
	level  *slog.LevelVar
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
	}
}

// parseLevel converts string level to slog.Level
func parseLevel(levelStr string) slog.Level {
	switch levelStr {
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

// With returns a new logger with additional context
func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{
		logger: l.logger.With(args...),
		level:  l.level,
	}
}

// WithContext returns a new logger with context
func (l *slogLogger) WithContext(ctx context.Context) Logger {
	// Extract trace/span information from context if available
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
