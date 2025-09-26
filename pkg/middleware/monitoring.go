package middleware

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/google/uuid"
)

// ResponseRecorder wraps http.ResponseWriter to capture response details
type ResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	size       int64
}

// NewResponseRecorder creates a new response recorder
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

// WriteHeader captures the status code
func (r *ResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the response body and size
func (r *ResponseRecorder) Write(data []byte) (int, error) {
	r.body.Write(data)
	n, err := r.ResponseWriter.Write(data)
	r.size += int64(n)
	return n, err
}

// StatusCode returns the captured status code
func (r *ResponseRecorder) StatusCode() int {
	return r.statusCode
}

// Size returns the response body size
func (r *ResponseRecorder) Size() int64 {
	return r.size
}

// Body returns the response body
func (r *ResponseRecorder) Body() []byte {
	return r.body.Bytes()
}

// MonitoringConfig holds monitoring middleware configuration
type MonitoringConfig struct {
	EnableRequestLogging  bool          `json:"enable_request_logging"`
	EnableMetrics         bool          `json:"enable_metrics"`
	EnableDetailedLogging bool          `json:"enable_detailed_logging"`
	LogSlowRequests       bool          `json:"log_slow_requests"`
	SlowRequestThreshold  time.Duration `json:"slow_request_threshold"`
	SkipPaths             []string      `json:"skip_paths"`
	LogHeaders            []string      `json:"log_headers"`
	LogBody               bool          `json:"log_body"`
	MaxBodySize           int64         `json:"max_body_size"`
}

// DefaultMonitoringConfig returns default monitoring configuration
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		EnableRequestLogging:  true,
		EnableMetrics:         true,
		EnableDetailedLogging: false,
		LogSlowRequests:       true,
		SlowRequestThreshold:  time.Second,
		SkipPaths:             []string{"/health", "/metrics", "/ready", "/live"},
		LogHeaders:            []string{"User-Agent", "Authorization", "Content-Type"},
		LogBody:               false,
		MaxBodySize:           1024, // 1KB
	}
}

// MonitoringMiddleware provides request monitoring functionality
type MonitoringMiddleware struct {
	config *MonitoringConfig
	logger logger.Logger
}

// NewMonitoringMiddleware creates a new monitoring middleware
func NewMonitoringMiddleware(config *MonitoringConfig, logger logger.Logger) *MonitoringMiddleware {
	if config == nil {
		config = DefaultMonitoringConfig()
	}

	return &MonitoringMiddleware{
		config: config,
		logger: logger.WithComponent("monitoring"),
	}
}

// RequestID middleware adds a unique request ID to each request
func (m *MonitoringMiddleware) RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request ID already exists in headers
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Add request ID to response header
		w.Header().Set("X-Request-ID", requestID)

		// Add request ID to context
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// RequestLogging middleware logs HTTP requests and responses
func (m *MonitoringMiddleware) RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.EnableRequestLogging || m.shouldSkipPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Create response recorder
		recorder := NewResponseRecorder(w)

		// Create context logger with request information
		ctxLogger := m.logger.WithContext(r.Context()).With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)

		// Log request start
		if m.config.EnableDetailedLogging {
			requestFields := []logger.Field{
				logger.String("event", "request_start"),
				logger.String("host", r.Host),
				logger.String("proto", r.Proto),
				logger.String("query", r.URL.RawQuery),
			}

			// Add specific headers
			for _, header := range m.config.LogHeaders {
				if value := r.Header.Get(header); value != "" {
					requestFields = append(requestFields, logger.String("header_"+header, value))
				}
			}

			ctxLogger.Info("Request started", requestFields...)
		}

		// Execute the request
		next.ServeHTTP(recorder, r)

		// Calculate duration
		duration := time.Since(start)
		status := recorder.StatusCode()

		// Prepare log fields
		logFields := []logger.Field{
			logger.String("event", "request_complete"),
			logger.Int("status", status),
			logger.Duration("duration", duration),
			logger.Int64("response_size", recorder.Size()),
		}

		// Add detailed fields if enabled
		if m.config.EnableDetailedLogging {
			logFields = append(logFields,
				logger.String("content_type", recorder.Header().Get("Content-Type")),
				logger.Int64("content_length", r.ContentLength),
			)
		}

		// Determine log level based on status and duration
		logLevel := m.determineLogLevel(status, duration)

		// Log the request
		switch logLevel {
		case "error":
			ctxLogger.Error("Request completed with error", logFields...)
		case "warn":
			ctxLogger.Warn("Request completed with warning", logFields...)
		case "info":
			ctxLogger.Info("Request completed", logFields...)
		default:
			if m.config.LogSlowRequests && duration > m.config.SlowRequestThreshold {
				ctxLogger.Warn("Slow request detected", logFields...)
			} else {
				ctxLogger.Info("Request completed", logFields...)
			}
		}

		// Record metrics if enabled
		if m.config.EnableMetrics {
			metrics.RecordHTTPRequest(r.Method, r.URL.Path, status, duration, recorder.Size())
		}
	})
}

// Metrics middleware for tracking HTTP metrics
func (m *MonitoringMiddleware) Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.EnableMetrics || m.shouldSkipPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Increment in-flight requests
		metrics.IncHTTPRequestsInFlight()
		defer metrics.DecHTTPRequestsInFlight()

		start := time.Now()
		recorder := NewResponseRecorder(w)

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)
		metrics.RecordHTTPRequest(r.Method, r.URL.Path, recorder.StatusCode(), duration, recorder.Size())
	})
}

// Recovery middleware with monitoring
func (m *MonitoringMiddleware) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				ctxLogger := m.logger.WithContext(r.Context())
				
				// Log the panic
				ctxLogger.Error("Request panicked",
					logger.String("error", fmt.Sprintf("%v", err)),
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
					logger.String("remote_addr", r.RemoteAddr),
				)

				// Record security event for potential attacks
				if requestID, ok := r.Context().Value("request_id").(string); ok {
					metrics.RecordSecurityEvent("panic", "high", r.RemoteAddr, requestID)
				}

				// Return 500 error
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// Performance middleware for tracking performance metrics
func (m *MonitoringMiddleware) Performance(component string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			recorder := NewResponseRecorder(w)

			next.ServeHTTP(recorder, r)

			duration := time.Since(start)
			status := "success"
			if recorder.StatusCode() >= 400 {
				status = "error"
			}

			operation := r.Method + " " + r.URL.Path
			metrics.RecordPerformanceOperation(operation, component, status, duration)
		})
	}
}

// SecurityHeaders middleware adds security headers
func (m *MonitoringMiddleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// RateLimitLogging middleware logs rate limit events
func (m *MonitoringMiddleware) RateLimitLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := NewResponseRecorder(w)
		next.ServeHTTP(recorder, r)

		// Log rate limit violations
		if recorder.StatusCode() == http.StatusTooManyRequests {
			ctxLogger := m.logger.WithContext(r.Context())
			ctxLogger.Security("Rate limit exceeded",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("remote_addr", r.RemoteAddr),
				logger.String("user_agent", r.UserAgent()),
			)

			// Record rate limit metric
			metrics.RecordRateLimit("http", r.RemoteAddr, r.RemoteAddr)
		}
	})
}

// Chain combines multiple middleware functions
func (m *MonitoringMiddleware) Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// AllMiddleware returns a chain of all monitoring middleware
func (m *MonitoringMiddleware) AllMiddleware() func(http.Handler) http.Handler {
	return m.Chain(
		m.RequestID,
		m.Recovery,
		m.SecurityHeaders,
		m.RequestLogging,
		m.Metrics,
		m.RateLimitLogging,
	)
}

// Helper methods

// shouldSkipPath checks if a path should be skipped for monitoring
func (m *MonitoringMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if path == skipPath {
			return true
		}
	}
	return false
}

// determineLogLevel determines the appropriate log level based on status and duration
func (m *MonitoringMiddleware) determineLogLevel(status int, duration time.Duration) string {
	if status >= 500 {
		return "error"
	}
	if status >= 400 {
		return "warn"
	}
	if duration > m.config.SlowRequestThreshold {
		return "warn"
	}
	return "info"
}

// AuthenticationLogging middleware logs authentication events
func (m *MonitoringMiddleware) AuthenticationLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := NewResponseRecorder(w)
		next.ServeHTTP(recorder, r)

		// Log authentication events based on status codes
		status := recorder.StatusCode()
		ctxLogger := m.logger.WithContext(r.Context())

		if status == http.StatusUnauthorized {
			ctxLogger.Security("Authentication failed",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("remote_addr", r.RemoteAddr),
				logger.String("user_agent", r.UserAgent()),
			)
			metrics.RecordSecurityEvent("auth_failed", "medium", r.RemoteAddr, "")
		} else if status == http.StatusForbidden {
			ctxLogger.Security("Authorization failed",
				logger.String("method", r.Method),
				logger.String("path", r.URL.Path),
				logger.String("remote_addr", r.RemoteAddr),
			)
			metrics.RecordSecurityEvent("authz_failed", "medium", r.RemoteAddr, "")
		}
	})
}

// Global monitoring middleware instance
var globalMonitoring *MonitoringMiddleware

// Initialize initializes the global monitoring middleware
func Initialize(config *MonitoringConfig, logger logger.Logger) {
	globalMonitoring = NewMonitoringMiddleware(config, logger)
}

// GetGlobal returns the global monitoring middleware
func GetGlobal() *MonitoringMiddleware {
	return globalMonitoring
}