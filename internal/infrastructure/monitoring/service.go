package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"n8n-pro/pkg/logger"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Service provides monitoring and metrics collection
type Service struct {
	registry *prometheus.Registry
	logger   logger.Logger
	
	// Predefined metrics
	requestCount    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	errorCount      *prometheus.CounterVec
	dbConnections   prometheus.Gauge
	cacheHits       prometheus.Counter
	cacheMisses     prometheus.Counter
}

// New creates a new monitoring service
func New(logger logger.Logger) *Service {
	if logger == nil {
		logger = logger.New("monitoring")
	}

	registry := prometheus.NewRegistry()

	service := &Service{
		registry: registry,
		logger:   logger,
	}

	service.registerMetrics()

	return service
}

// registerMetrics registers all metrics with Prometheus
func (s *Service) registerMetrics() {
	s.requestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	s.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "HTTP request duration in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10},
		},
		[]string{"method", "endpoint"},
	)

	s.errorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Total number of errors",
		},
		[]string{"type", "component"},
	)

	s.dbConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "db_connections",
			Help: "Current number of database connections",
		},
	)

	s.cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		},
	)

	s.cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		},
	)

	// Register all metrics
	s.registry.MustRegister(s.requestCount)
	s.registry.MustRegister(s.requestDuration)
	s.registry.MustRegister(s.errorCount)
	s.registry.MustRegister(s.dbConnections)
	s.registry.MustRegister(s.cacheHits)
	s.registry.MustRegister(s.cacheMisses)
}

// RecordRequest records an HTTP request
func (s *Service) RecordRequest(method, endpoint, status string, duration time.Duration) {
	s.requestCount.WithLabelValues(method, endpoint, status).Inc()
	s.requestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordError records an error
func (s *Service) RecordError(errorType, component string) {
	s.errorCount.WithLabelValues(errorType, component).Inc()
}

// SetDBConnections sets the current number of database connections
func (s *Service) SetDBConnections(count float64) {
	s.dbConnections.Set(count)
}

// RecordCacheHit records a cache hit
func (s *Service) RecordCacheHit() {
	s.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (s *Service) RecordCacheMiss() {
	s.cacheMisses.Inc()
}

// IncrementCounter increments a custom counter
func (s *Service) IncrementCounter(name, subsystem string, labels map[string]string) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      name,
			Help:      fmt.Sprintf("Custom counter: %s", name),
			Subsystem: subsystem,
		},
		getLabelNames(labels),
	)

	if err := s.registry.Register(counter); err != nil {
		// If already registered, get the existing one
		if _, exists := err.(prometheus.AlreadyRegisteredError); exists {
			// Try to find the already registered counter
			// For now, we'll log this case
			s.logger.Warn("Counter already registered", "name", name)
			return
		}
	}

	counter.With(labels).Inc()
}

// ObserveHistogram observes a custom histogram value
func (s *Service) ObserveHistogram(name, subsystem string, value float64, labels map[string]string) {
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:      name,
			Help:      fmt.Sprintf("Custom histogram: %s", name),
			Subsystem: subsystem,
			Buckets:   prometheus.DefBuckets,
		},
		getLabelNames(labels),
	)

	if err := s.registry.Register(histogram); err != nil {
		// If already registered, get the existing one
		if _, exists := err.(prometheus.AlreadyRegisteredError); exists {
			// In a real implementation, you'd need to get the already registered histogram
			s.logger.Warn("Histogram already registered", "name", name)
			return
		}
	}

	histogram.With(labels).Observe(value)
}

// GetRegistry returns the Prometheus registry
func (s *Service) GetRegistry() *prometheus.Registry {
	return s.registry
}

// StartServer starts a metrics server
func (s *Service) StartServer(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr: addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down metrics server")
		if err := server.Shutdown(context.Background()); err != nil {
			s.logger.Error("Failed to shutdown metrics server", "error", err)
		}
	}()

	s.logger.Info("Starting metrics server", "addr", addr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start metrics server: %w", err)
	}

	return nil
}

// Health returns the health status of the monitoring service
func (s *Service) Health(ctx context.Context) error {
	// Check if we can register and unregister a temporary metric
	tempCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "temp_health_check",
			Help: "Temporary counter for health check",
		},
	)

	if err := s.registry.Register(tempCounter); err != nil {
		return fmt.Errorf("failed to register health check metric: %w", err)
	}

	// Unregister the temporary metric
	s.registry.Unregister(tempCounter)

	return nil
}

// Middleware provides a monitoring middleware
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		s.RecordRequest(
			r.Method,
			r.URL.Path,
			fmt.Sprintf("%d", wrapped.statusCode),
			duration,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getLabelNames extracts label names from a map
func getLabelNames(labels map[string]string) []string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	return names
}

// Custom metrics functions
func (s *Service) RecordWorkflowExecution(duration time.Duration, status string) {
	s.ObserveHistogram("workflow_execution_duration_seconds", "workflow", duration.Seconds(), map[string]string{
		"status": status,
	})
}

func (s *Service) RecordAPICall(endpoint, method, status string) {
	s.IncrementCounter("api_calls_total", "api", map[string]string{
		"endpoint": endpoint,
		"method":   method,
		"status":   status,
	})
}

func (s *Service) RecordUserAction(action, userID string) {
	s.IncrementCounter("user_actions_total", "user", map[string]string{
		"action": action,
		"user_id": userID,
	})
}

func (s *Service) RecordDatabaseQuery(duration time.Duration, queryType, table string) {
	s.ObserveHistogram("database_query_duration_seconds", "database", duration.Seconds(), map[string]string{
		"type":  queryType,
		"table": table,
	})
}

func (s *Service) RecordCacheOperation(operation, key string) {
	if operation == "hit" {
		s.RecordCacheHit()
	} else {
		s.RecordCacheMiss()
	}
	s.IncrementCounter("cache_operations_total", "cache", map[string]string{
		"operation": operation,
		"key":       key,
	})
}