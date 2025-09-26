package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"n8n-pro/internal/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds metrics configuration
type Config struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	Path        string `json:"path" yaml:"path"`
	Port        int    `json:"port" yaml:"port"`
	Namespace   string `json:"namespace" yaml:"namespace"`
	Subsystem   string `json:"subsystem" yaml:"subsystem"`
	ServiceName string `json:"service_name" yaml:"service_name"`
}

// DefaultConfig returns default metrics configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     true,
		Path:        "/metrics",
		Port:        9090,
		Namespace:   "n8n_pro",
		Subsystem:   "",
		ServiceName: "api",
	}
}

// Metrics holds all application metrics
type Metrics struct {
	config *Config

	// HTTP metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight prometheus.Gauge
	HTTPResponseSize     *prometheus.HistogramVec

	// Workflow metrics
	WorkflowExecutionsTotal   *prometheus.CounterVec
	WorkflowExecutionDuration *prometheus.HistogramVec
	WorkflowsActive           prometheus.Gauge
	WorkflowNodesProcessed    *prometheus.CounterVec
	WorkflowErrors            *prometheus.CounterVec

	// Database metrics
	DBConnectionsOpen  prometheus.Gauge
	DBConnectionsIdle  prometheus.Gauge
	DBConnectionsInUse prometheus.Gauge
	DBQueryDuration    *prometheus.HistogramVec
	DBQueriesTotal     *prometheus.CounterVec

	// System metrics
	SystemStartTime prometheus.Gauge
	SystemUptime    *prometheus.CounterVec

	// Queue metrics
	QueueDepth     *prometheus.GaugeVec
	QueueProcessed *prometheus.CounterVec
	QueueErrors    *prometheus.CounterVec

	// Node metrics
	NodeExecutionsTotal   *prometheus.CounterVec
	NodeExecutionDuration *prometheus.HistogramVec
	NodeErrors            *prometheus.CounterVec

	// Authentication metrics
	AuthLoginAttempts     *prometheus.CounterVec
	AuthLoginSuccess      *prometheus.CounterVec
	AuthLoginFailures     *prometheus.CounterVec
	AuthTokenRefreshes    *prometheus.CounterVec
	AuthActiveSessions    prometheus.Gauge
	AuthAPIKeyUsage       *prometheus.CounterVec
	AuthRateLimits        *prometheus.CounterVec
	AuthAccountLockouts   *prometheus.CounterVec

	// Security metrics
	SecurityEvents        *prometheus.CounterVec
	SecurityThreats       *prometheus.CounterVec
	SecurityAudits        *prometheus.CounterVec

	// Performance metrics
	PerformanceOperations *prometheus.HistogramVec

	// Custom registry
	registry *prometheus.Registry
}

// New creates a new metrics instance
func New(config *Config) *Metrics {
	if config == nil {
		config = DefaultConfig()
	}

	registry := prometheus.NewRegistry()

	m := &Metrics{
		config:   config,
		registry: registry,
	}

	m.initHTTPMetrics()
	m.initWorkflowMetrics()
	m.initDatabaseMetrics()
	m.initSystemMetrics()
	m.initQueueMetrics()
	m.initNodeMetrics()
	m.initAuthMetrics()
	m.initSecurityMetrics()
	m.initPerformanceMetrics()

	// Register all metrics
	m.registerMetrics()

	return m
}

func (m *Metrics) initHTTPMetrics() {
	m.HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status", "service"},
	)

	m.HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path", "status", "service"},
	)

	m.HTTPRequestsInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently being processed",
		},
	)

	m.HTTPResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "http_response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
		[]string{"method", "path", "status", "service"},
	)
}

func (m *Metrics) initWorkflowMetrics() {
	m.WorkflowExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "workflow_executions_total",
			Help:      "Total number of workflow executions",
		},
		[]string{"workflow_id", "workflow_name", "status", "team_id"},
	)

	m.WorkflowExecutionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "workflow_execution_duration_seconds",
			Help:      "Workflow execution duration in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 1800, 3600},
		},
		[]string{"workflow_id", "workflow_name", "status", "team_id"},
	)

	m.WorkflowsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "workflows_active",
			Help:      "Number of currently active workflows",
		},
	)

	m.WorkflowNodesProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "workflow_nodes_processed_total",
			Help:      "Total number of workflow nodes processed",
		},
		[]string{"workflow_id", "node_type", "status"},
	)

	m.WorkflowErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "workflow_errors_total",
			Help:      "Total number of workflow errors",
		},
		[]string{"workflow_id", "error_type", "node_id"},
	)
}

func (m *Metrics) initDatabaseMetrics() {
	m.DBConnectionsOpen = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "db_connections_open",
			Help:      "Number of open database connections",
		},
	)

	m.DBConnectionsIdle = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "db_connections_idle",
			Help:      "Number of idle database connections",
		},
	)

	m.DBConnectionsInUse = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "db_connections_in_use",
			Help:      "Number of database connections currently in use",
		},
	)

	m.DBQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "db_query_duration_seconds",
			Help:      "Database query duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"operation", "table", "status"},
	)

	m.DBQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "db_queries_total",
			Help:      "Total number of database queries",
		},
		[]string{"operation", "table", "status"},
	)
}

func (m *Metrics) initSystemMetrics() {
	m.SystemStartTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "system_start_time_seconds",
			Help:      "System start time in seconds since epoch",
		},
	)

	m.SystemUptime = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "system_uptime_seconds_total",
			Help:      "System uptime in seconds",
		},
		[]string{"service"},
	)

	// Set start time
	m.SystemStartTime.Set(float64(time.Now().Unix()))
}

func (m *Metrics) initQueueMetrics() {
	m.QueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "queue_depth",
			Help:      "Number of messages in queue",
		},
		[]string{"queue_name", "partition"},
	)

	m.QueueProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "queue_processed_total",
			Help:      "Total number of messages processed from queue",
		},
		[]string{"queue_name", "status"},
	)

	m.QueueErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "queue_errors_total",
			Help:      "Total number of queue processing errors",
		},
		[]string{"queue_name", "error_type"},
	)
}

func (m *Metrics) initNodeMetrics() {
	m.NodeExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "node_executions_total",
			Help:      "Total number of node executions",
		},
		[]string{"node_type", "node_id", "workflow_id", "status"},
	)

	m.NodeExecutionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "node_execution_duration_seconds",
			Help:      "Node execution duration in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"node_type", "node_id", "workflow_id", "status"},
	)

	m.NodeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "node_errors_total",
			Help:      "Total number of node errors",
		},
		[]string{"node_type", "node_id", "workflow_id", "error_type"},
	)
}

func (m *Metrics) initAuthMetrics() {
	m.AuthLoginAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_login_attempts_total",
			Help:      "Total number of login attempts",
		},
		[]string{"method", "source_ip", "user_agent"},
	)

	m.AuthLoginSuccess = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_login_success_total",
			Help:      "Total number of successful logins",
		},
		[]string{"method", "user_id", "organization_id"},
	)

	m.AuthLoginFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_login_failures_total",
			Help:      "Total number of failed login attempts",
		},
		[]string{"method", "failure_reason", "source_ip"},
	)

	m.AuthTokenRefreshes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_token_refreshes_total",
			Help:      "Total number of token refreshes",
		},
		[]string{"user_id", "status"},
	)

	m.AuthActiveSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_active_sessions",
			Help:      "Number of currently active sessions",
		},
	)

	m.AuthAPIKeyUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_api_key_usage_total",
			Help:      "Total number of API key authentications",
		},
		[]string{"key_id", "user_id", "organization_id", "status"},
	)

	m.AuthRateLimits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_rate_limits_total",
			Help:      "Total number of rate limit violations",
		},
		[]string{"limit_type", "identifier", "source_ip"},
	)

	m.AuthAccountLockouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "auth_account_lockouts_total",
			Help:      "Total number of account lockouts",
		},
		[]string{"user_id", "reason", "source_ip"},
	)
}

func (m *Metrics) initSecurityMetrics() {
	m.SecurityEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "security_events_total",
			Help:      "Total number of security events",
		},
		[]string{"event_type", "severity", "source_ip", "user_id"},
	)

	m.SecurityThreats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "security_threats_total",
			Help:      "Total number of detected security threats",
		},
		[]string{"threat_type", "severity", "source_ip", "action_taken"},
	)

	m.SecurityAudits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "security_audits_total",
			Help:      "Total number of audit events",
		},
		[]string{"audit_type", "user_id", "resource", "action"},
	)
}

func (m *Metrics) initPerformanceMetrics() {
	m.PerformanceOperations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: m.config.Namespace,
			Subsystem: m.config.Subsystem,
			Name:      "performance_operations_duration_seconds",
			Help:      "Performance operation duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"operation", "component", "status"},
	)
}

func (m *Metrics) registerMetrics() {
	// Register HTTP metrics
	m.registry.MustRegister(m.HTTPRequestsTotal)
	m.registry.MustRegister(m.HTTPRequestDuration)
	m.registry.MustRegister(m.HTTPRequestsInFlight)
	m.registry.MustRegister(m.HTTPResponseSize)

	// Register workflow metrics
	m.registry.MustRegister(m.WorkflowExecutionsTotal)
	m.registry.MustRegister(m.WorkflowExecutionDuration)
	m.registry.MustRegister(m.WorkflowsActive)
	m.registry.MustRegister(m.WorkflowNodesProcessed)
	m.registry.MustRegister(m.WorkflowErrors)

	// Register database metrics
	m.registry.MustRegister(m.DBConnectionsOpen)
	m.registry.MustRegister(m.DBConnectionsIdle)
	m.registry.MustRegister(m.DBConnectionsInUse)
	m.registry.MustRegister(m.DBQueryDuration)
	m.registry.MustRegister(m.DBQueriesTotal)

	// Register system metrics
	m.registry.MustRegister(m.SystemStartTime)
	m.registry.MustRegister(m.SystemUptime)

	// Register queue metrics
	m.registry.MustRegister(m.QueueDepth)
	m.registry.MustRegister(m.QueueProcessed)
	m.registry.MustRegister(m.QueueErrors)

	// Register node metrics
	m.registry.MustRegister(m.NodeExecutionsTotal)
	m.registry.MustRegister(m.NodeExecutionDuration)
	m.registry.MustRegister(m.NodeErrors)

	// Register authentication metrics
	m.registry.MustRegister(m.AuthLoginAttempts)
	m.registry.MustRegister(m.AuthLoginSuccess)
	m.registry.MustRegister(m.AuthLoginFailures)
	m.registry.MustRegister(m.AuthTokenRefreshes)
	m.registry.MustRegister(m.AuthActiveSessions)
	m.registry.MustRegister(m.AuthAPIKeyUsage)
	m.registry.MustRegister(m.AuthRateLimits)
	m.registry.MustRegister(m.AuthAccountLockouts)

	// Register security metrics
	m.registry.MustRegister(m.SecurityEvents)
	m.registry.MustRegister(m.SecurityThreats)
	m.registry.MustRegister(m.SecurityAudits)

	// Register performance metrics
	m.registry.MustRegister(m.PerformanceOperations)
}

// RecordHTTPRequest records HTTP request metrics
func (m *Metrics) RecordHTTPRequest(method, path string, statusCode int, duration time.Duration, responseSize int64) {
	status := strconv.Itoa(statusCode)
	service := m.config.ServiceName

	m.HTTPRequestsTotal.WithLabelValues(method, path, status, service).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, path, status, service).Observe(duration.Seconds())
	m.HTTPResponseSize.WithLabelValues(method, path, status, service).Observe(float64(responseSize))
}

// IncHTTPRequestsInFlight increments in-flight HTTP requests
func (m *Metrics) IncHTTPRequestsInFlight() {
	m.HTTPRequestsInFlight.Inc()
}

// DecHTTPRequestsInFlight decrements in-flight HTTP requests
func (m *Metrics) DecHTTPRequestsInFlight() {
	m.HTTPRequestsInFlight.Dec()
}

// RecordWorkflowExecution records workflow execution metrics
func (m *Metrics) RecordWorkflowExecution(workflowID, workflowName, status, teamID string, duration time.Duration) {
	m.WorkflowExecutionsTotal.WithLabelValues(workflowID, workflowName, status, teamID).Inc()
	m.WorkflowExecutionDuration.WithLabelValues(workflowID, workflowName, status, teamID).Observe(duration.Seconds())
}

// SetWorkflowsActive sets the number of active workflows
func (m *Metrics) SetWorkflowsActive(count float64) {
	m.WorkflowsActive.Set(count)
}

// RecordNodeExecution records node execution metrics
func (m *Metrics) RecordNodeExecution(nodeType, nodeID, workflowID, status string, duration time.Duration) {
	m.NodeExecutionsTotal.WithLabelValues(nodeType, nodeID, workflowID, status).Inc()
	m.NodeExecutionDuration.WithLabelValues(nodeType, nodeID, workflowID, status).Observe(duration.Seconds())
}

// RecordDBQuery records database query metrics
func (m *Metrics) RecordDBQuery(operation, table, status string, duration time.Duration) {
	m.DBQueriesTotal.WithLabelValues(operation, table, status).Inc()
	m.DBQueryDuration.WithLabelValues(operation, table, status).Observe(duration.Seconds())
}

// UpdateDBStats updates database connection statistics
func (m *Metrics) UpdateDBStats(open, idle, inUse int) {
	m.DBConnectionsOpen.Set(float64(open))
	m.DBConnectionsIdle.Set(float64(idle))
	m.DBConnectionsInUse.Set(float64(inUse))
}

// RecordQueueMessage records queue message metrics
func (m *Metrics) RecordQueueMessage(queueName, status string) {
	m.QueueProcessed.WithLabelValues(queueName, status).Inc()
}

// SetQueueDepth sets the queue depth
func (m *Metrics) SetQueueDepth(queueName, partition string, depth float64) {
	m.QueueDepth.WithLabelValues(queueName, partition).Set(depth)
}

// Authentication metrics methods

// RecordLoginAttempt records a login attempt
func (m *Metrics) RecordLoginAttempt(method, sourceIP, userAgent string) {
	m.AuthLoginAttempts.WithLabelValues(method, sourceIP, userAgent).Inc()
}

// RecordLoginSuccess records a successful login
func (m *Metrics) RecordLoginSuccess(method, userID, organizationID string) {
	m.AuthLoginSuccess.WithLabelValues(method, userID, organizationID).Inc()
}

// RecordLoginFailure records a failed login attempt
func (m *Metrics) RecordLoginFailure(method, failureReason, sourceIP string) {
	m.AuthLoginFailures.WithLabelValues(method, failureReason, sourceIP).Inc()
}

// RecordTokenRefresh records a token refresh
func (m *Metrics) RecordTokenRefresh(userID, status string) {
	m.AuthTokenRefreshes.WithLabelValues(userID, status).Inc()
}

// SetActiveSessions sets the number of active sessions
func (m *Metrics) SetActiveSessions(count float64) {
	m.AuthActiveSessions.Set(count)
}

// RecordAPIKeyUsage records API key usage
func (m *Metrics) RecordAPIKeyUsage(keyID, userID, organizationID, status string) {
	m.AuthAPIKeyUsage.WithLabelValues(keyID, userID, organizationID, status).Inc()
}

// RecordRateLimit records a rate limit violation
func (m *Metrics) RecordRateLimit(limitType, identifier, sourceIP string) {
	m.AuthRateLimits.WithLabelValues(limitType, identifier, sourceIP).Inc()
}

// RecordAccountLockout records an account lockout
func (m *Metrics) RecordAccountLockout(userID, reason, sourceIP string) {
	m.AuthAccountLockouts.WithLabelValues(userID, reason, sourceIP).Inc()
}

// Security metrics methods

// RecordSecurityEvent records a security event
func (m *Metrics) RecordSecurityEvent(eventType, severity, sourceIP, userID string) {
	m.SecurityEvents.WithLabelValues(eventType, severity, sourceIP, userID).Inc()
}

// RecordSecurityThreat records a security threat
func (m *Metrics) RecordSecurityThreat(threatType, severity, sourceIP, actionTaken string) {
	m.SecurityThreats.WithLabelValues(threatType, severity, sourceIP, actionTaken).Inc()
}

// RecordSecurityAudit records a security audit event
func (m *Metrics) RecordSecurityAudit(auditType, userID, resource, action string) {
	m.SecurityAudits.WithLabelValues(auditType, userID, resource, action).Inc()
}

// Performance metrics methods

// RecordPerformanceOperation records a performance operation
func (m *Metrics) RecordPerformanceOperation(operation, component, status string, duration time.Duration) {
	m.PerformanceOperations.WithLabelValues(operation, component, status).Observe(duration.Seconds())
}

// Register allows registering custom metrics
func (m *Metrics) Register(collector prometheus.Collector) error {
	return m.registry.Register(collector)
}

// MustRegister registers custom metrics and panics on error
func (m *Metrics) MustRegister(collector prometheus.Collector) {
	m.registry.MustRegister(collector)
}

// Handler returns the HTTP handler for metrics endpoint
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// StartServer starts the metrics HTTP server
func (m *Metrics) StartServer(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(m.config.Path, m.Handler())

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", m.config.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	return server.ListenAndServe()
}

// Global metrics instance
var globalMetrics *Metrics

// Initialize initializes global metrics
func Initialize(metricsConfig *config.MetricsConfig) {
	if metricsConfig == nil {
		globalMetrics = New(DefaultConfig())
		return
	}

	// Convert config.MetricsConfig to metrics.Config
	cfg := &Config{
		Enabled:     metricsConfig.Enabled,
		Path:        metricsConfig.Path,
		Port:        metricsConfig.Port,
		Namespace:   metricsConfig.Namespace,
		Subsystem:   metricsConfig.Subsystem,
		ServiceName: metricsConfig.ServiceName,
	}

	globalMetrics = New(cfg)
}

// GetGlobal returns the global metrics instance
func GetGlobal() *Metrics {
	if globalMetrics == nil {
		globalMetrics = New(DefaultConfig())
	}
	return globalMetrics
}

// Global convenience functions
func RecordHTTPRequest(method, path string, statusCode int, duration time.Duration, responseSize int64) {
	GetGlobal().RecordHTTPRequest(method, path, statusCode, duration, responseSize)
}

func IncHTTPRequestsInFlight() {
	GetGlobal().IncHTTPRequestsInFlight()
}

func DecHTTPRequestsInFlight() {
	GetGlobal().DecHTTPRequestsInFlight()
}

func RecordWorkflowExecution(workflowID, workflowName, status, teamID string, duration time.Duration) {
	GetGlobal().RecordWorkflowExecution(workflowID, workflowName, status, teamID, duration)
}

func SetWorkflowsActive(count float64) {
	GetGlobal().SetWorkflowsActive(count)
}

func RecordNodeExecution(nodeType, nodeID, workflowID, status string, duration time.Duration) {
	GetGlobal().RecordNodeExecution(nodeType, nodeID, workflowID, status, duration)
}

func RecordDBQuery(operation, table, status string, duration time.Duration) {
	GetGlobal().RecordDBQuery(operation, table, status, duration)
}

func UpdateDBStats(open, idle, inUse int) {
	GetGlobal().UpdateDBStats(open, idle, inUse)
}

// Global authentication metrics functions
func RecordLoginAttempt(method, sourceIP, userAgent string) {
	GetGlobal().RecordLoginAttempt(method, sourceIP, userAgent)
}

func RecordLoginSuccess(method, userID, organizationID string) {
	GetGlobal().RecordLoginSuccess(method, userID, organizationID)
}

func RecordLoginFailure(method, failureReason, sourceIP string) {
	GetGlobal().RecordLoginFailure(method, failureReason, sourceIP)
}

func RecordTokenRefresh(userID, status string) {
	GetGlobal().RecordTokenRefresh(userID, status)
}

func SetActiveSessions(count float64) {
	GetGlobal().SetActiveSessions(count)
}

func RecordAPIKeyUsage(keyID, userID, organizationID, status string) {
	GetGlobal().RecordAPIKeyUsage(keyID, userID, organizationID, status)
}

func RecordRateLimit(limitType, identifier, sourceIP string) {
	GetGlobal().RecordRateLimit(limitType, identifier, sourceIP)
}

func RecordAccountLockout(userID, reason, sourceIP string) {
	GetGlobal().RecordAccountLockout(userID, reason, sourceIP)
}

// Global security metrics functions
func RecordSecurityEvent(eventType, severity, sourceIP, userID string) {
	GetGlobal().RecordSecurityEvent(eventType, severity, sourceIP, userID)
}

func RecordSecurityThreat(threatType, severity, sourceIP, actionTaken string) {
	GetGlobal().RecordSecurityThreat(threatType, severity, sourceIP, actionTaken)
}

func RecordSecurityAudit(auditType, userID, resource, action string) {
	GetGlobal().RecordSecurityAudit(auditType, userID, resource, action)
}

// Global performance metrics functions
func RecordPerformanceOperation(operation, component, status string, duration time.Duration) {
	GetGlobal().RecordPerformanceOperation(operation, component, status, duration)
}
