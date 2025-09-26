package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"n8n-pro/pkg/logger"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Name        string                 `json:"name"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status    Status                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Checks    map[string]CheckResult `json:"checks"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Checker interface defines a health check
type Checker interface {
	Check(ctx context.Context) CheckResult
	Name() string
}

// Config holds health check configuration
type Config struct {
	Timeout         time.Duration `json:"timeout"`
	CheckInterval   time.Duration `json:"check_interval"`
	EnableEndpoint  bool          `json:"enable_endpoint"`
	Endpoint        string        `json:"endpoint"`
	Port            int           `json:"port"`
	EnableChecks    []string      `json:"enable_checks"`
	DisableChecks   []string      `json:"disable_checks"`
}

// DefaultConfig returns default health check configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout:        10 * time.Second,
		CheckInterval:  30 * time.Second,
		EnableEndpoint: true,
		Endpoint:       "/health",
		Port:           8080,
		EnableChecks:   []string{"database", "redis", "system"},
		DisableChecks:  []string{},
	}
}

// HealthChecker manages health checks
type HealthChecker struct {
	config    *Config
	checkers  map[string]Checker
	cache     map[string]CheckResult
	mu        sync.RWMutex
	logger    logger.Logger
	ticker    *time.Ticker
	stopCh    chan struct{}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config *Config, logger logger.Logger) *HealthChecker {
	if config == nil {
		config = DefaultConfig()
	}

	return &HealthChecker{
		config:   config,
		checkers: make(map[string]Checker),
		cache:    make(map[string]CheckResult),
		logger:   logger.WithComponent("health"),
		stopCh:   make(chan struct{}),
	}
}

// RegisterChecker registers a new health checker
func (hc *HealthChecker) RegisterChecker(checker Checker) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	name := checker.Name()
	hc.checkers[name] = checker
	hc.logger.Info("Registered health checker", "name", name)
}

// UnregisterChecker unregisters a health checker
func (hc *HealthChecker) UnregisterChecker(name string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	delete(hc.checkers, name)
	delete(hc.cache, name)
	hc.logger.Info("Unregistered health checker", "name", name)
}

// Check performs all health checks
func (hc *HealthChecker) Check(ctx context.Context) HealthResponse {
	start := time.Now()
	
	// Create context with timeout
	checkCtx, cancel := context.WithTimeout(ctx, hc.config.Timeout)
	defer cancel()

	hc.mu.RLock()
	checkers := make(map[string]Checker)
	for name, checker := range hc.checkers {
		if hc.isCheckEnabled(name) {
			checkers[name] = checker
		}
	}
	hc.mu.RUnlock()

	// Run checks concurrently
	results := make(chan CheckResult, len(checkers))
	var wg sync.WaitGroup

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()
			result := checker.Check(checkCtx)
			results <- result
		}(name, checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	checks := make(map[string]CheckResult)
	for result := range results {
		checks[result.Name] = result
	}

	// Update cache
	hc.mu.Lock()
	for name, result := range checks {
		hc.cache[name] = result
	}
	hc.mu.Unlock()

	// Determine overall status
	overallStatus := hc.determineOverallStatus(checks)
	
	duration := time.Since(start)
	
	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Duration:  duration,
		Checks:    checks,
		Metadata: map[string]interface{}{
			"service": "n8n-pro",
			"version": "1.0.0",
		},
	}

	hc.logger.Info("Health check completed", 
		"status", overallStatus,
		"duration_ms", duration.Milliseconds(),
		"total_checks", len(checks))

	return response
}

// GetCachedResult returns a cached check result
func (hc *HealthChecker) GetCachedResult(name string) (CheckResult, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	result, exists := hc.cache[name]
	return result, exists
}

// isCheckEnabled checks if a specific health check is enabled
func (hc *HealthChecker) isCheckEnabled(name string) bool {
	// Check if explicitly disabled
	for _, disabled := range hc.config.DisableChecks {
		if disabled == name {
			return false
		}
	}

	// Check if explicitly enabled (if EnableChecks is not empty)
	if len(hc.config.EnableChecks) > 0 {
		for _, enabled := range hc.config.EnableChecks {
			if enabled == name {
				return true
			}
		}
		return false
	}

	// Default to enabled if not explicitly disabled
	return true
}

// determineOverallStatus determines the overall health status
func (hc *HealthChecker) determineOverallStatus(checks map[string]CheckResult) Status {
	if len(checks) == 0 {
		return StatusHealthy
	}

	hasUnhealthy := false
	hasDegraded := false

	for _, result := range checks {
		switch result.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return StatusUnhealthy
	}
	if hasDegraded {
		return StatusDegraded
	}
	return StatusHealthy
}

// StartPeriodicChecks starts periodic health checks
func (hc *HealthChecker) StartPeriodicChecks(ctx context.Context) {
	if hc.config.CheckInterval <= 0 {
		hc.logger.Info("Periodic health checks disabled")
		return
	}

	hc.ticker = time.NewTicker(hc.config.CheckInterval)
	
	go func() {
		hc.logger.Info("Started periodic health checks", 
			"interval", hc.config.CheckInterval)
		
		for {
			select {
			case <-hc.ticker.C:
				result := hc.Check(ctx)
				if result.Status != StatusHealthy {
					hc.logger.Warn("Health check failed",
						"status", result.Status,
						"duration_ms", result.Duration.Milliseconds())
				}
			case <-hc.stopCh:
				hc.logger.Info("Stopped periodic health checks")
				return
			case <-ctx.Done():
				hc.logger.Info("Stopped periodic health checks due to context cancellation")
				return
			}
		}
	}()
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	if hc.ticker != nil {
		hc.ticker.Stop()
	}
	
	close(hc.stopCh)
}

// HTTPHandler returns an HTTP handler for health checks
func (hc *HealthChecker) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")

		// Perform health check
		ctx := r.Context()
		result := hc.Check(ctx)

		// Set status code based on health
		switch result.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still OK but degraded
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Encode response
		if err := json.NewEncoder(w).Encode(result); err != nil {
			hc.logger.Error("Failed to encode health check response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})
}

// StartServer starts the health check HTTP server
func (hc *HealthChecker) StartServer(ctx context.Context) error {
	if !hc.config.EnableEndpoint {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(hc.config.Endpoint, hc.HTTPHandler())

	// Add readiness endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ready",
			"timestamp": time.Now(),
		})
	})

	// Add liveness endpoint
	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "alive",
			"timestamp": time.Now(),
		})
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", hc.config.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	hc.logger.Info("Starting health check server",
		"port", hc.config.Port,
		"endpoint", hc.config.Endpoint)

	return server.ListenAndServe()
}

// Built-in health checkers

// DatabaseChecker checks database connectivity
type DatabaseChecker struct {
	name string
	ping func(ctx context.Context) error
}

// NewDatabaseChecker creates a new database health checker
func NewDatabaseChecker(name string, ping func(ctx context.Context) error) *DatabaseChecker {
	return &DatabaseChecker{
		name: name,
		ping: ping,
	}
}

func (dc *DatabaseChecker) Name() string {
	return dc.name
}

func (dc *DatabaseChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		Name:      dc.name,
		Timestamp: start,
	}

	if err := dc.ping(ctx); err != nil {
		result.Status = StatusUnhealthy
		result.Error = err.Error()
		result.Message = "Database connectivity failed"
	} else {
		result.Status = StatusHealthy
		result.Message = "Database is accessible"
	}

	result.Duration = time.Since(start)
	return result
}

// SystemChecker checks system resources
type SystemChecker struct {
	name string
}

// NewSystemChecker creates a new system health checker
func NewSystemChecker() *SystemChecker {
	return &SystemChecker{name: "system"}
}

func (sc *SystemChecker) Name() string {
	return sc.name
}

func (sc *SystemChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		Name:      sc.name,
		Status:    StatusHealthy,
		Message:   "System resources are healthy",
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}

	// Add system metrics if available
	// This could include memory, CPU, disk space checks
	result.Metadata["uptime"] = time.Since(start).String()
	
	result.Duration = time.Since(start)
	return result
}

// CustomChecker allows for custom health checks
type CustomChecker struct {
	name     string
	checkFn  func(ctx context.Context) (Status, string, error)
}

// NewCustomChecker creates a new custom health checker
func NewCustomChecker(name string, checkFn func(ctx context.Context) (Status, string, error)) *CustomChecker {
	return &CustomChecker{
		name:    name,
		checkFn: checkFn,
	}
}

func (cc *CustomChecker) Name() string {
	return cc.name
}

func (cc *CustomChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	
	result := CheckResult{
		Name:      cc.name,
		Timestamp: start,
	}

	status, message, err := cc.checkFn(ctx)
	result.Status = status
	result.Message = message
	if err != nil {
		result.Error = err.Error()
	}

	result.Duration = time.Since(start)
	return result
}

// Global health checker instance
var globalHealthChecker *HealthChecker

// Initialize initializes the global health checker
func Initialize(config *Config, logger logger.Logger) {
	globalHealthChecker = NewHealthChecker(config, logger)
}

// GetGlobal returns the global health checker
func GetGlobal() *HealthChecker {
	return globalHealthChecker
}

// Global convenience functions
func RegisterChecker(checker Checker) {
	if globalHealthChecker != nil {
		globalHealthChecker.RegisterChecker(checker)
	}
}

func Check(ctx context.Context) HealthResponse {
	if globalHealthChecker != nil {
		return globalHealthChecker.Check(ctx)
	}
	return HealthResponse{Status: StatusUnhealthy}
}

func StartPeriodicChecks(ctx context.Context) {
	if globalHealthChecker != nil {
		globalHealthChecker.StartPeriodicChecks(ctx)
	}
}