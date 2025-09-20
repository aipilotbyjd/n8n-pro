package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"n8n-pro/pkg/logger"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute" yaml:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour" yaml:"requests_per_hour"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	KeyFunc           func(*http.Request) string
	SkipPaths         []string `json:"skip_paths" yaml:"skip_paths"`
	EnableHeaders     bool     `json:"enable_headers" yaml:"enable_headers"`
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		RequestsPerMinute: 60,
		RequestsPerHour:   1000,
		BurstSize:         10,
		CleanupInterval:   5 * time.Minute,
		KeyFunc:           defaultKeyFunc,
		SkipPaths:         []string{"/health", "/version", "/metrics"},
		EnableHeaders:     true,
	}
}

// requestInfo tracks request information for rate limiting
type requestInfo struct {
	requests    []time.Time
	lastSeen    time.Time
	totalCount  int64
	minuteCount int
	hourCount   int
}

// RateLimiter implements rate limiting functionality
type RateLimiter struct {
	config    *RateLimitConfig
	clients   map[string]*requestInfo
	mutex     sync.RWMutex
	logger    logger.Logger
	stopChan  chan struct{}
	cleanupWG sync.WaitGroup
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig, log logger.Logger) *RateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	limiter := &RateLimiter{
		config:   config,
		clients:  make(map[string]*requestInfo),
		logger:   log,
		stopChan: make(chan struct{}),
	}

	// Start cleanup routine
	limiter.cleanupWG.Add(1)
	go limiter.cleanupRoutine()

	return limiter
}

// Middleware returns the rate limiting middleware
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped
			if rl.shouldSkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get client key
			key := rl.config.KeyFunc(r)

			// Check rate limit
			allowed, remaining, resetTime := rl.checkRateLimit(key)

			// Add headers if enabled
			if rl.config.EnableHeaders {
				rl.setRateLimitHeaders(w, remaining, resetTime)
			}

			if !allowed {
				rl.logger.Warn("Rate limit exceeded",
					"client", key,
					"path", r.URL.Path,
					"method", r.Method,
				)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(int(resetTime.Sub(time.Now()).Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error": "Rate limit exceeded", "retry_after": "` +
					strconv.Itoa(int(resetTime.Sub(time.Now()).Seconds())) + `s"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkRateLimit checks if a request should be allowed
func (rl *RateLimiter) checkRateLimit(key string) (allowed bool, remaining int, resetTime time.Time) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Get or create client info
	client, exists := rl.clients[key]
	if !exists {
		client = &requestInfo{
			requests: make([]time.Time, 0),
			lastSeen: now,
		}
		rl.clients[key] = client
	}

	client.lastSeen = now
	client.totalCount++

	// Clean old requests
	rl.cleanOldRequests(client, now)

	// Check minute limit
	minuteCount := rl.countRequestsInWindow(client.requests, now.Add(-time.Minute))
	if minuteCount >= rl.config.RequestsPerMinute {
		return false, 0, rl.getResetTime(client.requests, time.Minute)
	}

	// Check hour limit
	hourCount := rl.countRequestsInWindow(client.requests, now.Add(-time.Hour))
	if hourCount >= rl.config.RequestsPerHour {
		return false, 0, rl.getResetTime(client.requests, time.Hour)
	}

	// Check burst limit
	if len(client.requests) >= rl.config.BurstSize {
		// Check if oldest request in burst window is within the last minute
		if len(client.requests) > 0 && now.Sub(client.requests[0]) < time.Minute {
			return false, 0, client.requests[0].Add(time.Minute)
		}
	}

	// Allow request and record it
	client.requests = append(client.requests, now)
	client.minuteCount = minuteCount + 1
	client.hourCount = hourCount + 1

	// Calculate remaining requests
	remaining = rl.config.RequestsPerMinute - client.minuteCount
	if hourRemaining := rl.config.RequestsPerHour - client.hourCount; hourRemaining < remaining {
		remaining = hourRemaining
	}

	return true, remaining, now.Add(time.Minute)
}

// cleanOldRequests removes requests older than 1 hour
func (rl *RateLimiter) cleanOldRequests(client *requestInfo, now time.Time) {
	cutoff := now.Add(-time.Hour)

	// Find first request within the hour window
	start := 0
	for i, req := range client.requests {
		if req.After(cutoff) {
			start = i
			break
		}
		if i == len(client.requests)-1 {
			// All requests are older than 1 hour
			start = len(client.requests)
		}
	}

	// Keep only recent requests
	if start > 0 {
		client.requests = client.requests[start:]
	}
}

// countRequestsInWindow counts requests within a time window
func (rl *RateLimiter) countRequestsInWindow(requests []time.Time, since time.Time) int {
	count := 0
	for _, req := range requests {
		if req.After(since) {
			count++
		}
	}
	return count
}

// getResetTime calculates when the rate limit will reset
func (rl *RateLimiter) getResetTime(requests []time.Time, window time.Duration) time.Time {
	if len(requests) == 0 {
		return time.Now()
	}

	// Find the oldest request that would still be in the window
	now := time.Now()
	for _, req := range requests {
		if now.Sub(req) < window {
			return req.Add(window)
		}
	}

	return now
}

// setRateLimitHeaders sets rate limiting headers
func (rl *RateLimiter) setRateLimitHeaders(w http.ResponseWriter, remaining int, resetTime time.Time) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerMinute))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
}

// shouldSkipPath checks if a path should skip rate limiting
func (rl *RateLimiter) shouldSkipPath(path string) bool {
	for _, skipPath := range rl.config.SkipPaths {
		if path == skipPath {
			return true
		}
	}
	return false
}

// cleanupRoutine periodically cleans up old client data
func (rl *RateLimiter) cleanupRoutine() {
	defer rl.cleanupWG.Done()

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes old client data
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * time.Hour) // Keep data for 2 hours

	var keysToDelete []string
	for key, client := range rl.clients {
		if client.lastSeen.Before(cutoff) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(rl.clients, key)
	}

	if len(keysToDelete) > 0 {
		rl.logger.Debug("Cleaned up rate limiter data", "removed_clients", len(keysToDelete))
	}
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	rl.cleanupWG.Wait()
}

// GetStats returns rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	totalRequests := int64(0)
	activeClients := 0
	now := time.Now()

	for _, client := range rl.clients {
		totalRequests += client.totalCount
		if now.Sub(client.lastSeen) < time.Hour {
			activeClients++
		}
	}

	return map[string]interface{}{
		"total_clients":       len(rl.clients),
		"active_clients":      activeClients,
		"total_requests":      totalRequests,
		"requests_per_minute": rl.config.RequestsPerMinute,
		"requests_per_hour":   rl.config.RequestsPerHour,
		"burst_size":          rl.config.BurstSize,
	}
}

// Reset clears all rate limiting data for a specific key
func (rl *RateLimiter) Reset(key string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	delete(rl.clients, key)
}

// ResetAll clears all rate limiting data
func (rl *RateLimiter) ResetAll() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.clients = make(map[string]*requestInfo)
}

// Helper functions

// defaultKeyFunc extracts client key from request (IP address)
func defaultKeyFunc(r *http.Request) string {
	// Check for forwarded IP
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check for real IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use remote address
	return r.RemoteAddr
}

// IPKeyFunc creates a key function that uses IP address
func IPKeyFunc() func(*http.Request) string {
	return defaultKeyFunc
}

// UserKeyFunc creates a key function that uses user ID from context
func UserKeyFunc() func(*http.Request) string {
	return func(r *http.Request) string {
		if user := GetUserFromContext(r.Context()); user != nil {
			return "user:" + user.ID
		}
		return defaultKeyFunc(r)
	}
}

// APIKeyFunc creates a key function that uses API key
func APIKeyFunc() func(*http.Request) string {
	return func(r *http.Request) string {
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			return "api:" + apiKey
		}
		return defaultKeyFunc(r)
	}
}

// CompositeKeyFunc creates a key function that combines multiple sources
func CompositeKeyFunc() func(*http.Request) string {
	return func(r *http.Request) string {
		// Try user ID first
		if user := GetUserFromContext(r.Context()); user != nil {
			return "user:" + user.ID
		}

		// Try API key
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			return "api:" + apiKey
		}

		// Fall back to IP
		return "ip:" + defaultKeyFunc(r)
	}
}

// PerEndpointRateLimiter creates different limits for different endpoints
func PerEndpointRateLimiter(endpoints map[string]*RateLimitConfig, defaultConfig *RateLimitConfig, log logger.Logger) func(http.Handler) http.Handler {
	limiters := make(map[string]*RateLimiter)

	// Create limiter for each endpoint
	for path, config := range endpoints {
		limiters[path] = NewRateLimiter(config, log.With("endpoint", path))
	}

	// Create default limiter
	defaultLimiter := NewRateLimiter(defaultConfig, log.With("endpoint", "default"))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find appropriate limiter
			limiter := defaultLimiter
			if endpointLimiter, exists := limiters[r.URL.Path]; exists {
				limiter = endpointLimiter
			}

			// Apply rate limiting
			limiter.Middleware()(next).ServeHTTP(w, r)
		})
	}
}
