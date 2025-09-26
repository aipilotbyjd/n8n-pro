package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/errors"
)

// RateLimitType represents different types of rate limiting
type RateLimitType string

const (
	RateLimitGlobal    RateLimitType = "global"
	RateLimitPerUser   RateLimitType = "per_user"
	RateLimitPerAPIKey RateLimitType = "per_api_key"
	RateLimitPerIP     RateLimitType = "per_ip"
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
}

// RateLimitEntry represents a rate limit tracking entry
type RateLimitEntry struct {
	Key            string                 `json:"key"`
	Count          int                    `json:"count"`
	WindowStart    time.Time              `json:"window_start"`
	LastRequest    time.Time              `json:"last_request"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool          `json:"allowed"`
	Limit         int           `json:"limit"`
	Remaining     int           `json:"remaining"`
	ResetAt       time.Time     `json:"reset_at"`
	RetryAfter    time.Duration `json:"retry_after,omitempty"`
	RateLimitType RateLimitType `json:"rate_limit_type"`
}

// RateLimitService provides advanced rate limiting capabilities
type RateLimitService struct {
	configs map[RateLimitType]*RateLimitConfig
	entries map[string]*RateLimitEntry
	mutex   sync.RWMutex
	logger  logger.Logger
	
	// Cleanup goroutine control
	stopCleanup chan struct{}
}

// NewRateLimitService creates a new rate limiting service
func NewRateLimitService(logger logger.Logger) *RateLimitService {
	service := &RateLimitService{
		configs:     make(map[RateLimitType]*RateLimitConfig),
		entries:     make(map[string]*RateLimitEntry),
		logger:      logger,
		stopCleanup: make(chan struct{}),
	}

	// Set default configurations
	service.setDefaultConfigs()

	// Start cleanup goroutine
	go service.cleanupWorker()

	return service
}

// SetConfig sets rate limiting configuration for a specific type
func (s *RateLimitService) SetConfig(limitType RateLimitType, config *RateLimitConfig) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.configs[limitType] = config
}

// CheckRateLimit checks if a request should be allowed based on rate limits
func (s *RateLimitService) CheckRateLimit(ctx context.Context, limitType RateLimitType, key string, metadata map[string]interface{}) (*RateLimitResult, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	config, exists := s.configs[limitType]
	if !exists {
		return &RateLimitResult{
			Allowed:       true,
			Limit:         0,
			Remaining:     0,
			RateLimitType: limitType,
		}, nil
	}

	entryKey := fmt.Sprintf("%s:%s", limitType, key)
	now := time.Now()

	// Get or create rate limit entry
	entry, exists := s.entries[entryKey]
	if !exists {
		entry = &RateLimitEntry{
			Key:         entryKey,
			Count:       0,
			WindowStart: now,
			LastRequest: now,
			Metadata:    metadata,
		}
		s.entries[entryKey] = entry
	}

	// Check if we need to reset the window
	if now.Sub(entry.WindowStart) >= config.WindowSize {
		entry.Count = 0
		entry.WindowStart = now
	}

	// Update last request time
	entry.LastRequest = now

	// Check if limit is exceeded
	if entry.Count >= config.RequestsPerMinute {
		resetAt := entry.WindowStart.Add(config.WindowSize)
		retryAfter := time.Until(resetAt)

		s.logger.Warn("Rate limit exceeded",
			"type", limitType,
			"key", key,
			"count", entry.Count,
			"limit", config.RequestsPerMinute,
		)

		return &RateLimitResult{
			Allowed:       false,
			Limit:         config.RequestsPerMinute,
			Remaining:     0,
			ResetAt:       resetAt,
			RetryAfter:    retryAfter,
			RateLimitType: limitType,
		}, nil
	}

	// Increment counter and allow request
	entry.Count++
	remaining := config.RequestsPerMinute - entry.Count
	resetAt := entry.WindowStart.Add(config.WindowSize)

	return &RateLimitResult{
		Allowed:       true,
		Limit:         config.RequestsPerMinute,
		Remaining:     remaining,
		ResetAt:       resetAt,
		RateLimitType: limitType,
	}, nil
}

// CheckMultipleRateLimits checks multiple rate limits and returns the most restrictive result
func (s *RateLimitService) CheckMultipleRateLimits(ctx context.Context, checks []RateLimitCheck) (*RateLimitResult, error) {
	var mostRestrictive *RateLimitResult
	
	for _, check := range checks {
		result, err := s.CheckRateLimit(ctx, check.Type, check.Key, check.Metadata)
		if err != nil {
			return nil, err
		}

		// If any check fails, return immediately
		if !result.Allowed {
			return result, nil
		}

		// Track the most restrictive allowed result
		if mostRestrictive == nil || result.Remaining < mostRestrictive.Remaining {
			mostRestrictive = result
		}
	}

	return mostRestrictive, nil
}

// RateLimitCheck represents a single rate limit check
type RateLimitCheck struct {
	Type     RateLimitType          `json:"type"`
	Key      string                 `json:"key"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// GetRateLimitStatus returns current rate limit status for a key
func (s *RateLimitService) GetRateLimitStatus(limitType RateLimitType, key string) (*RateLimitResult, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	config, exists := s.configs[limitType]
	if !exists {
		return nil, errors.NewNotFoundError("Rate limit configuration not found")
	}

	entryKey := fmt.Sprintf("%s:%s", limitType, key)
	entry, exists := s.entries[entryKey]
	if !exists {
		return &RateLimitResult{
			Allowed:       true,
			Limit:         config.RequestsPerMinute,
			Remaining:     config.RequestsPerMinute,
			ResetAt:       time.Now().Add(config.WindowSize),
			RateLimitType: limitType,
		}, nil
	}

	now := time.Now()
	if now.Sub(entry.WindowStart) >= config.WindowSize {
		// Window has expired
		return &RateLimitResult{
			Allowed:       true,
			Limit:         config.RequestsPerMinute,
			Remaining:     config.RequestsPerMinute,
			ResetAt:       now.Add(config.WindowSize),
			RateLimitType: limitType,
		}, nil
	}

	remaining := config.RequestsPerMinute - entry.Count
	resetAt := entry.WindowStart.Add(config.WindowSize)

	return &RateLimitResult{
		Allowed:       remaining > 0,
		Limit:         config.RequestsPerMinute,
		Remaining:     remaining,
		ResetAt:       resetAt,
		RateLimitType: limitType,
	}, nil
}

// ResetRateLimit resets the rate limit for a specific key
func (s *RateLimitService) ResetRateLimit(limitType RateLimitType, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entryKey := fmt.Sprintf("%s:%s", limitType, key)
	delete(s.entries, entryKey)

	s.logger.Info("Rate limit reset", "type", limitType, "key", key)
	return nil
}

// GetRateLimitMetrics returns metrics about rate limiting
func (s *RateLimitService) GetRateLimitMetrics() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	metrics := map[string]interface{}{
		"total_entries": len(s.entries),
		"by_type":       make(map[string]int),
		"active_limits": make(map[string]int),
	}

	byType := metrics["by_type"].(map[string]int)
	activeLimits := metrics["active_limits"].(map[string]int)

	now := time.Now()
	for _, entry := range s.entries {
		// Extract type from entry key
		parts := map[string]int{}
		for limitType := range s.configs {
			prefix := fmt.Sprintf("%s:", limitType)
			if len(entry.Key) > len(prefix) {
				parts[string(limitType)]++
			}
		}
		
		// Count active limits (entries that have made requests recently)
		if now.Sub(entry.LastRequest) < 5*time.Minute {
			activeLimits[entry.Key] = entry.Count
		}
	}

	return metrics
}

// Cleanup removes expired entries
func (s *RateLimitService) Cleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	expired := []string{}

	for key, entry := range s.entries {
		// Find config for this entry type
		var config *RateLimitConfig
		for limitType, cfg := range s.configs {
			if key == fmt.Sprintf("%s:%s", limitType, entry.Key[len(limitType)+1:]) {
				config = cfg
				break
			}
		}

		if config == nil {
			expired = append(expired, key)
			continue
		}

		// Remove entries that haven't been used for a long time
		if now.Sub(entry.LastRequest) > 2*config.WindowSize {
			expired = append(expired, key)
		}
	}

	for _, key := range expired {
		delete(s.entries, key)
	}

	if len(expired) > 0 {
		s.logger.Debug("Cleaned up expired rate limit entries", "count", len(expired))
	}
}

// Stop stops the rate limiting service
func (s *RateLimitService) Stop() {
	close(s.stopCleanup)
}

// Helper methods

func (s *RateLimitService) setDefaultConfigs() {
	s.configs[RateLimitGlobal] = &RateLimitConfig{
		RequestsPerMinute: 1000,
		BurstSize:         100,
		WindowSize:        time.Minute,
		CleanupInterval:   5 * time.Minute,
	}

	s.configs[RateLimitPerUser] = &RateLimitConfig{
		RequestsPerMinute: 100,
		BurstSize:         20,
		WindowSize:        time.Minute,
		CleanupInterval:   5 * time.Minute,
	}

	s.configs[RateLimitPerAPIKey] = &RateLimitConfig{
		RequestsPerMinute: 200,
		BurstSize:         50,
		WindowSize:        time.Minute,
		CleanupInterval:   5 * time.Minute,
	}

	s.configs[RateLimitPerIP] = &RateLimitConfig{
		RequestsPerMinute: 50,
		BurstSize:         10,
		WindowSize:        time.Minute,
		CleanupInterval:   5 * time.Minute,
	}
}

func (s *RateLimitService) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.Cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

// Advanced rate limiting strategies

// AdaptiveRateLimit adjusts rate limits based on system load
func (s *RateLimitService) AdaptiveRateLimit(ctx context.Context, limitType RateLimitType, key string, systemLoad float64) (*RateLimitResult, error) {
	config, exists := s.configs[limitType]
	if !exists {
		return nil, errors.NewNotFoundError("Rate limit configuration not found")
	}

	// Adjust limits based on system load
	adjustedLimit := int(float64(config.RequestsPerMinute) * (1.0 - systemLoad*0.5))
	if adjustedLimit < config.RequestsPerMinute/4 {
		adjustedLimit = config.RequestsPerMinute / 4 // Minimum 25% of original limit
	}

	// Create temporary config with adjusted limits
	tempConfig := *config
	tempConfig.RequestsPerMinute = adjustedLimit

	// Store original config temporarily
	originalConfig := s.configs[limitType]
	s.configs[limitType] = &tempConfig

	// Check rate limit with adjusted config
	result, err := s.CheckRateLimit(ctx, limitType, key, map[string]interface{}{
		"adaptive": true,
		"system_load": systemLoad,
		"original_limit": originalConfig.RequestsPerMinute,
	})

	// Restore original config
	s.configs[limitType] = originalConfig

	return result, err
}

// BurstRateLimit allows burst traffic up to a certain threshold
func (s *RateLimitService) BurstRateLimit(ctx context.Context, limitType RateLimitType, key string, burstTokens int) (*RateLimitResult, error) {
	// This would implement a token bucket algorithm for burst handling
	// For now, return the standard rate limit check
	result, err := s.CheckRateLimit(ctx, limitType, key, map[string]interface{}{
		"burst_tokens": burstTokens,
	})
	
	if err != nil {
		return nil, err
	}

	// If standard limit is exceeded but we have burst tokens, allow it
	if !result.Allowed && burstTokens > 0 {
		result.Allowed = true
		result.Remaining = burstTokens - 1
		// Add burst metadata
		if result.Remaining <= 0 {
			result.RetryAfter = time.Until(result.ResetAt)
		}
	}

	return result, nil
}