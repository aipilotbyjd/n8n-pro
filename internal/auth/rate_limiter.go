package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"gorm.io/gorm"
)

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	db        *gorm.DB
	config    *RateLimiterConfig
	logger    logger.Logger
	buckets   map[string]*TokenBucket
	bucketsMu sync.RWMutex
	cleanupTicker *time.Ticker
}

// RateLimiterConfig contains rate limiter configuration
type RateLimiterConfig struct {
	// Login rate limits
	LoginAttemptsPerIP      int           `json:"login_attempts_per_ip"`
	LoginAttemptsPerUser    int           `json:"login_attempts_per_user"`
	LoginWindow             time.Duration `json:"login_window"`
	
	// Registration rate limits
	RegistrationPerIP       int           `json:"registration_per_ip"`
	RegistrationWindow      time.Duration `json:"registration_window"`
	
	// Password reset rate limits
	PasswordResetPerIP      int           `json:"password_reset_per_ip"`
	PasswordResetPerEmail   int           `json:"password_reset_per_email"`
	PasswordResetWindow     time.Duration `json:"password_reset_window"`
	
	// API rate limits
	APIRequestsPerMinute    int           `json:"api_requests_per_minute"`
	APIRequestsPerHour      int           `json:"api_requests_per_hour"`
	
	// General settings
	CleanupInterval         time.Duration `json:"cleanup_interval"`
	PersistToDB             bool          `json:"persist_to_db"`
	BlockDuration           time.Duration `json:"block_duration"`
	
	// Advanced settings
	BurstMultiplier         float64       `json:"burst_multiplier"`
	EnableProgressiveDelay  bool          `json:"enable_progressive_delay"`
	MaxProgressiveDelay     time.Duration `json:"max_progressive_delay"`
}

// DefaultRateLimiterConfig returns default rate limiter configuration
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		LoginAttemptsPerIP:      5,
		LoginAttemptsPerUser:    3,
		LoginWindow:             15 * time.Minute,
		
		RegistrationPerIP:       3,
		RegistrationWindow:      1 * time.Hour,
		
		PasswordResetPerIP:      5,
		PasswordResetPerEmail:   3,
		PasswordResetWindow:     1 * time.Hour,
		
		APIRequestsPerMinute:    60,
		APIRequestsPerHour:      1000,
		
		CleanupInterval:         5 * time.Minute,
		PersistToDB:             true,
		BlockDuration:           30 * time.Minute,
		
		BurstMultiplier:         1.5,
		EnableProgressiveDelay:  true,
		MaxProgressiveDelay:     5 * time.Second,
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(db *gorm.DB, config *RateLimiterConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	rl := &RateLimiter{
		db:      db,
		config:  config,
		logger:  logger.New("rate-limiter"),
		buckets: make(map[string]*TokenBucket),
	}

	// Start cleanup routine
	if config.CleanupInterval > 0 {
		rl.startCleanupRoutine()
	}

	// Load persisted buckets from DB if configured
	if config.PersistToDB {
		rl.loadPersistedBuckets()
	}

	return rl
}

// TokenBucket implements the token bucket algorithm
type TokenBucket struct {
	Key          string
	Tokens       float64
	MaxTokens    float64
	RefillRate   float64 // tokens per second
	LastRefillAt time.Time
	BlockedUntil *time.Time
	mu           sync.Mutex
}

// Allow checks if the rate limit allows the action
func (rl *RateLimiter) Allow(action string, identifier string) bool {
	key := fmt.Sprintf("%s:%s", action, identifier)
	
	// Get or create bucket
	bucket := rl.getOrCreateBucket(key, action)
	
	// Check if blocked
	if bucket.isBlocked() {
		rl.logRateLimitEvent(action, identifier, false, "blocked")
		return false
	}
	
	// Try to consume a token
	allowed := bucket.consume(1)
	
	if !allowed {
		// Apply progressive delay if configured
		if rl.config.EnableProgressiveDelay {
			delay := rl.calculateProgressiveDelay(bucket)
			time.Sleep(delay)
		}
		
		// Check if we should block
		if bucket.Tokens <= -float64(bucket.MaxTokens) {
			bucket.block(rl.config.BlockDuration)
			rl.persistBucket(bucket)
		}
		
		rl.logRateLimitEvent(action, identifier, false, "rate_limited")
	} else {
		rl.logRateLimitEvent(action, identifier, true, "allowed")
	}
	
	// Persist to DB if configured
	if rl.config.PersistToDB && !allowed {
		rl.persistBucket(bucket)
	}
	
	return allowed
}

// AllowMultiple checks if multiple tokens can be consumed
func (rl *RateLimiter) AllowMultiple(action string, identifier string, tokens int) bool {
	key := fmt.Sprintf("%s:%s", action, identifier)
	bucket := rl.getOrCreateBucket(key, action)
	
	if bucket.isBlocked() {
		return false
	}
	
	return bucket.consume(float64(tokens))
}

// Reset resets the rate limit for a specific key
func (rl *RateLimiter) Reset(action string, identifier string) {
	key := fmt.Sprintf("%s:%s", action, identifier)
	
	rl.bucketsMu.Lock()
	delete(rl.buckets, key)
	rl.bucketsMu.Unlock()
	
	// Remove from DB if persisted
	if rl.config.PersistToDB {
		rl.db.Where("bucket_key = ?", key).Delete(&models.RateLimitBucket{})
	}
}

// Block explicitly blocks an identifier
func (rl *RateLimiter) Block(action string, identifier string, duration time.Duration) {
	key := fmt.Sprintf("%s:%s", action, identifier)
	bucket := rl.getOrCreateBucket(key, action)
	
	bucket.block(duration)
	
	if rl.config.PersistToDB {
		rl.persistBucket(bucket)
	}
	
	rl.logRateLimitEvent(action, identifier, false, "manually_blocked")
}

// IsBlocked checks if an identifier is currently blocked
func (rl *RateLimiter) IsBlocked(action string, identifier string) bool {
	key := fmt.Sprintf("%s:%s", action, identifier)
	
	rl.bucketsMu.RLock()
	bucket, exists := rl.buckets[key]
	rl.bucketsMu.RUnlock()
	
	if !exists {
		// Check DB if persisted
		if rl.config.PersistToDB {
			var dbBucket models.RateLimitBucket
			err := rl.db.Where("bucket_key = ?", key).First(&dbBucket).Error
			if err == nil {
				// Check if still blocked based on DB data
				// This is simplified - you'd need to store block info in DB
				return false
			}
		}
		return false
	}
	
	return bucket.isBlocked()
}

// GetRemainingTokens returns the number of remaining tokens
func (rl *RateLimiter) GetRemainingTokens(action string, identifier string) int {
	key := fmt.Sprintf("%s:%s", action, identifier)
	bucket := rl.getOrCreateBucket(key, action)
	
	bucket.refill()
	return int(bucket.Tokens)
}

// Helper functions

func (rl *RateLimiter) getOrCreateBucket(key string, action string) *TokenBucket {
	rl.bucketsMu.RLock()
	bucket, exists := rl.buckets[key]
	rl.bucketsMu.RUnlock()
	
	if exists {
		return bucket
	}
	
	// Create new bucket based on action type
	maxTokens, refillRate := rl.getActionLimits(action)
	
	bucket = &TokenBucket{
		Key:          key,
		Tokens:       maxTokens,
		MaxTokens:    maxTokens,
		RefillRate:   refillRate,
		LastRefillAt: time.Now(),
	}
	
	rl.bucketsMu.Lock()
	rl.buckets[key] = bucket
	rl.bucketsMu.Unlock()
	
	return bucket
}

func (rl *RateLimiter) getActionLimits(action string) (maxTokens float64, refillRate float64) {
	switch action {
	case "login":
		maxTokens = float64(rl.config.LoginAttemptsPerIP)
		refillRate = maxTokens / rl.config.LoginWindow.Seconds()
	case "register":
		maxTokens = float64(rl.config.RegistrationPerIP)
		refillRate = maxTokens / rl.config.RegistrationWindow.Seconds()
	case "password_reset":
		maxTokens = float64(rl.config.PasswordResetPerIP)
		refillRate = maxTokens / rl.config.PasswordResetWindow.Seconds()
	case "api":
		maxTokens = float64(rl.config.APIRequestsPerMinute)
		refillRate = maxTokens / 60.0
	default:
		// Default limits
		maxTokens = 10
		refillRate = 1
	}
	
	// Apply burst multiplier
	maxTokens *= rl.config.BurstMultiplier
	
	return maxTokens, refillRate
}

func (rl *RateLimiter) calculateProgressiveDelay(bucket *TokenBucket) time.Duration {
	// Calculate delay based on how far into negative tokens we are
	if bucket.Tokens >= 0 {
		return 0
	}
	
	deficit := -bucket.Tokens
	maxDeficit := bucket.MaxTokens
	
	// Linear progression from 0 to MaxProgressiveDelay
	delayRatio := deficit / maxDeficit
	if delayRatio > 1 {
		delayRatio = 1
	}
	
	delay := time.Duration(float64(rl.config.MaxProgressiveDelay) * delayRatio)
	return delay
}

func (rl *RateLimiter) persistBucket(bucket *TokenBucket) {
	if !rl.config.PersistToDB {
		return
	}
	
	dbBucket := &models.RateLimitBucket{
		BucketKey:    bucket.Key,
		BucketType:   rl.extractActionFromKey(bucket.Key),
		Tokens:       int(bucket.Tokens),
		MaxTokens:    int(bucket.MaxTokens),
		RefillRate:   int(bucket.RefillRate * 60), // Convert to per minute
		LastRefillAt: bucket.LastRefillAt,
		UpdatedAt:    time.Now(),
	}
	
	// Upsert the bucket
	err := rl.db.Where("bucket_key = ?", bucket.Key).
		Assign(dbBucket).
		FirstOrCreate(&models.RateLimitBucket{}).Error
	
	if err != nil {
		rl.logger.Error("Failed to persist rate limit bucket", "error", err, "key", bucket.Key)
	}
}

func (rl *RateLimiter) loadPersistedBuckets() {
	var dbBuckets []models.RateLimitBucket
	
	// Load buckets updated in the last hour
	cutoff := time.Now().Add(-1 * time.Hour)
	err := rl.db.Where("updated_at > ?", cutoff).Find(&dbBuckets).Error
	
	if err != nil {
		rl.logger.Error("Failed to load persisted buckets", "error", err)
		return
	}
	
	for _, dbBucket := range dbBuckets {
		bucket := &TokenBucket{
			Key:          dbBucket.BucketKey,
			Tokens:       float64(dbBucket.Tokens),
			MaxTokens:    float64(dbBucket.MaxTokens),
			RefillRate:   float64(dbBucket.RefillRate) / 60, // Convert from per minute
			LastRefillAt: dbBucket.LastRefillAt,
		}
		
		rl.buckets[dbBucket.BucketKey] = bucket
	}
	
	rl.logger.Info("Loaded persisted rate limit buckets", "count", len(dbBuckets))
}

func (rl *RateLimiter) startCleanupRoutine() {
	rl.cleanupTicker = time.NewTicker(rl.config.CleanupInterval)
	
	go func() {
		for range rl.cleanupTicker.C {
			rl.cleanup()
		}
	}()
}

func (rl *RateLimiter) cleanup() {
	rl.bucketsMu.Lock()
	defer rl.bucketsMu.Unlock()
	
	now := time.Now()
	keysToDelete := []string{}
	
	for key, bucket := range rl.buckets {
		// Remove buckets that haven't been used in a while and are at max tokens
		bucket.refill()
		if bucket.Tokens >= bucket.MaxTokens && 
		   now.Sub(bucket.LastRefillAt) > rl.config.CleanupInterval {
			keysToDelete = append(keysToDelete, key)
		}
	}
	
	for _, key := range keysToDelete {
		delete(rl.buckets, key)
	}
	
	if len(keysToDelete) > 0 {
		rl.logger.Debug("Cleaned up rate limit buckets", "count", len(keysToDelete))
	}
	
	// Clean up old DB records
	if rl.config.PersistToDB {
		cutoff := now.Add(-24 * time.Hour)
		rl.db.Where("updated_at < ?", cutoff).Delete(&models.RateLimitBucket{})
	}
}

func (rl *RateLimiter) extractActionFromKey(key string) string {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func (rl *RateLimiter) logRateLimitEvent(action string, identifier string, allowed bool, reason string) {
	event := &models.SecurityEvent{
		EventType:     fmt.Sprintf("rate_limit_%s", action),
		EventCategory: "security",
		Severity:      "info",
		Description:   fmt.Sprintf("Rate limit check for %s: %s (%s)", action, identifier, reason),
		Details: models.JSONB{
			"action":     action,
			"identifier": identifier,
			"allowed":    allowed,
			"reason":     reason,
		},
		CreatedAt: time.Now(),
	}
	
	if !allowed {
		event.Severity = "warning"
	}
	
	// Log asynchronously
	go func() {
		if err := rl.db.Create(event).Error; err != nil {
			rl.logger.Error("Failed to log rate limit event", "error", err)
		}
	}()
}

// Stop stops the rate limiter and cleans up resources
func (rl *RateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
	
	// Persist all buckets before stopping
	if rl.config.PersistToDB {
		rl.bucketsMu.RLock()
		defer rl.bucketsMu.RUnlock()
		
		for _, bucket := range rl.buckets {
			rl.persistBucket(bucket)
		}
	}
}

// TokenBucket methods

func (b *TokenBucket) refill() {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(b.LastRefillAt).Seconds()
	
	tokensToAdd := elapsed * b.RefillRate
	b.Tokens = min(b.Tokens+tokensToAdd, b.MaxTokens)
	b.LastRefillAt = now
}

func (b *TokenBucket) consume(tokens float64) bool {
	b.refill()
	
	b.mu.Lock()
	defer b.mu.Unlock()
	
	if b.Tokens >= tokens {
		b.Tokens -= tokens
		return true
	}
	
	// Allow going negative to track deficit
	b.Tokens -= tokens
	return false
}

func (b *TokenBucket) isBlocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	if b.BlockedUntil == nil {
		return false
	}
	
	if time.Now().After(*b.BlockedUntil) {
		b.BlockedUntil = nil
		b.Tokens = b.MaxTokens // Reset tokens when unblocked
		return false
	}
	
	return true
}

func (b *TokenBucket) block(duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	blockedUntil := time.Now().Add(duration)
	b.BlockedUntil = &blockedUntil
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}