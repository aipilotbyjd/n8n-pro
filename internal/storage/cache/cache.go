package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// Cache defines the interface for cache operations
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Clear(ctx context.Context) error
	GetMany(ctx context.Context, keys []string) (map[string][]byte, error)
	SetMany(ctx context.Context, items map[string]CacheItem) error
	DeleteMany(ctx context.Context, keys []string) error
	GetStats() CacheStats
	Close() error
}

// CacheItem represents an item to be cached
type CacheItem struct {
	Value []byte        `json:"value"`
	TTL   time.Duration `json:"ttl"`
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits      int64         `json:"hits"`
	Misses    int64         `json:"misses"`
	Sets      int64         `json:"sets"`
	Deletes   int64         `json:"deletes"`
	Evictions int64         `json:"evictions"`
	Size      int64         `json:"size"`
	Items     int64         `json:"items"`
	HitRate   float64       `json:"hit_rate"`
	LastReset time.Time     `json:"last_reset"`
	Uptime    time.Duration `json:"uptime"`
}

// Config represents cache configuration
type Config struct {
	Type           string        `json:"type" yaml:"type"` // memory, redis
	TTL            time.Duration `json:"ttl" yaml:"ttl"`
	MaxSize        int64         `json:"max_size" yaml:"max_size"`
	MaxItems       int64         `json:"max_items" yaml:"max_items"`
	EvictionPolicy string        `json:"eviction_policy" yaml:"eviction_policy"` // lru, lfu, fifo

	// Redis configuration
	RedisURL      string `json:"redis_url" yaml:"redis_url"`
	RedisPassword string `json:"redis_password" yaml:"redis_password"`
	RedisDB       int    `json:"redis_db" yaml:"redis_db"`
	RedisPrefix   string `json:"redis_prefix" yaml:"redis_prefix"`

	// Memory cache configuration
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`

	// Advanced settings
	Compression bool   `json:"compression" yaml:"compression"`
	Serializer  string `json:"serializer" yaml:"serializer"` // json, msgpack, gob
}

// DefaultConfig returns default cache configuration
func DefaultConfig() *Config {
	return &Config{
		Type:            "memory",
		TTL:             1 * time.Hour,
		MaxSize:         100 * 1024 * 1024, // 100MB
		MaxItems:        10000,
		EvictionPolicy:  "lru",
		CleanupInterval: 10 * time.Minute,
		Compression:     false,
		Serializer:      "json",
		RedisPrefix:     "n8n:",
	}
}

// cacheEntry represents an entry in the memory cache
type cacheEntry struct {
	Value       []byte    `json:"value"`
	ExpiresAt   time.Time `json:"expires_at"`
	AccessTime  time.Time `json:"access_time"`
	AccessCount int64     `json:"access_count"`
	Size        int64     `json:"size"`
}

// isExpired checks if the cache entry has expired
func (e *cacheEntry) isExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// MemoryCache implements an in-memory cache with LRU eviction
type MemoryCache struct {
	config    *Config
	data      map[string]*cacheEntry
	mutex     sync.RWMutex
	stats     CacheStats
	startTime time.Time
	logger    logger.Logger
	stopChan  chan struct{}
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(config *Config, log logger.Logger) *MemoryCache {
	if config == nil {
		config = DefaultConfig()
	}

	cache := &MemoryCache{
		config:    config,
		data:      make(map[string]*cacheEntry),
		stats:     CacheStats{LastReset: time.Now()},
		startTime: time.Now(),
		logger:    log,
		stopChan:  make(chan struct{}),
	}

	// Start cleanup routine
	go cache.cleanupRoutine()

	return cache
}

// Get retrieves a value from the cache
func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mutex.RLock()
	entry, exists := c.data[key]
	c.mutex.RUnlock()

	if !exists {
		c.updateStats(func(s *CacheStats) { s.Misses++ })
		return nil, errors.NewNotFoundError("cache key not found")
	}

	if entry.isExpired() {
		// Remove expired entry
		c.mutex.Lock()
		delete(c.data, key)
		c.mutex.Unlock()

		c.updateStats(func(s *CacheStats) {
			s.Misses++
			s.Evictions++
			s.Items--
		})
		return nil, errors.NewNotFoundError("cache key expired")
	}

	// Update access statistics for LRU/LFU
	c.mutex.Lock()
	entry.AccessTime = time.Now()
	entry.AccessCount++
	c.mutex.Unlock()

	c.updateStats(func(s *CacheStats) { s.Hits++ })
	return entry.Value, nil
}

// Set stores a value in the cache
func (c *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.config.TTL
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	entry := &cacheEntry{
		Value:       value,
		ExpiresAt:   expiresAt,
		AccessTime:  time.Now(),
		AccessCount: 1,
		Size:        int64(len(value)),
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if we need to evict entries
	if err := c.evictIfNeeded(entry.Size); err != nil {
		return err
	}

	// Store the entry
	oldEntry, existed := c.data[key]
	c.data[key] = entry

	// Update statistics
	c.updateStats(func(s *CacheStats) {
		s.Sets++
		if existed {
			s.Size = s.Size - oldEntry.Size + entry.Size
		} else {
			s.Size += entry.Size
			s.Items++
		}
	})

	return nil
}

// Delete removes a value from the cache
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.data[key]
	if !exists {
		return nil // Deleting non-existent key is not an error
	}

	delete(c.data, key)

	c.updateStats(func(s *CacheStats) {
		s.Deletes++
		s.Items--
		s.Size -= entry.Size
	})

	return nil
}

// Exists checks if a key exists in the cache
func (c *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	c.mutex.RLock()
	entry, exists := c.data[key]
	c.mutex.RUnlock()

	if !exists {
		return false, nil
	}

	if entry.isExpired() {
		// Clean up expired entry
		c.mutex.Lock()
		delete(c.data, key)
		c.mutex.Unlock()

		c.updateStats(func(s *CacheStats) {
			s.Evictions++
			s.Items--
		})
		return false, nil
	}

	return true, nil
}

// Clear removes all entries from the cache
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data = make(map[string]*cacheEntry)

	c.updateStats(func(s *CacheStats) {
		s.Items = 0
		s.Size = 0
	})

	return nil
}

// GetMany retrieves multiple values from the cache
func (c *MemoryCache) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	for _, key := range keys {
		if value, err := c.Get(ctx, key); err == nil {
			result[key] = value
		}
	}

	return result, nil
}

// SetMany stores multiple values in the cache
func (c *MemoryCache) SetMany(ctx context.Context, items map[string]CacheItem) error {
	for key, item := range items {
		if err := c.Set(ctx, key, item.Value, item.TTL); err != nil {
			return err
		}
	}
	return nil
}

// DeleteMany removes multiple values from the cache
func (c *MemoryCache) DeleteMany(ctx context.Context, keys []string) error {
	for _, key := range keys {
		if err := c.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// GetStats returns cache statistics
func (c *MemoryCache) GetStats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stats := c.stats
	stats.Uptime = time.Since(c.startTime)

	if stats.Hits+stats.Misses > 0 {
		stats.HitRate = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}

	return stats
}

// Close shuts down the cache
func (c *MemoryCache) Close() error {
	close(c.stopChan)
	return nil
}

// evictIfNeeded evicts entries if necessary to make room for new entry
func (c *MemoryCache) evictIfNeeded(newEntrySize int64) error {
	// Check size limit
	if c.config.MaxSize > 0 && c.stats.Size+newEntrySize > c.config.MaxSize {
		if err := c.evictEntries(newEntrySize); err != nil {
			return err
		}
	}

	// Check item count limit
	if c.config.MaxItems > 0 && c.stats.Items >= c.config.MaxItems {
		if err := c.evictEntries(0); err != nil {
			return err
		}
	}

	return nil
}

// evictEntries evicts entries based on the configured policy
func (c *MemoryCache) evictEntries(spaceNeeded int64) error {
	if len(c.data) == 0 {
		return errors.NewValidationError("cache is full and no entries to evict")
	}

	var keysToEvict []string

	switch c.config.EvictionPolicy {
	case "lru":
		keysToEvict = c.getLRUKeys(spaceNeeded)
	case "lfu":
		keysToEvict = c.getLFUKeys(spaceNeeded)
	case "fifo":
		keysToEvict = c.getFIFOKeys(spaceNeeded)
	default:
		keysToEvict = c.getLRUKeys(spaceNeeded)
	}

	// Evict the selected keys
	var evictedSize int64
	for _, key := range keysToEvict {
		if entry, exists := c.data[key]; exists {
			evictedSize += entry.Size
			delete(c.data, key)
		}
	}

	c.updateStats(func(s *CacheStats) {
		s.Evictions += int64(len(keysToEvict))
		s.Items -= int64(len(keysToEvict))
		s.Size -= evictedSize
	})

	return nil
}

// getLRUKeys returns keys for LRU eviction
func (c *MemoryCache) getLRUKeys(spaceNeeded int64) []string {
	type keyTime struct {
		key  string
		time time.Time
		size int64
	}

	var entries []keyTime
	for key, entry := range c.data {
		entries = append(entries, keyTime{key, entry.AccessTime, entry.Size})
	}

	// Sort by access time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].time.After(entries[j].time) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	var keys []string
	var freedSpace int64

	for _, entry := range entries {
		keys = append(keys, entry.key)
		freedSpace += entry.size

		if spaceNeeded > 0 && freedSpace >= spaceNeeded {
			break
		}
		if spaceNeeded == 0 && len(keys) >= len(c.data)/4 { // Evict 25% when just reducing count
			break
		}
	}

	return keys
}

// getLFUKeys returns keys for LFU eviction
func (c *MemoryCache) getLFUKeys(spaceNeeded int64) []string {
	type keyCount struct {
		key   string
		count int64
		size  int64
	}

	var entries []keyCount
	for key, entry := range c.data {
		entries = append(entries, keyCount{key, entry.AccessCount, entry.Size})
	}

	// Sort by access count (least frequent first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].count > entries[j].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	var keys []string
	var freedSpace int64

	for _, entry := range entries {
		keys = append(keys, entry.key)
		freedSpace += entry.size

		if spaceNeeded > 0 && freedSpace >= spaceNeeded {
			break
		}
		if spaceNeeded == 0 && len(keys) >= len(c.data)/4 {
			break
		}
	}

	return keys
}

// getFIFOKeys returns keys for FIFO eviction (oldest entries first)
func (c *MemoryCache) getFIFOKeys(spaceNeeded int64) []string {
	// For FIFO, we would need to track insertion time
	// For simplicity, using LRU as fallback
	return c.getLRUKeys(spaceNeeded)
}

// cleanupRoutine periodically removes expired entries
func (c *MemoryCache) cleanupRoutine() {
	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupExpired()
		case <-c.stopChan:
			return
		}
	}
}

// cleanupExpired removes expired entries
func (c *MemoryCache) cleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var expiredKeys []string
	var freedSize int64

	for key, entry := range c.data {
		if entry.isExpired() {
			expiredKeys = append(expiredKeys, key)
			freedSize += entry.Size
		}
	}

	for _, key := range expiredKeys {
		delete(c.data, key)
	}

	if len(expiredKeys) > 0 {
		c.updateStats(func(s *CacheStats) {
			s.Evictions += int64(len(expiredKeys))
			s.Items -= int64(len(expiredKeys))
			s.Size -= freedSize
		})

		c.logger.Debug("Cleaned up expired cache entries", "count", len(expiredKeys))
	}
}

// updateStats safely updates cache statistics
func (c *MemoryCache) updateStats(updateFunc func(*CacheStats)) {
	// Note: This assumes the caller already holds appropriate locks
	updateFunc(&c.stats)
}

// Manager manages multiple cache instances
type Manager struct {
	caches map[string]Cache
	mutex  sync.RWMutex
	logger logger.Logger
}

// NewManager creates a new cache manager
func NewManager(log logger.Logger) *Manager {
	return &Manager{
		caches: make(map[string]Cache),
		logger: log,
	}
}

// GetCache returns a cache instance by name
func (m *Manager) GetCache(name string) (Cache, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	cache, exists := m.caches[name]
	if !exists {
		return nil, errors.NewNotFoundError(fmt.Sprintf("cache '%s' not found", name))
	}

	return cache, nil
}

// CreateCache creates a new cache instance
func (m *Manager) CreateCache(name string, config *Config) (Cache, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.caches[name]; exists {
		return nil, errors.NewValidationError(fmt.Sprintf("cache '%s' already exists", name))
	}

	var cache Cache
	var err error

	switch config.Type {
	case "memory":
		cache = NewMemoryCache(config, m.logger.With("cache", name))
	case "redis":
		// Redis implementation would go here
		return nil, errors.NewValidationError("Redis cache not implemented yet")
	default:
		return nil, errors.NewValidationError(fmt.Sprintf("unsupported cache type: %s", config.Type))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	m.caches[name] = cache
	m.logger.Info("Cache created", "name", name, "type", config.Type)

	return cache, nil
}

// RemoveCache removes a cache instance
func (m *Manager) RemoveCache(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cache, exists := m.caches[name]
	if !exists {
		return errors.NewNotFoundError(fmt.Sprintf("cache '%s' not found", name))
	}

	if err := cache.Close(); err != nil {
		m.logger.Error("Error closing cache", "name", name, "error", err)
	}

	delete(m.caches, name)
	m.logger.Info("Cache removed", "name", name)

	return nil
}

// GetAllStats returns statistics for all caches
func (m *Manager) GetAllStats() map[string]CacheStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := make(map[string]CacheStats)
	for name, cache := range m.caches {
		stats[name] = cache.GetStats()
	}

	return stats
}

// Close closes all cache instances
func (m *Manager) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for name, cache := range m.caches {
		if err := cache.Close(); err != nil {
			m.logger.Error("Error closing cache", "name", name, "error", err)
		}
	}

	m.caches = make(map[string]Cache)
	return nil
}

// Helper functions for common cache patterns

// GetOrSet retrieves a value from cache, or sets it if not found
func GetOrSet(ctx context.Context, cache Cache, key string, ttl time.Duration, valueFunc func() ([]byte, error)) ([]byte, error) {
	// Try to get from cache first
	value, err := cache.Get(ctx, key)
	if err == nil {
		return value, nil
	}

	// If not found, generate value
	value, err = valueFunc()
	if err != nil {
		return nil, err
	}

	// Store in cache for next time
	cache.Set(ctx, key, value, ttl)

	return value, nil
}

// GetJSON retrieves and unmarshals a JSON value from cache
func GetJSON(ctx context.Context, cache Cache, key string, target interface{}) error {
	data, err := cache.Get(ctx, key)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}

// SetJSON marshals and stores a JSON value in cache
func SetJSON(ctx context.Context, cache Cache, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return cache.Set(ctx, key, data, ttl)
}
