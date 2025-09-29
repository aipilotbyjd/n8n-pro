package memory

import (
	"context"
	"sync"
	"time"

	"n8n-pro/pkg/logger"
)

// Cache provides in-memory caching functionality
type Cache struct {
	data   map[string]*cacheItem
	mutex  sync.RWMutex
	logger logger.Logger
}

// cacheItem represents a cached item with expiration
type cacheItem struct {
	value      interface{}
	expiration time.Time
}

// New creates a new in-memory cache
func New(logger logger.Logger) *Cache {
	if logger == nil {
		logger = logger.New("memory-cache")
	}

	cache := &Cache{
		data:   make(map[string]*cacheItem),
		logger: logger,
	}

	// Start cleanup goroutine
	go cache.startCleanup()

	return cache
}

// Get retrieves a value from the cache
func (c *Cache) Get(ctx context.Context, key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.data[key]
	if !exists {
		c.logger.Debug("Cache miss", "key", key)
		return nil, false
	}

	// Check if item is expired
	if time.Now().After(item.expiration) {
		c.logger.Debug("Cache item expired", "key", key)
		return nil, false
	}

	c.logger.Debug("Cache hit", "key", key)
	return item.value, true
}

// Set stores a value in the cache with expiration
func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	} else {
		// Default expiration of 1 hour if not specified
		exp = time.Now().Add(time.Hour)
	}

	c.data[key] = &cacheItem{
		value:      value,
		expiration: exp,
	}

	c.logger.Debug("Cache set", "key", key, "expiration", exp)

	return nil
}

// Delete removes a value from the cache
func (c *Cache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)

	c.logger.Debug("Cache delete", "key", key)

	return nil
}

// Exists checks if a key exists in the cache and is not expired
func (c *Cache) Exists(ctx context.Context, key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, exists := c.data[key]
	if !exists {
		return false
	}

	// Check if item is expired
	if time.Now().After(item.expiration) {
		return false
	}

	return true
}

// Clear removes all items from the cache
func (c *Cache) Clear(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data = make(map[string]*cacheItem)

	c.logger.Debug("Cache cleared")

	return nil
}

// startCleanup starts the cleanup goroutine for expired items
func (c *Cache) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Run cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpired()
	}
}

// cleanupExpired removes expired items from the cache
func (c *Cache) cleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	deleted := 0

	for key, item := range c.data {
		if now.After(item.expiration) {
			delete(c.data, key)
			deleted++
		}
	}

	if deleted > 0 {
		c.logger.Info("Cache cleanup completed", "deleted", deleted)
	}
}

// GetMultiple retrieves multiple values from the cache
func (c *Cache) GetMultiple(ctx context.Context, keys []string) map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	result := make(map[string]interface{})

	for _, key := range keys {
		item, exists := c.data[key]
		if !exists {
			continue
		}

		// Check if item is expired
		if time.Now().After(item.expiration) {
			continue
		}

		result[key] = item.value
	}

	return result
}

// SetMultiple stores multiple values in the cache
func (c *Cache) SetMultiple(ctx context.Context, items map[string]interface{}, expiration time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	} else {
		// Default expiration of 1 hour if not specified
		exp = time.Now().Add(time.Hour)
	}

	for key, value := range items {
		c.data[key] = &cacheItem{
			value:      value,
			expiration: exp,
		}
	}

	c.logger.Debug("Cache multiple set", "count", len(items))

	return nil
}

// Keys returns all cache keys
func (c *Cache) Keys(ctx context.Context) []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	keys := make([]string, 0, len(c.data))
	for key := range c.data {
		item, exists := c.data[key]
		if !exists {
			continue
		}

		// Don't include expired keys
		if time.Now().After(item.expiration) {
			continue
		}

		keys = append(keys, key)
	}

	return keys
}

// Size returns the number of items in the cache
func (c *Cache) Size(ctx context.Context) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	count := 0
	now := time.Now()

	for _, item := range c.data {
		if now.Before(item.expiration) {
			count++
		}
	}

	return count
}