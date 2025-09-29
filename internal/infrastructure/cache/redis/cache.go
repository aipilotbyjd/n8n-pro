package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"n8n-pro/pkg/logger"

	"github.com/go-redis/redis/v8"
)

// Cache provides Redis caching functionality
type Cache struct {
	client *redis.Client
	logger logger.Logger
}

// New creates a new Redis cache instance
func New(address, password string, db int, logger logger.Logger) *Cache {
	if logger == nil {
		logger = logger.New("redis-cache")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password,
		DB:       db,
	})

	cache := &Cache{
		client: client,
		logger: logger,
	}

	return cache
}

// Get retrieves a value from Redis
func (c *Cache) Get(ctx context.Context, key string) (interface{}, bool) {
	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			c.logger.Debug("Cache miss", "key", key)
			return nil, false
		}
		
		c.logger.Error("Failed to get from cache", "key", key, "error", err)
		return nil, false
	}

	var result interface{}
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		c.logger.Error("Failed to unmarshal cached value", "key", key, "error", err)
		return nil, false
	}

	c.logger.Debug("Cache hit", "key", key)

	return result, true
}

// Set stores a value in Redis with expiration
func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		c.logger.Error("Failed to marshal value for cache", "key", key, "error", err)
		return err
	}

	var exp time.Duration
	if expiration > 0 {
		exp = expiration
	} else {
		// Default expiration of 1 hour if not specified
		exp = time.Hour
	}

	if err := c.client.Set(ctx, key, jsonValue, exp).Err(); err != nil {
		c.logger.Error("Failed to set cache", "key", key, "error", err)
		return err
	}

	c.logger.Debug("Cache set", "key", key, "expiration", exp)

	return nil
}

// Delete removes a value from Redis
func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		c.logger.Error("Failed to delete from cache", "key", key, "error", err)
		return err
	}

	c.logger.Debug("Cache delete", "key", key)

	return nil
}

// Exists checks if a key exists in Redis
func (c *Cache) Exists(ctx context.Context, key string) bool {
	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		c.logger.Error("Failed to check cache existence", "key", key, "error", err)
		return false
	}

	exists := count > 0
	if exists {
		c.logger.Debug("Cache exists", "key", key)
	} else {
		c.logger.Debug("Cache does not exist", "key", key)
	}

	return exists
}

// Clear removes all items from Redis (use with caution)
func (c *Cache) Clear(ctx context.Context) error {
	// Get all keys matching a pattern (you might want to use a specific pattern)
	// For now, we'll flush the entire database
	if err := c.client.FlushDB(ctx).Err(); err != nil {
		c.logger.Error("Failed to flush Redis DB", "error", err)
		return err
	}

	c.logger.Debug("Cache cleared")

	return nil
}

// GetMultiple retrieves multiple values from Redis
func (c *Cache) GetMultiple(ctx context.Context, keys []string) map[string]interface{} {
	if len(keys) == 0 {
		return make(map[string]interface{})
	}

	cmd := c.client.MGet(ctx, keys...)
	if cmd.Err() != nil {
		c.logger.Error("Failed to get multiple values from cache", "keys", keys, "error", cmd.Err())
		return make(map[string]interface{})
	}

	values := cmd.Val()
	result := make(map[string]interface{})

	for i, key := range keys {
		if i >= len(values) || values[i] == nil {
			continue
		}

		value := values[i]
		if strValue, ok := value.(string); ok {
			var resultValue interface{}
			if err := json.Unmarshal([]byte(strValue), &resultValue); err != nil {
				c.logger.Error("Failed to unmarshal cached value", "key", key, "error", err)
				continue
			}
			result[key] = resultValue
		}
	}

	return result
}

// SetMultiple stores multiple values in Redis
func (c *Cache) SetMultiple(ctx context.Context, items map[string]interface{}, expiration time.Duration) error {
	if len(items) == 0 {
		return nil
	}

	var exp time.Duration
	if expiration > 0 {
		exp = expiration
	} else {
		// Default expiration of 1 hour if not specified
		exp = time.Hour
	}

	pipe := c.client.Pipeline()

	for key, value := range items {
		jsonValue, err := json.Marshal(value)
		if err != nil {
			c.logger.Error("Failed to marshal value for cache", "key", key, "error", err)
			continue
		}

		pipe.Set(ctx, key, jsonValue, exp)
	}

	cmds, err := pipe.Exec(ctx)
	if err != nil {
		c.logger.Error("Failed to set multiple values in cache", "error", err)
		return err
	}

	for _, cmd := range cmds {
		if cmd.Err() != nil {
			c.logger.Error("Failed to execute cache command", "cmd", cmd, "error", cmd.Err())
		}
	}

	c.logger.Debug("Cache multiple set", "count", len(items))

	return nil
}

// Keys returns all keys in Redis matching a pattern
func (c *Cache) Keys(ctx context.Context, pattern string) []string {
	if pattern == "" {
		pattern = "*"
	}

	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.logger.Error("Failed to get keys from cache", "pattern", pattern, "error", err)
		return []string{}
	}

	return keys
}

// Size returns the number of items in Redis
func (c *Cache) Size(ctx context.Context) int {
	count, err := c.client.DBSize(ctx).Result()
	if err != nil {
		c.logger.Error("Failed to get cache size", "error", err)
		return 0
	}

	return int(count)
}

// Expire sets expiration for a key
func (c *Cache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	if err := c.client.Expire(ctx, key, expiration).Err(); err != nil {
		c.logger.Error("Failed to set expiration", "key", key, "error", err)
		return err
	}

	return nil
}

// TTL returns the time to live for a key
func (c *Cache) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := c.client.TTL(ctx, key).Result()
	if err != nil {
		c.logger.Error("Failed to get TTL", "key", key, "error", err)
		return 0, err
	}

	return ttl, nil
}

// Close closes the Redis connection
func (c *Cache) Close() error {
	return c.client.Close()
}

// Ping tests Redis connection
func (c *Cache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}