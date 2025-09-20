package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"n8n-pro/pkg/errors"
)

// Strategy represents different retry strategies
type Strategy string

const (
	StrategyFixed       Strategy = "fixed"
	StrategyLinear      Strategy = "linear"
	StrategyExponential Strategy = "exponential"
	StrategyCustom      Strategy = "custom"
)

// Config holds retry configuration
type Config struct {
	MaxAttempts   int           `json:"max_attempts" yaml:"max_attempts"`
	InitialDelay  time.Duration `json:"initial_delay" yaml:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay" yaml:"max_delay"`
	Strategy      Strategy      `json:"strategy" yaml:"strategy"`
	Multiplier    float64       `json:"multiplier" yaml:"multiplier"`
	Jitter        bool          `json:"jitter" yaml:"jitter"`
	JitterPercent float64       `json:"jitter_percent" yaml:"jitter_percent"`
	Timeout       time.Duration `json:"timeout" yaml:"timeout"`
}

// DefaultConfig returns default retry configuration
func DefaultConfig() *Config {
	return &Config{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		Strategy:      StrategyExponential,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.1,
		Timeout:       5 * time.Minute,
	}
}

// PresetConfigs for common scenarios
var (
	HTTPConfig = &Config{
		MaxAttempts:   5,
		InitialDelay:  200 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		Strategy:      StrategyExponential,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.2,
		Timeout:       30 * time.Second,
	}

	DatabaseConfig = &Config{
		MaxAttempts:   3,
		InitialDelay:  50 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		Strategy:      StrategyExponential,
		Multiplier:    1.5,
		Jitter:        true,
		JitterPercent: 0.1,
		Timeout:       30 * time.Second,
	}

	ExternalServiceConfig = &Config{
		MaxAttempts:   4,
		InitialDelay:  500 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		Strategy:      StrategyExponential,
		Multiplier:    2.5,
		Jitter:        true,
		JitterPercent: 0.3,
		Timeout:       2 * time.Minute,
	}

	WorkflowNodeConfig = &Config{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      60 * time.Second,
		Strategy:      StrategyExponential,
		Multiplier:    2.0,
		Jitter:        false,
		JitterPercent: 0.0,
		Timeout:       10 * time.Minute,
	}
)

// RetryFunc represents a function that can be retried
type RetryFunc func(ctx context.Context, attempt int) error

// RetryCondition determines whether an error should trigger a retry
type RetryCondition func(err error, attempt int) bool

// BackoffFunc calculates the delay for the next attempt
type BackoffFunc func(attempt int, config *Config) time.Duration

// Retryer handles retry logic
type Retryer struct {
	config    *Config
	condition RetryCondition
	backoff   BackoffFunc
	onRetry   func(attempt int, err error, delay time.Duration)
}

// New creates a new Retryer with default configuration
func New() *Retryer {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Retryer with custom configuration
func NewWithConfig(config *Config) *Retryer {
	r := &Retryer{
		config:    config,
		condition: DefaultRetryCondition,
		backoff:   getBackoffFunc(config.Strategy),
	}
	return r
}

// WithCondition sets a custom retry condition
func (r *Retryer) WithCondition(condition RetryCondition) *Retryer {
	r.condition = condition
	return r
}

// WithOnRetry sets a callback function called on each retry attempt
func (r *Retryer) WithOnRetry(onRetry func(attempt int, err error, delay time.Duration)) *Retryer {
	r.onRetry = onRetry
	return r
}

// Execute runs the provided function with retry logic
func (r *Retryer) Execute(ctx context.Context, fn RetryFunc) error {
	if r.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.config.Timeout)
		defer cancel()
	}

	var lastErr error

	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute the function
		err := fn(ctx, attempt)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if we should retry
		if attempt >= r.config.MaxAttempts || !r.condition(err, attempt) {
			break
		}

		// Calculate delay for next attempt
		delay := r.backoff(attempt, r.config)

		// Call retry callback if provided
		if r.onRetry != nil {
			r.onRetry(attempt, err, delay)
		}

		// Wait for the calculated delay
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	// Wrap the final error with retry information
	if appErr := errors.GetAppError(lastErr); appErr != nil {
		return appErr.WithContext("retry_attempts", r.config.MaxAttempts).
			WithContext("final_attempt", true)
	}

	return errors.Wrap(lastErr, errors.ErrorTypeInternal, errors.CodeInternal,
		fmt.Sprintf("operation failed after %d attempts", r.config.MaxAttempts)).
		WithContext("retry_attempts", r.config.MaxAttempts)
}

// ExecuteWithResult runs a function that returns a value and error
func ExecuteWithResult[T any](ctx context.Context, config *Config, fn func(ctx context.Context, attempt int) (T, error)) (T, error) {
	var result T
	var resultSet bool

	retryFn := func(ctx context.Context, attempt int) error {
		r, err := fn(ctx, attempt)
		if err == nil {
			result = r
			resultSet = true
		}
		return err
	}

	retryer := NewWithConfig(config)
	err := retryer.Execute(ctx, retryFn)

	if !resultSet {
		var zero T
		return zero, err
	}

	return result, err
}

// DefaultRetryCondition checks if an error should trigger a retry
func DefaultRetryCondition(err error, attempt int) bool {
	if err == nil {
		return false
	}

	// Check if it's an AppError and if it's retryable
	if appErr := errors.GetAppError(err); appErr != nil {
		return appErr.IsRetryable()
	}

	// Default behavior for non-AppErrors
	return isRetryableError(err)
}

// isRetryableError determines if a standard error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Add logic for common retryable errors
	errStr := err.Error()

	// Network-related errors
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"rate limit",
		"circuit breaker open",
	}

	for _, pattern := range retryablePatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

// ErrorTypeCondition creates a retry condition based on error type
func ErrorTypeCondition(errorTypes ...errors.ErrorType) RetryCondition {
	return func(err error, attempt int) bool {
		if appErr := errors.GetAppError(err); appErr != nil {
			for _, errorType := range errorTypes {
				if appErr.Type == errorType {
					return true
				}
			}
		}
		return false
	}
}

// ErrorCodeCondition creates a retry condition based on error code
func ErrorCodeCondition(codes ...errors.ErrorCode) RetryCondition {
	return func(err error, attempt int) bool {
		if appErr := errors.GetAppError(err); appErr != nil {
			for _, code := range codes {
				if appErr.Code == code {
					return true
				}
			}
		}
		return false
	}
}

// CombineConditions combines multiple retry conditions with AND logic
func CombineConditions(conditions ...RetryCondition) RetryCondition {
	return func(err error, attempt int) bool {
		for _, condition := range conditions {
			if !condition(err, attempt) {
				return false
			}
		}
		return true
	}
}

// AnyCondition combines multiple retry conditions with OR logic
func AnyCondition(conditions ...RetryCondition) RetryCondition {
	return func(err error, attempt int) bool {
		for _, condition := range conditions {
			if condition(err, attempt) {
				return true
			}
		}
		return false
	}
}

// Backoff strategies

func getBackoffFunc(strategy Strategy) BackoffFunc {
	switch strategy {
	case StrategyFixed:
		return FixedBackoff
	case StrategyLinear:
		return LinearBackoff
	case StrategyExponential:
		return ExponentialBackoff
	default:
		return ExponentialBackoff
	}
}

// FixedBackoff provides a fixed delay between retries
func FixedBackoff(attempt int, config *Config) time.Duration {
	delay := config.InitialDelay
	if config.Jitter {
		delay = addJitter(delay, config.JitterPercent)
	}
	return delay
}

// LinearBackoff provides a linearly increasing delay
func LinearBackoff(attempt int, config *Config) time.Duration {
	delay := config.InitialDelay * time.Duration(attempt)
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	if config.Jitter {
		delay = addJitter(delay, config.JitterPercent)
	}
	return delay
}

// ExponentialBackoff provides exponentially increasing delays
func ExponentialBackoff(attempt int, config *Config) time.Duration {
	multiplier := config.Multiplier
	if multiplier <= 1.0 {
		multiplier = 2.0
	}

	delay := time.Duration(float64(config.InitialDelay) * math.Pow(multiplier, float64(attempt-1)))
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	if config.Jitter {
		delay = addJitter(delay, config.JitterPercent)
	}
	return delay
}

// CustomBackoff allows for a custom backoff function
func CustomBackoff(backoffFunc func(attempt int) time.Duration) BackoffFunc {
	return func(attempt int, config *Config) time.Duration {
		delay := backoffFunc(attempt)
		if config.Jitter {
			delay = addJitter(delay, config.JitterPercent)
		}
		return delay
	}
}

// addJitter adds randomness to prevent thundering herd
func addJitter(delay time.Duration, jitterPercent float64) time.Duration {
	if jitterPercent <= 0 {
		return delay
	}

	jitter := float64(delay) * jitterPercent
	adjustment := (rand.Float64() - 0.5) * 2 * jitter

	result := time.Duration(float64(delay) + adjustment)
	if result < 0 {
		result = delay / 2
	}

	return result
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Convenience functions for common retry scenarios

// RetryHTTP retries HTTP operations
func RetryHTTP(ctx context.Context, fn RetryFunc) error {
	return NewWithConfig(HTTPConfig).Execute(ctx, fn)
}

// RetryDatabase retries database operations
func RetryDatabase(ctx context.Context, fn RetryFunc) error {
	return NewWithConfig(DatabaseConfig).Execute(ctx, fn)
}

// RetryExternalService retries external service calls
func RetryExternalService(ctx context.Context, fn RetryFunc) error {
	return NewWithConfig(ExternalServiceConfig).Execute(ctx, fn)
}

// RetryWorkflowNode retries workflow node execution
func RetryWorkflowNode(ctx context.Context, fn RetryFunc) error {
	return NewWithConfig(WorkflowNodeConfig).Execute(ctx, fn)
}

// Circuit breaker integration
type CircuitBreaker struct {
	failures    int
	lastFailure time.Time
	threshold   int
	timeout     time.Duration
	state       string // "closed", "open", "half-open"
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
		state:     "closed",
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn RetryFunc) error {
	if cb.state == "open" {
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.state = "half-open"
		} else {
			return errors.New(errors.ErrorTypeExternal, errors.CodeResourceUnavailable, "circuit breaker open")
		}
	}

	err := fn(ctx, 1)
	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()

		if cb.failures >= cb.threshold {
			cb.state = "open"
		}
		return err
	}

	// Success - reset circuit breaker
	cb.failures = 0
	cb.state = "closed"
	return nil
}

// WithCircuitBreaker combines retry with circuit breaker
func (r *Retryer) WithCircuitBreaker(threshold int, timeout time.Duration) *RetryerWithCircuitBreaker {
	return &RetryerWithCircuitBreaker{
		retryer:        r,
		circuitBreaker: NewCircuitBreaker(threshold, timeout),
	}
}

// RetryerWithCircuitBreaker combines retry logic with circuit breaker
type RetryerWithCircuitBreaker struct {
	retryer        *Retryer
	circuitBreaker *CircuitBreaker
}

// Execute executes with both retry and circuit breaker logic
func (rcb *RetryerWithCircuitBreaker) Execute(ctx context.Context, fn RetryFunc) error {
	return rcb.circuitBreaker.Execute(ctx, func(ctx context.Context, attempt int) error {
		return rcb.retryer.Execute(ctx, fn)
	})
}
