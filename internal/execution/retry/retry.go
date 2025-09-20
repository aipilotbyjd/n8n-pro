package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// Strategy represents different retry strategies
type Strategy string

const (
	StrategyFixed       Strategy = "fixed"       // Fixed delay between retries
	StrategyLinear      Strategy = "linear"      // Linear increase in delay
	StrategyExponential Strategy = "exponential" // Exponential backoff
	StrategyCustom      Strategy = "custom"      // Custom retry logic
	StrategyImmediate   Strategy = "immediate"   // No delay between retries
	StrategyJittered    Strategy = "jittered"    // Exponential with jitter
)

// ErrorType represents different types of errors for retry decisions
type ErrorType string

const (
	ErrorTypeNetwork    ErrorType = "network"    // Network connectivity issues
	ErrorTypeTimeout    ErrorType = "timeout"    // Timeout errors
	ErrorTypeRateLimit  ErrorType = "rate_limit" // Rate limiting errors
	ErrorTypeServer     ErrorType = "server"     // Server errors (5xx)
	ErrorTypeValidation ErrorType = "validation" // Validation errors (usually non-retryable)
	ErrorTypeAuth       ErrorType = "auth"       // Authentication errors
	ErrorTypeQuota      ErrorType = "quota"      // Quota exceeded errors
	ErrorTypeUnknown    ErrorType = "unknown"    // Unknown error types
)

// Policy defines retry behavior
type Policy struct {
	Strategy      Strategy      `json:"strategy" yaml:"strategy"`
	MaxAttempts   int           `json:"max_attempts" yaml:"max_attempts"`
	BaseDelay     time.Duration `json:"base_delay" yaml:"base_delay"`
	MaxDelay      time.Duration `json:"max_delay" yaml:"max_delay"`
	Multiplier    float64       `json:"multiplier" yaml:"multiplier"`
	Jitter        bool          `json:"jitter" yaml:"jitter"`
	JitterPercent float64       `json:"jitter_percent" yaml:"jitter_percent"`

	// Retry conditions
	RetryableErrors    []ErrorType `json:"retryable_errors" yaml:"retryable_errors"`
	NonRetryableErrors []ErrorType `json:"non_retryable_errors" yaml:"non_retryable_errors"`
	RetryStatusCodes   []int       `json:"retry_status_codes" yaml:"retry_status_codes"`

	// Circuit breaker settings
	EnableCircuitBreaker bool          `json:"enable_circuit_breaker" yaml:"enable_circuit_breaker"`
	FailureThreshold     int           `json:"failure_threshold" yaml:"failure_threshold"`
	RecoveryTimeout      time.Duration `json:"recovery_timeout" yaml:"recovery_timeout"`

	// Custom retry condition function
	ShouldRetry func(error, int) bool `json:"-" yaml:"-"`
}

// DefaultPolicy returns a default retry policy
func DefaultPolicy() *Policy {
	return &Policy{
		Strategy:      StrategyExponential,
		MaxAttempts:   3,
		BaseDelay:     1 * time.Second,
		MaxDelay:      30 * time.Second,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.1,
		RetryableErrors: []ErrorType{
			ErrorTypeNetwork,
			ErrorTypeTimeout,
			ErrorTypeServer,
			ErrorTypeRateLimit,
		},
		NonRetryableErrors: []ErrorType{
			ErrorTypeValidation,
			ErrorTypeAuth,
		},
		RetryStatusCodes:     []int{429, 500, 502, 503, 504},
		EnableCircuitBreaker: false,
		FailureThreshold:     5,
		RecoveryTimeout:      30 * time.Second,
	}
}

// NetworkPolicy returns a policy optimized for network operations
func NetworkPolicy() *Policy {
	return &Policy{
		Strategy:      StrategyJittered,
		MaxAttempts:   5,
		BaseDelay:     500 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.25,
		RetryableErrors: []ErrorType{
			ErrorTypeNetwork,
			ErrorTypeTimeout,
			ErrorTypeServer,
			ErrorTypeRateLimit,
		},
		RetryStatusCodes:     []int{408, 429, 500, 502, 503, 504},
		EnableCircuitBreaker: true,
		FailureThreshold:     10,
		RecoveryTimeout:      60 * time.Second,
	}
}

// DatabasePolicy returns a policy optimized for database operations
func DatabasePolicy() *Policy {
	return &Policy{
		Strategy:      StrategyExponential,
		MaxAttempts:   3,
		BaseDelay:     1 * time.Second,
		MaxDelay:      15 * time.Second,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.1,
		RetryableErrors: []ErrorType{
			ErrorTypeNetwork,
			ErrorTypeTimeout,
			ErrorTypeServer,
		},
		EnableCircuitBreaker: false,
	}
}

// Attempt represents a single retry attempt
type Attempt struct {
	Number    int           `json:"number"`
	StartTime time.Time     `json:"start_time"`
	EndTime   *time.Time    `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	Success   bool          `json:"success"`
	Delay     time.Duration `json:"delay,omitempty"`
}

// RetryState tracks the state of retry attempts
type RetryState struct {
	ExecutionID   string        `json:"execution_id"`
	NodeID        string        `json:"node_id"`
	Attempts      []Attempt     `json:"attempts"`
	Policy        *Policy       `json:"policy"`
	TotalDelay    time.Duration `json:"total_delay"`
	StartTime     time.Time     `json:"start_time"`
	LastAttempt   *time.Time    `json:"last_attempt"`
	IsExhausted   bool          `json:"is_exhausted"`
	CircuitOpen   bool          `json:"circuit_open"`
	NextAttemptAt *time.Time    `json:"next_attempt_at"`
}

// Retrier handles retry logic
type Retrier struct {
	logger logger.Logger
	rand   *rand.Rand
}

// New creates a new Retrier instance
func New(log logger.Logger) *Retrier {
	return &Retrier{
		logger: log,
		rand:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Execute executes a function with retry logic
func (r *Retrier) Execute(ctx context.Context, policy *Policy, fn func() error) error {
	if policy == nil {
		policy = DefaultPolicy()
	}

	state := &RetryState{
		Policy:    policy,
		StartTime: time.Now(),
		Attempts:  make([]Attempt, 0, policy.MaxAttempts),
	}

	return r.ExecuteWithState(ctx, state, fn)
}

// ExecuteWithState executes with explicit state tracking
func (r *Retrier) ExecuteWithState(ctx context.Context, state *RetryState, fn func() error) error {
	for attempt := 1; attempt <= state.Policy.MaxAttempts; attempt++ {
		// Check context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Check circuit breaker
		if state.CircuitOpen && state.Policy.EnableCircuitBreaker {
			if time.Since(*state.LastAttempt) < state.Policy.RecoveryTimeout {
				return errors.NewExecutionError("Circuit breaker is open")
			}
			// Reset circuit breaker
			state.CircuitOpen = false
			r.logger.Info("Circuit breaker reset", "execution_id", state.ExecutionID, "node_id", state.NodeID)
		}

		// Add delay for subsequent attempts
		if attempt > 1 {
			delay := r.calculateDelay(state.Policy, attempt-1)
			state.TotalDelay += delay

			r.logger.Info("Delaying retry attempt",
				"attempt", attempt,
				"delay", delay,
				"execution_id", state.ExecutionID,
				"node_id", state.NodeID,
			)

			// Set next attempt time
			nextAttempt := time.Now().Add(delay)
			state.NextAttemptAt = &nextAttempt

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Record attempt start
		attemptStart := time.Now()
		attemptRecord := Attempt{
			Number:    attempt,
			StartTime: attemptStart,
		}

		// Execute function
		err := fn()

		// Record attempt end
		attemptEnd := time.Now()
		attemptRecord.EndTime = &attemptEnd
		attemptRecord.Duration = attemptEnd.Sub(attemptStart)
		state.LastAttempt = &attemptEnd

		if err == nil {
			// Success
			attemptRecord.Success = true
			state.Attempts = append(state.Attempts, attemptRecord)

			r.logger.Info("Execution succeeded",
				"attempt", attempt,
				"total_duration", time.Since(state.StartTime),
				"execution_id", state.ExecutionID,
				"node_id", state.NodeID,
			)

			return nil
		}

		// Failure - record error
		attemptRecord.Error = err.Error()
		state.Attempts = append(state.Attempts, attemptRecord)

		r.logger.Warn("Execution attempt failed",
			"attempt", attempt,
			"error", err,
			"execution_id", state.ExecutionID,
			"node_id", state.NodeID,
		)

		// Check if we should retry
		if !r.shouldRetry(err, attempt, state.Policy) {
			r.logger.Info("Error is not retryable",
				"error", err,
				"attempt", attempt,
				"execution_id", state.ExecutionID,
				"node_id", state.NodeID,
			)
			return err
		}

		// Check if this is the last attempt
		if attempt == state.Policy.MaxAttempts {
			state.IsExhausted = true

			// Update circuit breaker
			if state.Policy.EnableCircuitBreaker {
				consecutiveFailures := r.countConsecutiveFailures(state.Attempts)
				if consecutiveFailures >= state.Policy.FailureThreshold {
					state.CircuitOpen = true
					r.logger.Warn("Circuit breaker opened",
						"consecutive_failures", consecutiveFailures,
						"threshold", state.Policy.FailureThreshold,
						"execution_id", state.ExecutionID,
						"node_id", state.NodeID,
					)
				}
			}

			return fmt.Errorf("max retry attempts (%d) exceeded: %w", state.Policy.MaxAttempts, err)
		}
	}

	return errors.NewExecutionError("Unexpected end of retry loop")
}

// calculateDelay calculates the delay for a given attempt number
func (r *Retrier) calculateDelay(policy *Policy, attempt int) time.Duration {
	var delay time.Duration

	switch policy.Strategy {
	case StrategyFixed:
		delay = policy.BaseDelay

	case StrategyLinear:
		delay = time.Duration(float64(policy.BaseDelay) * float64(attempt))

	case StrategyExponential, StrategyJittered:
		delay = time.Duration(float64(policy.BaseDelay) * math.Pow(policy.Multiplier, float64(attempt-1)))

	case StrategyImmediate:
		delay = 0

	case StrategyCustom:
		// Custom strategy would be implemented via callback
		delay = policy.BaseDelay

	default:
		delay = policy.BaseDelay
	}

	// Apply maximum delay limit
	if delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}

	// Apply jitter if enabled
	if policy.Jitter && delay > 0 {
		jitterAmount := float64(delay) * policy.JitterPercent
		jitter := time.Duration(r.rand.Float64()*jitterAmount*2 - jitterAmount)
		delay += jitter

		// Ensure delay is not negative
		if delay < 0 {
			delay = 0
		}
	}

	return delay
}

// shouldRetry determines if an error should trigger a retry
func (r *Retrier) shouldRetry(err error, attempt int, policy *Policy) bool {
	// Custom retry function takes precedence
	if policy.ShouldRetry != nil {
		return policy.ShouldRetry(err, attempt)
	}

	// Check error type
	errorType := r.classifyError(err)

	// Check non-retryable errors first
	for _, nonRetryable := range policy.NonRetryableErrors {
		if errorType == nonRetryable {
			return false
		}
	}

	// Check retryable errors
	for _, retryable := range policy.RetryableErrors {
		if errorType == retryable {
			return true
		}
	}

	// Check status codes for HTTP errors
	if httpErr, ok := err.(*errors.HTTPError); ok {
		for _, code := range policy.RetryStatusCodes {
			if httpErr.StatusCode == code {
				return true
			}
		}
	}

	// Default to not retrying unknown errors
	return false
}

// classifyError classifies an error into a retry-relevant type
func (r *Retrier) classifyError(err error) ErrorType {
	switch e := err.(type) {
	case *errors.NetworkError:
		return ErrorTypeNetwork
	case *errors.TimeoutError:
		return ErrorTypeTimeout
	case *errors.ValidationError:
		return ErrorTypeValidation
	case *errors.UnauthorizedError, *errors.ForbiddenError:
		return ErrorTypeAuth
	case *errors.HTTPError:
		if e.StatusCode == 429 {
			return ErrorTypeRateLimit
		}
		if e.StatusCode >= 500 && e.StatusCode < 600 {
			return ErrorTypeServer
		}
		if e.StatusCode >= 400 && e.StatusCode < 500 {
			return ErrorTypeValidation
		}
	case *errors.QuotaError:
		return ErrorTypeQuota
	}

	return ErrorTypeUnknown
}

// countConsecutiveFailures counts consecutive failures from the end
func (r *Retrier) countConsecutiveFailures(attempts []Attempt) int {
	count := 0
	for i := len(attempts) - 1; i >= 0; i-- {
		if !attempts[i].Success {
			count++
		} else {
			break
		}
	}
	return count
}

// ExecuteWithBackoff is a convenience function for simple exponential backoff
func (r *Retrier) ExecuteWithBackoff(ctx context.Context, maxAttempts int, baseDelay time.Duration, fn func() error) error {
	policy := &Policy{
		Strategy:      StrategyExponential,
		MaxAttempts:   maxAttempts,
		BaseDelay:     baseDelay,
		MaxDelay:      30 * time.Second,
		Multiplier:    2.0,
		Jitter:        true,
		JitterPercent: 0.1,
		RetryableErrors: []ErrorType{
			ErrorTypeNetwork,
			ErrorTypeTimeout,
			ErrorTypeServer,
		},
	}

	return r.Execute(ctx, policy, fn)
}

// ExecuteWithTimeout executes with both retry logic and timeout
func (r *Retrier) ExecuteWithTimeout(ctx context.Context, policy *Policy, timeout time.Duration, fn func() error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return r.Execute(timeoutCtx, policy, fn)
}

// GetRetryStats returns statistics about retry behavior
func (r *Retrier) GetRetryStats(state *RetryState) map[string]interface{} {
	if state == nil {
		return nil
	}

	stats := make(map[string]interface{})
	stats["total_attempts"] = len(state.Attempts)
	stats["total_delay"] = state.TotalDelay
	stats["total_duration"] = time.Since(state.StartTime)
	stats["is_exhausted"] = state.IsExhausted
	stats["circuit_open"] = state.CircuitOpen

	if len(state.Attempts) > 0 {
		lastAttempt := state.Attempts[len(state.Attempts)-1]
		stats["last_error"] = lastAttempt.Error
		stats["last_success"] = lastAttempt.Success
	}

	// Calculate success rate
	successCount := 0
	for _, attempt := range state.Attempts {
		if attempt.Success {
			successCount++
		}
	}
	if len(state.Attempts) > 0 {
		stats["success_rate"] = float64(successCount) / float64(len(state.Attempts))
	}

	return stats
}

// IsRetryableError checks if an error is generally retryable
func IsRetryableError(err error) bool {
	retrier := New(logger.New("retry"))
	policy := DefaultPolicy()
	return retrier.shouldRetry(err, 1, policy)
}

// WaitForRetry calculates and waits for the appropriate retry delay
func WaitForRetry(ctx context.Context, attempt int, policy *Policy) error {
	if attempt <= 1 {
		return nil
	}

	retrier := New(logger.New("retry"))
	delay := retrier.calculateDelay(policy, attempt-1)

	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PolicyBuilder helps build retry policies fluently
type PolicyBuilder struct {
	policy *Policy
}

// NewPolicyBuilder creates a new policy builder
func NewPolicyBuilder() *PolicyBuilder {
	return &PolicyBuilder{
		policy: DefaultPolicy(),
	}
}

// WithStrategy sets the retry strategy
func (b *PolicyBuilder) WithStrategy(strategy Strategy) *PolicyBuilder {
	b.policy.Strategy = strategy
	return b
}

// WithMaxAttempts sets the maximum number of attempts
func (b *PolicyBuilder) WithMaxAttempts(attempts int) *PolicyBuilder {
	b.policy.MaxAttempts = attempts
	return b
}

// WithBaseDelay sets the base delay
func (b *PolicyBuilder) WithBaseDelay(delay time.Duration) *PolicyBuilder {
	b.policy.BaseDelay = delay
	return b
}

// WithMaxDelay sets the maximum delay
func (b *PolicyBuilder) WithMaxDelay(delay time.Duration) *PolicyBuilder {
	b.policy.MaxDelay = delay
	return b
}

// WithJitter enables jitter with the specified percentage
func (b *PolicyBuilder) WithJitter(percent float64) *PolicyBuilder {
	b.policy.Jitter = true
	b.policy.JitterPercent = percent
	return b
}

// WithCircuitBreaker enables circuit breaker with the specified settings
func (b *PolicyBuilder) WithCircuitBreaker(threshold int, timeout time.Duration) *PolicyBuilder {
	b.policy.EnableCircuitBreaker = true
	b.policy.FailureThreshold = threshold
	b.policy.RecoveryTimeout = timeout
	return b
}

// WithRetryableErrors sets the list of retryable error types
func (b *PolicyBuilder) WithRetryableErrors(errorTypes ...ErrorType) *PolicyBuilder {
	b.policy.RetryableErrors = errorTypes
	return b
}

// WithCustomCondition sets a custom retry condition function
func (b *PolicyBuilder) WithCustomCondition(fn func(error, int) bool) *PolicyBuilder {
	b.policy.ShouldRetry = fn
	return b
}

// Build returns the constructed policy
func (b *PolicyBuilder) Build() *Policy {
	return b.policy
}
