package errors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
)

// ErrorCategory represents the category of error for better classification
type ErrorCategory string

const (
	CategoryValidation     ErrorCategory = "validation"
	CategoryAuthentication ErrorCategory = "authentication"
	CategoryAuthorization  ErrorCategory = "authorization"
	CategoryBusiness       ErrorCategory = "business"
	CategoryInternal       ErrorCategory = "internal"
	CategoryExternal       ErrorCategory = "external"
	CategoryNetwork        ErrorCategory = "network"
	CategoryDatabase       ErrorCategory = "database"
	CategorySecurity       ErrorCategory = "security"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ErrorCode represents predefined error codes for client applications
type ErrorCode string

const (
	CodeInvalidRequest       ErrorCode = "INVALID_REQUEST"
	CodeValidationFailed     ErrorCode = "VALIDATION_FAILED"
	CodeUnauthorized         ErrorCode = "UNAUTHORIZED"
	CodeForbidden            ErrorCode = "FORBIDDEN"
	CodeNotFound             ErrorCode = "NOT_FOUND"
	CodeConflict             ErrorCode = "CONFLICT"
	CodeRateLimited          ErrorCode = "RATE_LIMITED"
	CodeInternalError        ErrorCode = "INTERNAL_ERROR"
	CodeServiceUnavailable   ErrorCode = "SERVICE_UNAVAILABLE"
	CodeDatabaseError        ErrorCode = "DATABASE_ERROR"
	CodeSecurityThreat       ErrorCode = "SECURITY_THREAT"
	CodeExternalServiceError ErrorCode = "EXTERNAL_SERVICE_ERROR"
	CodeConfigurationError   ErrorCode = "CONFIGURATION_ERROR"
)

// EnhancedError represents a comprehensive error with additional context
type EnhancedError struct {
	Code         ErrorCode                `json:"code"`
	Message      string                   `json:"message"`
	UserMessage  string                   `json:"user_message,omitempty"`
	Category     ErrorCategory            `json:"category"`
	Severity     ErrorSeverity            `json:"severity"`
	Details      map[string]interface{}   `json:"details,omitempty"`
	Timestamp    time.Time                `json:"timestamp"`
	RequestID    string                   `json:"request_id,omitempty"`
	UserID       string                   `json:"user_id,omitempty"`
	Trace        []string                 `json:"trace,omitempty"`
	Cause        error                    `json:"-"`
	HTTPStatus   int                      `json:"-"`
	Retryable    bool                     `json:"retryable"`
	LogLevel     logger.LogLevel          `json:"-"`
}

// Error implements the error interface
func (e *EnhancedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *EnhancedError) Unwrap() error {
	return e.Cause
}

// WithUserMessage sets a user-friendly error message
func (e *EnhancedError) WithUserMessage(msg string) *EnhancedError {
	e.UserMessage = msg
	return e
}

// WithDetails adds additional details to the error
func (e *EnhancedError) WithDetails(details map[string]interface{}) *EnhancedError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithRequestID sets the request ID for tracing
func (e *EnhancedError) WithRequestID(requestID string) *EnhancedError {
	e.RequestID = requestID
	return e
}

// WithUserID sets the user ID for context
func (e *EnhancedError) WithUserID(userID string) *EnhancedError {
	e.UserID = userID
	return e
}

// WithCause sets the underlying cause of the error
func (e *EnhancedError) WithCause(cause error) *EnhancedError {
	e.Cause = cause
	return e
}

// AddTrace adds a trace entry to the error
func (e *EnhancedError) AddTrace(trace string) *EnhancedError {
	e.Trace = append(e.Trace, trace)
	return e
}

// IsRetryable returns whether the error is retryable
func (e *EnhancedError) IsRetryable() bool {
	return e.Retryable
}

// ToHTTPResponse converts the error to an HTTP response
func (e *EnhancedError) ToHTTPResponse() HTTPErrorResponse {
	return HTTPErrorResponse{
		Error: HTTPError{
			Code:        string(e.Code),
			Message:     e.GetSafeMessage(),
			Details:     e.GetSafeDetails(),
			Timestamp:   e.Timestamp,
			RequestID:   e.RequestID,
			Retryable:   e.Retryable,
		},
		HTTPStatus: e.HTTPStatus,
	}
}

// GetSafeMessage returns a message safe for client consumption
func (e *EnhancedError) GetSafeMessage() string {
	if e.UserMessage != "" {
		return e.UserMessage
	}
	
	// For security and internal errors, return generic messages
	if e.Category == CategorySecurity || e.Category == CategoryInternal {
		return "An internal error occurred. Please try again later."
	}
	
	return e.Message
}

// GetSafeDetails returns details safe for client consumption
func (e *EnhancedError) GetSafeDetails() map[string]interface{} {
	safeDetails := make(map[string]interface{})
	
	// Only include safe details for external consumption
	if e.Details != nil {
		for key, value := range e.Details {
			// Exclude sensitive information
			if !isSensitiveKey(key) {
				safeDetails[key] = value
			}
		}
	}
	
	return safeDetails
}

// HTTPError represents an error response for HTTP clients
type HTTPError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id,omitempty"`
	Retryable bool                   `json:"retryable"`
}

// HTTPErrorResponse combines HTTP error with status code
type HTTPErrorResponse struct {
	Error      HTTPError `json:"error"`
	HTTPStatus int       `json:"-"`
}

// ErrorBuilder provides a fluent interface for building enhanced errors
type ErrorBuilder struct {
	error *EnhancedError
}

// NewErrorBuilder creates a new error builder
func NewErrorBuilder(code ErrorCode, message string) *ErrorBuilder {
	return &ErrorBuilder{
		error: &EnhancedError{
			Code:      code,
			Message:   message,
			Timestamp: time.Now().UTC(),
			LogLevel:  logger.LogLevelError,
		},
	}
}

// Category sets the error category
func (eb *ErrorBuilder) Category(category ErrorCategory) *ErrorBuilder {
	eb.error.Category = category
	return eb
}

// Severity sets the error severity
func (eb *ErrorBuilder) Severity(severity ErrorSeverity) *ErrorBuilder {
	eb.error.Severity = severity
	
	// Adjust log level based on severity
	switch severity {
	case SeverityLow:
		eb.error.LogLevel = logger.LogLevelWarn
	case SeverityMedium:
		eb.error.LogLevel = logger.LogLevelError
	case SeverityHigh, SeverityCritical:
		eb.error.LogLevel = logger.LogLevelError
	}
	
	return eb
}

// UserMessage sets a user-friendly message
func (eb *ErrorBuilder) UserMessage(msg string) *ErrorBuilder {
	eb.error.UserMessage = msg
	return eb
}

// Details adds error details
func (eb *ErrorBuilder) Details(details map[string]interface{}) *ErrorBuilder {
	eb.error = eb.error.WithDetails(details)
	return eb
}

// HTTPStatus sets the HTTP status code
func (eb *ErrorBuilder) HTTPStatus(status int) *ErrorBuilder {
	eb.error.HTTPStatus = status
	return eb
}

// Retryable marks the error as retryable
func (eb *ErrorBuilder) Retryable(retryable bool) *ErrorBuilder {
	eb.error.Retryable = retryable
	return eb
}

// Cause sets the underlying cause
func (eb *ErrorBuilder) Cause(cause error) *ErrorBuilder {
	eb.error.Cause = cause
	return eb
}

// Build returns the constructed enhanced error
func (eb *ErrorBuilder) Build() *EnhancedError {
	// Add stack trace
	eb.addStackTrace()
	
	// Set default HTTP status if not set
	if eb.error.HTTPStatus == 0 {
		eb.error.HTTPStatus = eb.getDefaultHTTPStatus()
	}
	
	return eb.error
}

// addStackTrace adds stack trace information
func (eb *ErrorBuilder) addStackTrace() {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:]) // Skip runtime.Callers, addStackTrace, and Build
	
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if !strings.Contains(frame.File, "errors") { // Skip error handling code
			trace := fmt.Sprintf("%s:%d %s", frame.File, frame.Line, frame.Function)
			eb.error.Trace = append(eb.error.Trace, trace)
		}
		if !more {
			break
		}
		if len(eb.error.Trace) >= 5 { // Limit trace depth
			break
		}
	}
}

// getDefaultHTTPStatus returns default HTTP status based on error code
func (eb *ErrorBuilder) getDefaultHTTPStatus() int {
	switch eb.error.Code {
	case CodeInvalidRequest, CodeValidationFailed:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict:
		return http.StatusConflict
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case CodeInternalError, CodeDatabaseError, CodeConfigurationError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// Predefined error constructors

// NewValidationError creates a new validation error
func NewValidationError(message string) *EnhancedError {
	return NewErrorBuilder(CodeValidationFailed, message).
		Category(CategoryValidation).
		Severity(SeverityLow).
		HTTPStatus(http.StatusBadRequest).
		UserMessage("The provided input is invalid. Please check your data and try again.").
		Build()
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string) *EnhancedError {
	return NewErrorBuilder(CodeUnauthorized, message).
		Category(CategoryAuthentication).
		Severity(SeverityMedium).
		HTTPStatus(http.StatusUnauthorized).
		UserMessage("Authentication failed. Please check your credentials.").
		Build()
}

// NewAuthorizationError creates a new authorization error
func NewAuthorizationError(message string) *EnhancedError {
	return NewErrorBuilder(CodeForbidden, message).
		Category(CategoryAuthorization).
		Severity(SeverityMedium).
		HTTPStatus(http.StatusForbidden).
		UserMessage("You don't have permission to perform this action.").
		Build()
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(message string) *EnhancedError {
	return NewErrorBuilder(CodeNotFound, message).
		Category(CategoryBusiness).
		Severity(SeverityLow).
		HTTPStatus(http.StatusNotFound).
		UserMessage("The requested resource was not found.").
		Build()
}

// NewConflictError creates a new conflict error
func NewConflictError(message string) *EnhancedError {
	return NewErrorBuilder(CodeConflict, message).
		Category(CategoryBusiness).
		Severity(SeverityMedium).
		HTTPStatus(http.StatusConflict).
		UserMessage("The operation conflicts with existing data.").
		Build()
}

// NewInternalError creates a new internal error
func NewInternalError(message string) *EnhancedError {
	return NewErrorBuilder(CodeInternalError, message).
		Category(CategoryInternal).
		Severity(SeverityHigh).
		HTTPStatus(http.StatusInternalServerError).
		UserMessage("An internal error occurred. Please try again later.").
		Build()
}

// NewDatabaseError creates a new database error
func NewDatabaseError(message string, cause error) *EnhancedError {
	return NewErrorBuilder(CodeDatabaseError, message).
		Category(CategoryDatabase).
		Severity(SeverityHigh).
		HTTPStatus(http.StatusInternalServerError).
		UserMessage("A database error occurred. Please try again later.").
		Cause(cause).
		Retryable(true).
		Build()
}

// NewSecurityError creates a new security error
func NewSecurityError(message string) *EnhancedError {
	return NewErrorBuilder(CodeSecurityThreat, message).
		Category(CategorySecurity).
		Severity(SeverityCritical).
		HTTPStatus(http.StatusBadRequest).
		UserMessage("Security validation failed.").
		Build()
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(message string) *EnhancedError {
	return NewErrorBuilder(CodeRateLimited, message).
		Category(CategoryBusiness).
		Severity(SeverityMedium).
		HTTPStatus(http.StatusTooManyRequests).
		UserMessage("Too many requests. Please wait before trying again.").
		Retryable(true).
		Build()
}

// NewServiceUnavailableError creates a new service unavailable error
func NewServiceUnavailableError(message string) *EnhancedError {
	return NewErrorBuilder(CodeServiceUnavailable, message).
		Category(CategoryExternal).
		Severity(SeverityHigh).
		HTTPStatus(http.StatusServiceUnavailable).
		UserMessage("The service is temporarily unavailable. Please try again later.").
		Retryable(true).
		Build()
}

// ErrorHandler manages error handling, logging, and reporting
type ErrorHandler struct {
	logger            logger.Logger
	enableStackTrace  bool
	enableSentryIntegration bool
	maxDetailLength   int
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger logger.Logger) *ErrorHandler {
	return &ErrorHandler{
		logger:            logger,
		enableStackTrace:  true,
		maxDetailLength:   1000,
	}
}

// HandleError processes and logs an enhanced error
func (eh *ErrorHandler) HandleError(ctx context.Context, err *EnhancedError) {
	// Enrich error with context information
	if requestID := getRequestIDFromContext(ctx); requestID != "" {
		err.RequestID = requestID
	}
	if userID := getUserIDFromContext(ctx); userID != "" {
		err.UserID = userID
	}

	// Log the error with appropriate level
	eh.logError(err)

	// Report to external monitoring systems
	eh.reportError(ctx, err)

	// Trigger alerts for critical errors
	if err.Severity == SeverityCritical {
		eh.triggerAlert(err)
	}
}

// logError logs the error with structured information
func (eh *ErrorHandler) logError(err *EnhancedError) {
	logFields := map[string]interface{}{
		"error_code":     string(err.Code),
		"error_category": string(err.Category),
		"error_severity": string(err.Severity),
		"request_id":     err.RequestID,
		"user_id":        err.UserID,
		"retryable":      err.Retryable,
		"timestamp":      err.Timestamp,
	}

	// Add details if present
	if err.Details != nil {
		for key, value := range err.Details {
			if !isSensitiveKey(key) {
				logFields["detail_"+key] = value
			}
		}
	}

	// Add stack trace for internal errors
	if eh.enableStackTrace && (err.Category == CategoryInternal || err.Severity == SeverityCritical) {
		logFields["stack_trace"] = err.Trace
	}

	// Add cause if present
	if err.Cause != nil {
		logFields["cause"] = err.Cause.Error()
	}

	// Log with appropriate level
	switch err.LogLevel {
	case logger.LogLevelWarn:
		eh.logger.Warn(err.Message, logFields)
	case logger.LogLevelError:
		eh.logger.Error(err.Message, logFields)
	default:
		eh.logger.Error(err.Message, logFields)
	}
}

// reportError reports errors to external monitoring systems
func (eh *ErrorHandler) reportError(ctx context.Context, err *EnhancedError) {
	// TODO: Integrate with external error monitoring services like Sentry, Rollbar, etc.
	// This is a placeholder for external error reporting
	
	if eh.enableSentryIntegration {
		// Example Sentry integration would go here
		// sentry.CaptureException(err)
	}
}

// triggerAlert triggers alerts for critical errors
func (eh *ErrorHandler) triggerAlert(err *EnhancedError) {
	// TODO: Implement alerting mechanism (email, Slack, PagerDuty, etc.)
	eh.logger.Error("CRITICAL ERROR ALERT", map[string]interface{}{
		"error_code":    string(err.Code),
		"error_message": err.Message,
		"request_id":    err.RequestID,
		"user_id":       err.UserID,
		"timestamp":     err.Timestamp,
	})
}

// WriteErrorResponse writes an error response to HTTP response writer
func (eh *ErrorHandler) WriteErrorResponse(w http.ResponseWriter, err *EnhancedError) {
	httpResp := err.ToHTTPResponse()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpResp.HTTPStatus)
	
	if encodeErr := json.NewEncoder(w).Encode(httpResp.Error); encodeErr != nil {
		eh.logger.Error("Failed to encode error response", map[string]interface{}{
			"original_error": err.Message,
			"encode_error":   encodeErr.Error(),
		})
	}
}

// Utility functions

// isSensitiveKey checks if a key contains sensitive information
func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "token", "secret", "key", "auth", "credential",
		"private", "confidential", "sensitive", "ssn", "credit_card",
	}
	
	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	
	return false
}

// getRequestIDFromContext extracts request ID from context
func getRequestIDFromContext(ctx context.Context) string {
	if requestID := ctx.Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// getUserIDFromContext extracts user ID from context
func getUserIDFromContext(ctx context.Context) string {
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// ErrorMetrics provides metrics about error occurrences
type ErrorMetrics struct {
	TotalErrors        int64                    `json:"total_errors"`
	ErrorsByCode       map[ErrorCode]int64      `json:"errors_by_code"`
	ErrorsByCategory   map[ErrorCategory]int64  `json:"errors_by_category"`
	ErrorsBySeverity   map[ErrorSeverity]int64  `json:"errors_by_severity"`
	CriticalErrors     int64                    `json:"critical_errors"`
	RetryableErrors    int64                    `json:"retryable_errors"`
	LastUpdated        time.Time                `json:"last_updated"`
}

// ErrorMetricsCollector collects error metrics
type ErrorMetricsCollector struct {
	metrics ErrorMetrics
}

// NewErrorMetricsCollector creates a new error metrics collector
func NewErrorMetricsCollector() *ErrorMetricsCollector {
	return &ErrorMetricsCollector{
		metrics: ErrorMetrics{
			ErrorsByCode:     make(map[ErrorCode]int64),
			ErrorsByCategory: make(map[ErrorCategory]int64),
			ErrorsBySeverity: make(map[ErrorSeverity]int64),
			LastUpdated:      time.Now().UTC(),
		},
	}
}

// RecordError records an error occurrence in metrics
func (emc *ErrorMetricsCollector) RecordError(err *EnhancedError) {
	emc.metrics.TotalErrors++
	emc.metrics.ErrorsByCode[err.Code]++
	emc.metrics.ErrorsByCategory[err.Category]++
	emc.metrics.ErrorsBySeverity[err.Severity]++
	
	if err.Severity == SeverityCritical {
		emc.metrics.CriticalErrors++
	}
	
	if err.Retryable {
		emc.metrics.RetryableErrors++
	}
	
	emc.metrics.LastUpdated = time.Now().UTC()
}

// GetMetrics returns current error metrics
func (emc *ErrorMetricsCollector) GetMetrics() ErrorMetrics {
	return emc.metrics
}

// Reset resets all error metrics
func (emc *ErrorMetricsCollector) Reset() {
	emc.metrics = ErrorMetrics{
		ErrorsByCode:     make(map[ErrorCode]int64),
		ErrorsByCategory: make(map[ErrorCategory]int64),
		ErrorsBySeverity: make(map[ErrorSeverity]int64),
		LastUpdated:      time.Now().UTC(),
	}
}