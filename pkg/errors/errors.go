package errors

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// ErrorType represents the type of error
type ErrorType string

const (
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeConflict       ErrorType = "conflict"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeExternal       ErrorType = "external"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeWorkflow       ErrorType = "workflow"
	ErrorTypeNode           ErrorType = "node"
	ErrorTypeExecution      ErrorType = "execution"
	ErrorTypeDatabase       ErrorType = "database"
	ErrorTypeNetwork        ErrorType = "network"
	ErrorTypeConfiguration  ErrorType = "configuration"
)

// ErrorCode represents specific error codes
type ErrorCode string

const (
	// Authentication errors
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	CodeTokenExpired       ErrorCode = "token_expired"
	CodeTokenInvalid       ErrorCode = "token_invalid"

	// Authorization errors
	CodeInsufficientPermissions ErrorCode = "insufficient_permissions"
	CodeResourceForbidden       ErrorCode = "resource_forbidden"

	// Validation errors
	CodeInvalidInput    ErrorCode = "invalid_input"
	CodeMissingField    ErrorCode = "missing_field"
	CodeInvalidFormat   ErrorCode = "invalid_format"
	CodeValueOutOfRange ErrorCode = "value_out_of_range"

	// Resource errors
	CodeResourceNotFound    ErrorCode = "resource_not_found"
	CodeResourceExists      ErrorCode = "resource_exists"
	CodeResourceLocked      ErrorCode = "resource_locked"
	CodeResourceUnavailable ErrorCode = "resource_unavailable"

	// Workflow errors
	CodeWorkflowInvalid   ErrorCode = "workflow_invalid"
	CodeWorkflowNotFound  ErrorCode = "workflow_not_found"
	CodeWorkflowExecution ErrorCode = "workflow_execution"
	CodeNodeExecution     ErrorCode = "node_execution"
	CodeNodeConfiguration ErrorCode = "node_configuration"
	CodeNodeConnection    ErrorCode = "node_connection"

	// System errors
	CodeDatabaseConnection ErrorCode = "database_connection"
	CodeDatabaseQuery      ErrorCode = "database_query"
	CodeExternalService    ErrorCode = "external_service"
	CodeTimeout            ErrorCode = "timeout"
	CodeRateLimit          ErrorCode = "rate_limit"
	CodeInternal           ErrorCode = "internal_error"
)

// AppError represents a structured application error
type AppError struct {
	Type            ErrorType              `json:"type"`
	Code            ErrorCode              `json:"code"`
	Message         string                 `json:"message"`
	Details         string                 `json:"details,omitempty"`
	Cause           error                  `json:"-"`
	Context         map[string]interface{} `json:"context,omitempty"`
	StackTrace      string                 `json:"stack_trace,omitempty"`
	Retryable       bool                   `json:"retryable"`
	retryableSet    bool                   // internal flag to track if Retryable was explicitly set
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s - %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithCause sets the underlying cause
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// WithDetails adds additional details
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// WithStackTrace captures the current stack trace
func (e *AppError) WithStackTrace() *AppError {
	e.StackTrace = captureStackTrace()
	return e
}

// New creates a new AppError
func New(errorType ErrorType, code ErrorCode, message string) *AppError {
	return &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		Context:    make(map[string]interface{}),
		StackTrace: captureStackTrace(),
		Retryable:  false,
	}
}

// Newf creates a new AppError with formatted message
func Newf(errorType ErrorType, code ErrorCode, format string, args ...interface{}) *AppError {
	return New(errorType, code, fmt.Sprintf(format, args...))
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errorType ErrorType, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}

	// If it's already an AppError, preserve its information
	if appErr, ok := err.(*AppError); ok {
		return &AppError{
			Type:       errorType,
			Code:       code,
			Message:    message,
			Cause:      appErr,
			Context:    make(map[string]interface{}),
			StackTrace: captureStackTrace(),
			Retryable:  appErr.Retryable,
		}
	}

	return &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		Cause:      err,
		Context:    make(map[string]interface{}),
		StackTrace: captureStackTrace(),
		Retryable:  false,
	}
}

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, errorType ErrorType, code ErrorCode, format string, args ...interface{}) *AppError {
	return Wrap(err, errorType, code, fmt.Sprintf(format, args...))
}

// Is checks if the error is of a specific type
func Is(err error, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// GetAppError extracts AppError from error chain
func GetAppError(err error) *AppError {
	if err == nil {
		return nil
	}

	var appErr *AppError
	if As(err, &appErr) {
		return appErr
	}

	return nil
}

// Common error constructors

// ValidationError creates a validation error
func ValidationError(code ErrorCode, message string) *AppError {
	return New(ErrorTypeValidation, code, message)
}

// AuthenticationError creates an authentication error
func AuthenticationError(code ErrorCode, message string) *AppError {
	return New(ErrorTypeAuthentication, code, message)
}

// AuthorizationError creates an authorization error
func AuthorizationError(code ErrorCode, message string) *AppError {
	return New(ErrorTypeAuthorization, code, message)
}

// NotFoundError creates a not found error
func NotFoundError(resource string) *AppError {
	return New(ErrorTypeNotFound, CodeResourceNotFound, fmt.Sprintf("%s not found", resource))
}

// NewValidationError creates a validation error with a simple message
func NewValidationError(message string) *AppError {
	return New(ErrorTypeValidation, CodeInvalidInput, message)
}

// NewNotFoundError creates a not found error with a simple message
func NewNotFoundError(message string) *AppError {
	return New(ErrorTypeNotFound, CodeResourceNotFound, message)
}

// NewUnauthorizedError creates an unauthorized error with a simple message
func NewUnauthorizedError(message string) *AppError {
	return New(ErrorTypeAuthentication, CodeInvalidCredentials, message)
}

// NewForbiddenError creates a forbidden error with a simple message
func NewForbiddenError(message string) *AppError {
	return New(ErrorTypeAuthorization, CodeInsufficientPermissions, message)
}

// NewExecutionError creates an execution error with a simple message
func NewExecutionError(message string) *AppError {
	return New(ErrorTypeExecution, CodeWorkflowExecution, message)
}

// NewHTTPError creates an HTTP error
type HTTPError struct {
	*AppError
	StatusCode int `json:"status_code"`
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(statusCode int, message string) *HTTPError {
	return &HTTPError{
		AppError:   New(ErrorTypeExternal, CodeExternalService, message),
		StatusCode: statusCode,
	}
}

// NetworkError creates a network error
type NetworkError struct {
	*AppError
}

// NewNetworkError creates a new network error
func NewNetworkError(message string) *NetworkError {
	return &NetworkError{
		AppError: New(ErrorTypeNetwork, CodeExternalService, message),
	}
}

// QuotaError creates a quota error
type QuotaError struct {
	*AppError
}

// NewQuotaError creates a new quota error
func NewQuotaError(message string) *QuotaError {
	return &QuotaError{
		AppError: New(ErrorTypeRateLimit, CodeRateLimit, message),
	}
}

// ConflictError creates a conflict error
func ConflictError(resource string) *AppError {
	return New(ErrorTypeConflict, CodeResourceExists, fmt.Sprintf("%s already exists", resource))
}

// InternalError creates an internal error
func InternalError(message string) *AppError {
	return New(ErrorTypeInternal, CodeInternal, message).WithStackTrace()
}

// ExternalError creates an external service error
func ExternalError(service string, err error) *AppError {
	return Wrap(err, ErrorTypeExternal, CodeExternalService, fmt.Sprintf("external service %s failed", service))
}

// TimeoutError creates a timeout error
func TimeoutError(operation string) *AppError {
	return New(ErrorTypeTimeout, CodeTimeout, fmt.Sprintf("operation %s timed out", operation))
}

// DatabaseError creates a database error
func DatabaseError(operation string, err error) *AppError {
	return Wrap(err, ErrorTypeDatabase, CodeDatabaseQuery, fmt.Sprintf("database operation %s failed", operation))
}

// WorkflowError creates a workflow error
func WorkflowError(workflowID string, message string) *AppError {
	return New(ErrorTypeWorkflow, CodeWorkflowExecution, message).
		WithContext("workflow_id", workflowID)
}

// NodeError creates a node execution error
func NodeError(nodeID, nodeType string, message string) *AppError {
	return New(ErrorTypeNode, CodeNodeExecution, message).
		WithContext("node_id", nodeID).
		WithContext("node_type", nodeType)
}

// Predefined common errors
var (
	ErrInvalidInput       = ValidationError(CodeInvalidInput, "invalid input provided")
	ErrMissingField       = ValidationError(CodeMissingField, "required field is missing")
	ErrUnauthorized       = AuthenticationError(CodeInvalidCredentials, "authentication required")
	ErrForbidden          = AuthorizationError(CodeInsufficientPermissions, "insufficient permissions")
	ErrInternalServer     = InternalError("internal server error")
	ErrServiceUnavailable = New(ErrorTypeExternal, CodeResourceUnavailable, "service temporarily unavailable")
	ErrTooManyRequests    = New(ErrorTypeRateLimit, CodeRateLimit, "too many requests")
)

// HTTP status code mapping
func (e *AppError) HTTPStatus() int {
	switch e.Type {
	case ErrorTypeValidation:
		return 400
	case ErrorTypeAuthentication:
		return 401
	case ErrorTypeAuthorization:
		return 403
	case ErrorTypeNotFound:
		return 404
	case ErrorTypeConflict:
		return 409
	case ErrorTypeTimeout:
		return 408
	case ErrorTypeRateLimit:
		return 429
	case ErrorTypeExternal, ErrorTypeInternal:
		return 500
	default:
		return 500
	}
}

// IsRetryable checks if the error is retryable
func (e *AppError) IsRetryable() bool {
	// If retryable was explicitly set, use that value
	if e.retryableSet {
		return e.Retryable
	}

	// Some errors are inherently retryable
	switch e.Type {
	case ErrorTypeTimeout, ErrorTypeNetwork, ErrorTypeExternal:
		return true
	case ErrorTypeRateLimit:
		return true
	default:
		return false
	}
}

// SetRetryable marks the error as retryable
func (e *AppError) SetRetryable(retryable bool) *AppError {
	e.Retryable = retryable
	e.retryableSet = true
	return e
}

// captureStackTrace captures the current stack trace
func captureStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var builder strings.Builder
	for {
		frame, more := frames.Next()
		builder.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
		if !more {
			break
		}
	}

	return builder.String()
}

// ErrorList represents a collection of errors
type ErrorList struct {
	Errors []*AppError `json:"errors"`
}

// Error implements the error interface
func (el *ErrorList) Error() string {
	if len(el.Errors) == 0 {
		return "no errors"
	}

	if len(el.Errors) == 1 {
		return el.Errors[0].Error()
	}

	var messages []string
	for _, err := range el.Errors {
		messages = append(messages, err.Error())
	}

	return fmt.Sprintf("multiple errors: [%s]", strings.Join(messages, "; "))
}

// Add adds an error to the list
func (el *ErrorList) Add(err *AppError) {
	if err != nil {
		el.Errors = append(el.Errors, err)
	}
}

// HasErrors returns true if there are any errors
func (el *ErrorList) HasErrors() bool {
	return len(el.Errors) > 0
}

// NewErrorList creates a new error list
func NewErrorList() *ErrorList {
	return &ErrorList{
		Errors: make([]*AppError, 0),
	}
}

// Recovery middleware helper
type RecoveryHandler func(err interface{}) *AppError

// Recover recovers from panics and converts them to AppErrors
func Recover(handler RecoveryHandler) {
	if r := recover(); r != nil {
		var err *AppError
		if handler != nil {
			err = handler(r)
		} else {
			err = InternalError(fmt.Sprintf("panic recovered: %v", r))
		}

		// Log the error (would typically integrate with your logger here)
		_ = err // Placeholder for logging
	}
}

// Chain represents an error chain for workflow execution
type Chain struct {
	errors []*AppError
}

// NewChain creates a new error chain
func NewChain() *Chain {
	return &Chain{
		errors: make([]*AppError, 0),
	}
}

// Add adds an error to the chain
func (c *Chain) Add(err *AppError) {
	if err != nil {
		c.errors = append(c.errors, err)
	}
}

// HasErrors returns true if there are errors in the chain
func (c *Chain) HasErrors() bool {
	return len(c.errors) > 0
}

// Errors returns all errors in the chain
func (c *Chain) Errors() []*AppError {
	return c.errors
}

// First returns the first error in the chain
func (c *Chain) First() *AppError {
	if len(c.errors) > 0 {
		return c.errors[0]
	}
	return nil
}

// Last returns the last error in the chain
func (c *Chain) Last() *AppError {
	if len(c.errors) > 0 {
		return c.errors[len(c.errors)-1]
	}
	return nil
}
