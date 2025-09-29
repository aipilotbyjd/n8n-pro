package errors

import (
	"fmt"
	"net/http"
)

// ErrorType categorizes the type of error
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeDatabase       ErrorType = "database"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeConflict       ErrorType = "conflict"
)

// ErrorCode provides specific error codes
type ErrorCode string

const (
	CodeInvalidInput          ErrorCode = "INVALID_INPUT"
	CodeInvalidCredentials    ErrorCode = "INVALID_CREDENTIALS"
	CodeInsufficientScope     ErrorCode = "INSUFFICIENT_SCOPE"
	CodeResourceNotFound      ErrorCode = "RESOURCE_NOT_FOUND"
	CodeDatabaseQuery         ErrorCode = "DATABASE_QUERY_ERROR"
	CodeDatabaseConnection    ErrorCode = "DATABASE_CONNECTION_ERROR"
	CodeTokenExpired          ErrorCode = "TOKEN_EXPIRED"
	CodeTokenInvalid          ErrorCode = "TOKEN_INVALID"
	CodeTooManyAttempts       ErrorCode = "TOO_MANY_ATTEMPTS"
	CodeAccountLocked         ErrorCode = "ACCOUNT_LOCKED"
	CodeAccountDisabled       ErrorCode = "ACCOUNT_DISABLED"
	CodeAccountNotVerified    ErrorCode = "ACCOUNT_NOT_VERIFIED"
	CodeInternal              ErrorCode = "INTERNAL_ERROR"
	CodeDuplicateResource     ErrorCode = "DUPLICATE_RESOURCE"
)

// Error represents a structured error
type Error struct {
	Type       ErrorType `json:"type"`
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	HTTPStatus int       `json:"-"`
	Cause      error     `json:"-"`
}

// Error returns the error message
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Cause
}

// New creates a new error
func New(errorType ErrorType, code ErrorCode, message string) *Error {
	return &Error{
		Type:       errorType,
		Code:       code,
		Message:    message,
		HTTPStatus: getHTTPStatus(errorType),
	}
}

// Wrap wraps an error with additional context
func Wrap(err error, errorType ErrorType, code ErrorCode, message string) *Error {
	return &Error{
		Type:       errorType,
		Code:       code,
		Message:    message,
		Cause:      err,
		HTTPStatus: getHTTPStatus(errorType),
	}
}

// NewValidationError creates a validation error
func NewValidationError(message string) *Error {
	return New(ErrorTypeValidation, CodeInvalidInput, message)
}

// NewValidationErrorWithDetails creates a validation error with details
func NewValidationErrorWithDetails(message string, details map[string]interface{}) *Error {
	err := New(ErrorTypeValidation, CodeInvalidInput, message)
	err.Details = details
	return err
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(message string) *Error {
	return New(ErrorTypeAuthentication, CodeInvalidCredentials, message)
}

// NewAuthorizationError creates an authorization error
func NewAuthorizationError(message string) *Error {
	return New(ErrorTypeAuthorization, CodeInsufficientScope, message)
}

// NewNotFoundError creates a not found error
func NewNotFoundError(message string) *Error {
	return New(ErrorTypeNotFound, CodeResourceNotFound, message)
}

// NewDatabaseError creates a database error
func NewDatabaseError(message string) *Error {
	return New(ErrorTypeDatabase, CodeDatabaseQuery, message)
}

// NewInternalError creates an internal error
func NewInternalError(message string) *Error {
	return New(ErrorTypeInternal, CodeInternal, message)
}

// NewRateLimitError creates a rate limit error
func NewRateLimitError(message string) *Error {
	return New(ErrorTypeRateLimit, CodeTooManyAttempts, message)
}

// NewConflictError creates a conflict error
func NewConflictError(message string) *Error {
	return New(ErrorTypeConflict, CodeDuplicateResource, message)
}

// NewEmailExistsError creates a specific error when email already exists
func NewEmailExistsError(email string) *Error {
	err := New(ErrorTypeConflict, CodeDuplicateResource, "email already exists")
	err.Details = map[string]interface{}{
		"email": email,
	}
	return err
}

// IsValidationError checks if error is validation error
func IsValidationError(err error) bool {
	return isErrorOfType(err, ErrorTypeValidation)
}

// IsAuthenticationError checks if error is authentication error
func IsAuthenticationError(err error) bool {
	return isErrorOfType(err, ErrorTypeAuthentication)
}

// IsAuthorizationError checks if error is authorization error
func IsAuthorizationError(err error) bool {
	return isErrorOfType(err, ErrorTypeAuthorization)
}

// IsNotFoundError checks if error is not found error
func IsNotFoundError(err error) bool {
	return isErrorOfType(err, ErrorTypeNotFound)
}

// IsDatabaseError checks if error is database error
func IsDatabaseError(err error) bool {
	return isErrorOfType(err, ErrorTypeDatabase)
}

// IsInternalError checks if error is internal error
func IsInternalError(err error) bool {
	return isErrorOfType(err, ErrorTypeInternal)
}

// IsRateLimitError checks if error is rate limit error
func IsRateLimitError(err error) bool {
	return isErrorOfType(err, ErrorTypeRateLimit)
}

// IsConflictError checks if error is conflict error
func IsConflictError(err error) bool {
	return isErrorOfType(err, ErrorTypeConflict)
}

// isErrorOfType checks if error is of a specific type
func isErrorOfType(err error, errorType ErrorType) bool {
	if err == nil {
		return false
	}

	if appErr, ok := err.(*Error); ok {
		return appErr.Type == errorType
	}

	return false
}

// getHTTPStatus returns the HTTP status code for an error type
func getHTTPStatus(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeAuthentication:
		return http.StatusUnauthorized
	case ErrorTypeAuthorization:
		return http.StatusForbidden
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeRateLimit:
		return http.StatusTooManyRequests
	case ErrorTypeDatabase, ErrorTypeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// GetHTTPStatus returns the HTTP status code for an error
func GetHTTPStatus(err error) int {
	if appErr, ok := err.(*Error); ok {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

// ConvertToAPIError converts standard Go errors to API errors
func ConvertToAPIError(err error) *Error {
	if apiErr, ok := err.(*Error); ok {
		return apiErr
	}
	
	// Convert standard errors to internal error
	return NewInternalError(err.Error())
}