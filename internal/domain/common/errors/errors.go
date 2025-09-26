package errors

import (
	"errors"
	"fmt"
)

// Common domain error types
var (
	ErrNotFound           = errors.New("entity not found")
	ErrAlreadyExists      = errors.New("entity already exists")
	ErrInvalidInput       = errors.New("invalid input")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrConflict           = errors.New("conflict")
	ErrInternalError      = errors.New("internal error")
	ErrValidationFailed   = errors.New("validation failed")
	ErrBusinessRuleViolated = errors.New("business rule violated")
)

// DomainError represents a domain-specific error
type DomainError struct {
	Type    string                 `json:"type"`
	Message string                 `json:"message"`
	Code    string                 `json:"code,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
	Cause   error                  `json:"-"`
}

func (e *DomainError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *DomainError) Unwrap() error {
	return e.Cause
}

// Error constructors
func NewNotFoundError(entity string, id interface{}) *DomainError {
	return &DomainError{
		Type:    "NOT_FOUND",
		Message: fmt.Sprintf("%s with id '%v' not found", entity, id),
		Code:    "ENTITY_NOT_FOUND",
		Context: map[string]interface{}{
			"entity": entity,
			"id":     id,
		},
		Cause: ErrNotFound,
	}
}

func NewValidationError(field string, message string) *DomainError {
	return &DomainError{
		Type:    "VALIDATION_ERROR",
		Message: fmt.Sprintf("validation failed for field '%s': %s", field, message),
		Code:    "VALIDATION_FAILED",
		Context: map[string]interface{}{
			"field": field,
		},
		Cause: ErrValidationFailed,
	}
}

func NewBusinessRuleError(rule string, message string) *DomainError {
	return &DomainError{
		Type:    "BUSINESS_RULE_VIOLATION",
		Message: fmt.Sprintf("business rule '%s' violated: %s", rule, message),
		Code:    "BUSINESS_RULE_VIOLATED",
		Context: map[string]interface{}{
			"rule": rule,
		},
		Cause: ErrBusinessRuleViolated,
	}
}

func NewConflictError(entity string, field string, value interface{}) *DomainError {
	return &DomainError{
		Type:    "CONFLICT",
		Message: fmt.Sprintf("%s with %s '%v' already exists", entity, field, value),
		Code:    "ENTITY_CONFLICT",
		Context: map[string]interface{}{
			"entity": entity,
			"field":  field,
			"value":  value,
		},
		Cause: ErrConflict,
	}
}

func NewUnauthorizedError(message string) *DomainError {
	return &DomainError{
		Type:    "UNAUTHORIZED",
		Message: message,
		Code:    "UNAUTHORIZED_ACCESS",
		Cause:   ErrUnauthorized,
	}
}

func NewForbiddenError(resource string, action string) *DomainError {
	return &DomainError{
		Type:    "FORBIDDEN",
		Message: fmt.Sprintf("access to %s for action '%s' is forbidden", resource, action),
		Code:    "ACCESS_FORBIDDEN",
		Context: map[string]interface{}{
			"resource": resource,
			"action":   action,
		},
		Cause: ErrForbidden,
	}
}