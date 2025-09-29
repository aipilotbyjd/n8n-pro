package constants

// Common constants used across the application
const (
	// Application
	AppName    = "n8n-pro"
	AppVersion = "1.0.0"

	// Authentication
	DefaultJWTExpiry         = "24h"
	DefaultRefreshTokenExpiry = "720h" // 30 days
	MinPasswordLength       = 12
	MaxFailedLoginAttempts  = 5
	AccountLockoutDuration  = "30m"

	// Teams
	DefaultTeamRole = "member"
	MaxTeamNameLength = 100

	// Workflows
	DefaultWorkflowStatus = "draft"
	MaxWorkflowNameLength = 255

	// Users
	DefaultUserRole    = "member"
	DefaultUserStatus  = "active"
	MaxUserNameLength  = 100

	// Pagination
	DefaultPageSize = 20
	MaxPageSize     = 100

	// API
	MaxRequestSize = 10 * 1024 * 1024 // 10MB

	// Cache
	DefaultCacheExpiry = "5m"
	MaxCacheSize      = 1000

	// Database
	MaxRetries = 3
)

// Environment variables
const (
	EnvDevelopment = "development"
	EnvStaging     = "staging"
	EnvProduction  = "production"
)

// HTTP headers
const (
	HeaderAPIKey = "X-API-Key"
	HeaderUserID = "X-User-ID"
	HeaderTeamID = "X-Team-ID"
)

// Error codes
const (
	ErrCodeInvalidInput       = "INVALID_INPUT"
	ErrCodeResourceNotFound   = "RESOURCE_NOT_FOUND"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeDuplicateResource  = "DUPLICATE_RESOURCE"
	ErrCodeValidationFailed   = "VALIDATION_FAILED"
	ErrCodeAuthenticationFailed = "AUTHENTICATION_FAILED"
)