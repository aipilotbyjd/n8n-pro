package common

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Common constants used across the application
const (
	// Service names
	ServiceAPI       = "api"
	ServiceWorker    = "worker"
	ServiceScheduler = "scheduler"
	ServiceWebhook   = "webhook"
	ServiceAdmin     = "admin"

	// Default timeouts
	DefaultTimeout      = 30 * time.Second
	DefaultReadTimeout  = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
	DefaultIdleTimeout  = 120 * time.Second

	// Pagination defaults
	DefaultPageSize = 50
	MaxPageSize     = 1000

	// Common headers
	HeaderRequestID   = "X-Request-ID"
	HeaderUserID      = "X-User-ID"
	HeaderTeamID      = "X-Team-ID"
	HeaderContentType = "Content-Type"
	HeaderAccept      = "Accept"

	// Content types
	ContentTypeJSON = "application/json"
	ContentTypeXML  = "application/xml"
	ContentTypeText = "text/plain"
	ContentTypeForm = "application/x-www-form-urlencoded"

	// Common regex patterns
	EmailPattern   = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	UUIDPattern    = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	SlugPattern    = `^[a-z0-9-]+$`
	VersionPattern = `^v\d+\.\d+\.\d+$`

	// Database constraints
	MaxNameLength        = 255
	MaxDescriptionLength = 1000
	MaxTextFieldLength   = 65535

	// File size limits (in bytes)
	MaxFileSize       = 100 * 1024 * 1024 // 100MB
	MaxImageSize      = 10 * 1024 * 1024  // 10MB
	MaxDocumentSize   = 50 * 1024 * 1024  // 50MB
	MaxWorkflowSize   = 5 * 1024 * 1024   // 5MB
	MaxCredentialSize = 1024 * 1024       // 1MB

	// Rate limiting
	DefaultRateLimit = 1000
	BurstRateLimit   = 100

	// Cache TTL
	DefaultCacheTTL = 5 * time.Minute
	ShortCacheTTL   = 1 * time.Minute
	LongCacheTTL    = 1 * time.Hour
)

// Common interfaces used across the application

// Identifiable represents entities that have an ID
type Identifiable interface {
	GetID() string
}

// Timestamped represents entities with creation and update timestamps
type Timestamped interface {
	GetCreatedAt() time.Time
	GetUpdatedAt() time.Time
}

// Ownable represents entities that have an owner
type Ownable interface {
	GetOwnerID() string
	GetTeamID() string
}

// Soft deletes
type SoftDeletable interface {
	GetDeletedAt() *time.Time
	IsDeleted() bool
}

// Auditable combines multiple common interfaces
type Auditable interface {
	Identifiable
	Timestamped
	Ownable
}

// Validatable represents entities that can be validated
type Validatable interface {
	Validate() error
}

// Serializable represents entities that can be serialized
type Serializable interface {
	ToJSON() ([]byte, error)
	FromJSON([]byte) error
}

// Core domain types

// User represents a user in the system
type User struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Name     string   `json:"name,omitempty"`
	Role     string   `json:"role"`
	TeamID   string   `json:"team_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	IsActive bool     `json:"is_active"`
	Provider string   `json:"provider,omitempty"`
	Verified bool     `json:"verified,omitempty"`
	Picture  string   `json:"picture,omitempty"`
}

// Team represents a team in the system
type Team struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Plan string `json:"plan,omitempty"`
}

// Common request/response types

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page     int    `json:"page" query:"page" validate:"min=1"`
	PageSize int    `json:"page_size" query:"page_size" validate:"min=1,max=1000"`
	SortBy   string `json:"sort_by" query:"sort_by"`
	SortDir  string `json:"sort_dir" query:"sort_dir" validate:"oneof=asc desc"`
}

// GetOffset calculates the offset for database queries
func (p *PaginationRequest) GetOffset() int {
	if p.Page <= 1 {
		return 0
	}
	return (p.Page - 1) * p.GetPageSize()
}

// GetPageSize returns the page size with default
func (p *PaginationRequest) GetPageSize() int {
	if p.PageSize <= 0 {
		return DefaultPageSize
	}
	if p.PageSize > MaxPageSize {
		return MaxPageSize
	}
	return p.PageSize
}

// GetSortDirection returns normalized sort direction
func (p *PaginationRequest) GetSortDirection() string {
	if strings.ToLower(p.SortDir) == "asc" {
		return "ASC"
	}
	return "DESC"
}

// PaginationResponse represents paginated response metadata
type PaginationResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// NewPaginationResponse creates pagination response metadata
func NewPaginationResponse(page, pageSize int, total int64) *PaginationResponse {
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages < 1 {
		totalPages = 1
	}

	return &PaginationResponse{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Meta      interface{} `json:"meta,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// APIError represents API error details
type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details string                 `json:"details,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// NewSuccessResponse creates a successful API response
func NewSuccessResponse(data interface{}) *APIResponse {
	return &APIResponse{
		Success:   true,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// NewErrorResponse creates an error API response
func NewErrorResponse(code, message, details string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
	}
}

// NewEnhancedErrorResponse creates an enhanced error API response with context
func NewEnhancedErrorResponse(code, message, details string, context map[string]interface{}) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
			Context: context,
		},
		Timestamp: time.Now(),
	}
}

// Common utility functions

// GenerateID generates a new UUID string
func GenerateID() string {
	return uuid.New().String()
}

// IsValidUUID checks if a string is a valid UUID
func IsValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// IsValidEmail checks if a string is a valid email address
func IsValidEmail(email string) bool {
	if email == "" {
		return false
	}
	regex := regexp.MustCompile(EmailPattern)
	return regex.MatchString(email)
}

// IsValidSlug checks if a string is a valid slug
func IsValidSlug(slug string) bool {
	if slug == "" {
		return false
	}
	regex := regexp.MustCompile(SlugPattern)
	return regex.MatchString(slug)
}

// TruncateString truncates a string to maxLength
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	if maxLength <= 3 {
		return s[:maxLength]
	}
	return s[:maxLength-3] + "..."
}

// SanitizeString removes or replaces potentially harmful characters
func SanitizeString(s string) string {
	// Remove null bytes and control characters
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// ContainsString checks if a slice contains a string
func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveString removes all occurrences of a string from a slice
func RemoveString(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// UniqueStrings returns a slice with duplicate strings removed
func UniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !keys[s] {
			keys[s] = true
			result = append(result, s)
		}
	}
	return result
}

// CoalesceString returns the first non-empty string
func CoalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// StringPtr returns a pointer to a string
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to an int
func IntPtr(i int) *int {
	return &i
}

// BoolPtr returns a pointer to a bool
func BoolPtr(b bool) *bool {
	return &b
}

// TimePtr returns a pointer to a time.Time
func TimePtr(t time.Time) *time.Time {
	return &t
}

// DerefString dereferences a string pointer, returning empty string if nil
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DerefInt dereferences an int pointer, returning 0 if nil
func DerefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// DerefBool dereferences a bool pointer, returning false if nil
func DerefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// Context utilities

type contextKey string

const (
	ContextKeyRequestID contextKey = "request_id"
	ContextKeyUserID    contextKey = "user_id"
	ContextKeyTeamID    contextKey = "team_id"
	ContextKeyService   contextKey = "service"
)

// GetRequestIDFromContext extracts request ID from context
func GetRequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return id
	}
	return ""
}

// GetUserIDFromContext extracts user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ContextKeyUserID).(string); ok {
		return id
	}
	return ""
}

// GetTeamIDFromContext extracts team ID from context
func GetTeamIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ContextKeyTeamID).(string); ok {
		return id
	}
	return ""
}

// SetRequestIDInContext sets request ID in context
func SetRequestIDInContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// SetUserIDInContext sets user ID in context
func SetUserIDInContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ContextKeyUserID, userID)
}

// SetTeamIDInContext sets team ID in context
func SetTeamIDInContext(ctx context.Context, teamID string) context.Context {
	return context.WithValue(ctx, ContextKeyTeamID, teamID)
}

// FormatBytes formats byte size in human readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats duration in human readable format
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Clamp constrains a value between min and max
func Clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
