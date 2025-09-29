package types

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// JSONB is a custom type for PostgreSQL JSONB columns
type JSONB map[string]interface{}

// Value implements driver.Valuer interface
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner interface
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into JSONB", value)
	}

	return json.Unmarshal(bytes, j)
}

// StringSlice is a custom type for PostgreSQL string arrays
type StringSlice []string

// Value implements driver.Valuer interface
func (s StringSlice) Value() (driver.Value, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return json.Marshal(s)
}

// Scan implements sql.Scanner interface
func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = StringSlice{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into StringSlice", value)
	}

	return json.Unmarshal(bytes, s)
}

// BaseModel provides common fields for all models
type BaseModel struct {
	ID        string      `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CreatedAt time.Time   `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time   `json:"updated_at" gorm:"not null"`
	DeletedAt *time.Time  `json:"deleted_at,omitempty" gorm:"index"`
	CreatedBy string      `json:"created_by" gorm:"type:uuid;not null"`
	UpdatedBy string      `json:"updated_by" gorm:"type:uuid;not null"`
}

// Pagination represents pagination parameters
type Pagination struct {
	Page  int `json:"page" validate:"min=1"`
	Limit int `json:"limit" validate:"min=1,max=100"`
}

// GetOffset calculates the offset for pagination
func (p *Pagination) GetOffset() int {
	if p.Page <= 1 {
		return 0
	}
	return (p.Page - 1) * p.Limit
}

// PaginatedResult represents a paginated result
type PaginatedResult[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
}

// GetTotalPages calculates the total number of pages
func (p *PaginatedResult[T]) GetTotalPages() int {
	if p.Limit == 0 {
		return 0
	}
	totalPages := int(p.Total) / p.Limit
	if int(p.Total)%p.Limit > 0 {
		totalPages++
	}
	return totalPages
}

// Filter represents common filter parameters
type Filter struct {
	Page      int               `json:"page" validate:"min=1"`
	Limit     int               `json:"limit" validate:"min=1,max=100"`
	Search    string            `json:"search,omitempty"`
	SortBy    string            `json:"sort_by,omitempty"`
	SortOrder string            `json:"sort_order,omitempty"` // asc, desc
	Filters   map[string]interface{} `json:"filters,omitempty"` // Additional filters
}

// ApplyFilters applies common query filters
func (f *Filter) ApplyFilters(query interface{}) interface{} {
	// This would be implemented based on the specific query engine used
	// For now, it's a placeholder
	return query
}

// ContextKey is used for context keys
type ContextKey string

const (
	// Context keys
	ContextUserID    ContextKey = "user_id"
	ContextUserEmail ContextKey = "user_email"
	ContextUserRoles ContextKey = "user_roles"
	ContextTeamID    ContextKey = "team_id"
	ContextOrgID     ContextKey = "organization_id"
	ContextTraceID   ContextKey = "trace_id"
)

// GetUserFromContext retrieves user ID from context
func GetUserFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value(ContextUserID).(string); ok {
		return userID
	}
	return ""
}

// GetTeamFromContext retrieves team ID from context
func GetTeamFromContext(ctx context.Context) string {
	if teamID, ok := ctx.Value(ContextTeamID).(string); ok {
		return teamID
	}
	return ""
}

// GetOrgFromContext retrieves organization ID from context
func GetOrgFromContext(ctx context.Context) string {
	if orgID, ok := ctx.Value(ContextOrgID).(string); ok {
		return orgID
	}
	return ""
}

// GetTraceIDFromContext retrieves trace ID from context
func GetTraceIDFromContext(ctx context.Context) string {
	if traceID, ok := ctx.Value(ContextTraceID).(string); ok {
		return traceID
	}
	return ""
}

// Event represents a system event for event sourcing
type Event struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Aggregate string      `json:"aggregate"`
	AggregateID string    `json:"aggregate_id"`
	Data      JSONB       `json:"data"`
	Version   int         `json:"version"`
	Timestamp time.Time   `json:"timestamp"`
	Metadata  JSONB       `json:"metadata"`
}

// Command represents a command to be executed
type Command struct {
	Type  string `json:"type"`
	Data  JSONB  `json:"data"`
	CorrelationID string `json:"correlation_id"`
	CausationID   string `json:"causation_id"`
}

// Query represents a query to be executed
type Query struct {
	Type string `json:"type"`
	Filters map[string]interface{} `json:"filters"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Result represents a query result
type Result struct {
	Data    interface{} `json:"data"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
	Success bool `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Status represents service status
type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
	StatusPending  Status = "pending"
	StatusSuspended Status = "suspended"
	StatusArchived Status = "archived"
)

// UserRole represents user roles
type UserRole string

const (
	UserRoleOwner   UserRole = "owner"
	UserRoleAdmin   UserRole = "admin"
	UserRoleMember  UserRole = "member"
	UserRoleViewer  UserRole = "viewer"
	UserRoleBilling UserRole = "billing"
)

// AuditEvent represents an audit event
type AuditEvent struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	ResourceID  string    `json:"resource_id"`
	UserID      string    `json:"user_id"`
	TeamID      string    `json:"team_id"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Timestamp   time.Time `json:"timestamp"`
	Details     JSONB     `json:"details"`
	Success     bool      `json:"success"`
	SessionID   string    `json:"session_id"`
}

// Cacheable interface for cacheable entities
type Cacheable interface {
	GetCacheKey() string
	GetCacheExpiry() time.Duration
}

// SearchFilter represents search criteria
type SearchFilter struct {
	Query    string            `json:"query"`
	Fields   []string          `json:"fields"`
	Exact    bool              `json:"exact"`
	Fuzzy    bool              `json:"fuzzy"`
	Boost    map[string]float64 `json:"boost"`
}

// SortOrder represents sort direction
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// Response represents API response structure
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
}

// NewSuccessResponse creates a success response
func NewSuccessResponse(data interface{}) Response {
	return Response{
		Success: true,
		Data:    data,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(message, error string) Response {
	return Response{
		Success: false,
		Message: message,
		Error:   error,
	}
}