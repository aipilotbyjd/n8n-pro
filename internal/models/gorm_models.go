// Package models contains GORM model definitions for n8n-pro
// Following patterns used by GitHub, GitLab, and other large-scale applications
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BaseModel provides common fields for all models
type BaseModel struct {
	ID        string         `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `gorm:"not null" json:"created_at"`
	UpdatedAt time.Time      `gorm:"not null" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// BeforeCreate hook to generate UUID
func (base *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if base.ID == "" {
		base.ID = uuid.New().String()
	}
	return nil
}

// AuditableModel extends BaseModel with audit fields
type AuditableModel struct {
	BaseModel
	CreatedBy string `gorm:"type:uuid;not null" json:"created_by"`
	UpdatedBy string `gorm:"type:uuid;not null" json:"updated_by"`
}

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
		return errors.New("type assertion to []byte failed")
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
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, s)
}

// Organization model
type Organization struct {
	BaseModel
	Name     string `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Slug     string `gorm:"uniqueIndex;not null;size:255" json:"slug" validate:"required,slug"`
	Domain   string `gorm:"size:255" json:"domain,omitempty"`
	LogoURL  string `gorm:"size:512" json:"logo_url,omitempty"`
	
	// Plan and limits
	Plan       string `gorm:"not null;default:'free'" json:"plan"`
	PlanLimits JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"plan_limits"`
	
	// Settings and configuration
	Settings JSONB `gorm:"type:jsonb;not null;default:'{}'" json:"settings"`
	
	// Status
	Status string `gorm:"not null;default:'active'" json:"status"`
	
	// Relationships
	Teams   []Team   `gorm:"foreignKey:OrganizationID" json:"teams,omitempty"`
	Users   []User   `gorm:"foreignKey:OrganizationID" json:"users,omitempty"`
}

// TableName specifies the table name
func (Organization) TableName() string {
	return "organizations"
}

// Team model
type Team struct {
	BaseModel
	OrganizationID string `gorm:"type:uuid;not null;index" json:"organization_id"`
	Name           string `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Description    string `gorm:"type:text" json:"description,omitempty"`
	Settings       JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"settings"`
	
	// Relationships
	Organization    Organization     `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	Members         []TeamMember     `gorm:"foreignKey:TeamID" json:"members,omitempty"`
	Workflows       []Workflow       `gorm:"foreignKey:TeamID" json:"workflows,omitempty"`
}

// TableName specifies the table name
func (Team) TableName() string {
	return "teams"
}

// User model
type User struct {
	BaseModel
	OrganizationID string `gorm:"type:uuid;not null;index" json:"organization_id"`
	Email          string `gorm:"uniqueIndex:idx_users_org_email,where:deleted_at IS NULL;not null;size:255" json:"email"`
	FirstName      string `gorm:"not null;size:255" json:"first_name"`
	LastName       string `gorm:"not null;size:255" json:"last_name"`
	PasswordHash   string `gorm:"not null;size:255" json:"-"`
	
	// User status and role
	Status string `gorm:"not null;default:'pending'" json:"status"`
	Role   string `gorm:"not null;default:'member'" json:"role"`
	
	// Profile and settings
	Profile  JSONB `gorm:"type:jsonb;not null;default:'{}'" json:"profile"`
	Settings JSONB `gorm:"type:jsonb;not null;default:'{}'" json:"settings"`
	
	// Security fields
	EmailVerified              bool       `gorm:"not null;default:false" json:"email_verified"`
	EmailVerificationToken     string     `gorm:"size:255" json:"-"`
	EmailVerificationExpiresAt *time.Time `json:"-"`
	PasswordResetToken         string     `gorm:"size:255" json:"-"`
	PasswordResetExpiresAt     *time.Time `json:"-"`
	MFAEnabled                 bool       `gorm:"not null;default:false" json:"mfa_enabled"`
	MFASecret                  string     `gorm:"size:255" json:"-"`
	MFABackupCodes             StringSlice `gorm:"type:jsonb" json:"-"`
	
	// API access
	APIKey          string     `gorm:"uniqueIndex;size:255" json:"-"`
	APIKeyCreatedAt *time.Time `json:"api_key_created_at,omitempty"`
	
	// Activity tracking
	LastLoginAt         *time.Time `json:"last_login_at"`
	LastLoginIP         string     `gorm:"size:45" json:"last_login_ip"`
	LoginCount          int64      `gorm:"not null;default:0" json:"login_count"`
	FailedLoginAttempts int        `gorm:"not null;default:0" json:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`
	PasswordChangedAt   time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"password_changed_at"`
	
	// Relationships
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	TeamMembers  []TeamMember `gorm:"foreignKey:UserID" json:"team_members,omitempty"`
	Workflows    []Workflow   `gorm:"foreignKey:OwnerID" json:"workflows,omitempty"`
}

// TableName specifies the table name
func (User) TableName() string {
	return "users"
}

// BeforeCreate hook for User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	if u.APIKey == "" {
		u.APIKey = "n8n_" + uuid.New().String()
		now := time.Now()
		u.APIKeyCreatedAt = &now
	}
	u.PasswordChangedAt = time.Now()
	return nil
}

// TeamMember model for many-to-many relationship
type TeamMember struct {
	ID     string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	TeamID string `gorm:"type:uuid;not null;index" json:"team_id"`
	UserID string `gorm:"type:uuid;not null;index" json:"user_id"`
	Role   string `gorm:"not null;default:'member'" json:"role"`
	
	JoinedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"joined_at"`
	
	// Relationships
	Team Team `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name
func (TeamMember) TableName() string {
	return "team_members"
}

// Workflow model
type Workflow struct {
	AuditableModel
	Name        string `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Description string `gorm:"type:text" json:"description"`
	Status      string `gorm:"not null;default:'draft'" json:"status"`
	TeamID      string `gorm:"type:uuid;not null;index" json:"team_id"`
	OwnerID     string `gorm:"type:uuid;not null;index" json:"owner_id"`
	Version     int    `gorm:"not null;default:1" json:"version"`
	IsTemplate  bool   `gorm:"not null;default:false" json:"is_template"`
	TemplateID  string `gorm:"type:uuid" json:"template_id,omitempty"`
	
	// Workflow definition stored as JSONB
	Definition JSONB `gorm:"type:jsonb;not null;default:'{}'" json:"definition"`
	
	// Configuration
	Config JSONB `gorm:"type:jsonb;not null;default:'{}'" json:"config"`
	
	// Tags and metadata
	Tags     StringSlice `gorm:"type:jsonb" json:"tags"`
	Metadata JSONB       `gorm:"type:jsonb;not null;default:'{}'" json:"metadata"`
	
	// Statistics
	ExecutionCount  int64      `gorm:"not null;default:0" json:"execution_count"`
	LastExecutedAt  *time.Time `json:"last_executed_at,omitempty"`
	LastExecutionID string     `gorm:"type:uuid" json:"last_execution_id,omitempty"`
	SuccessRate     float64    `gorm:"not null;default:0" json:"success_rate"`
	AverageRuntime  int64      `gorm:"not null;default:0" json:"average_runtime"` // milliseconds
	
	// Relationships
	Team       Team              `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	Owner      User              `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	Executions []WorkflowExecution `gorm:"foreignKey:WorkflowID" json:"executions,omitempty"`
}

// TableName specifies the table name
func (Workflow) TableName() string {
	return "workflows"
}

// WorkflowExecution model
type WorkflowExecution struct {
	BaseModel
	WorkflowID   string `gorm:"type:uuid;not null;index" json:"workflow_id"`
	WorkflowName string `gorm:"not null;size:255" json:"workflow_name"`
	TeamID       string `gorm:"type:uuid;not null;index" json:"team_id"`
	TriggerID    string `gorm:"type:uuid" json:"trigger_id,omitempty"`
	Status       string `gorm:"not null;default:'pending';index" json:"status"`
	Mode         string `gorm:"not null;default:'manual'" json:"mode"`
	
	// Execution context and data
	TriggerData  JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"trigger_data"`
	InputData    JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"input_data"`
	OutputData   JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"output_data"`
	ErrorMessage string `gorm:"type:text" json:"error_message,omitempty"`
	ErrorStack   string `gorm:"type:text" json:"error_stack,omitempty"`
	ErrorNodeID  string `gorm:"type:uuid" json:"error_node_id,omitempty"`
	
	// Timing
	StartTime time.Time  `gorm:"not null;index" json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  *int64     `json:"duration,omitempty"` // milliseconds
	
	// Execution details
	NodesExecuted int `gorm:"not null;default:0" json:"nodes_executed"`
	NodesTotal    int `gorm:"not null;default:0" json:"nodes_total"`
	
	// Retry information
	RetryCount        int    `gorm:"not null;default:0" json:"retry_count"`
	MaxRetries        int    `gorm:"not null;default:0" json:"max_retries"`
	ParentExecutionID string `gorm:"type:uuid" json:"parent_execution_id,omitempty"`
	
	// Resources
	MemoryUsage int64 `gorm:"not null;default:0" json:"memory_usage"` // bytes
	CPUTime     int64 `gorm:"not null;default:0" json:"cpu_time"`     // milliseconds
	
	// Context
	UserAgent string `gorm:"size:512" json:"user_agent"`
	IPAddress string `gorm:"size:45" json:"ip_address"`
	Metadata  JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"metadata"`
	
	// Relationships
	Workflow Workflow `gorm:"foreignKey:WorkflowID" json:"workflow,omitempty"`
	Team     Team     `gorm:"foreignKey:TeamID" json:"team,omitempty"`
}

// TableName specifies the table name
func (WorkflowExecution) TableName() string {
	return "workflow_executions"
}

// WorkflowVersion model for version control
type WorkflowVersion struct {
	BaseModel
	WorkflowID  string `gorm:"type:uuid;not null;index" json:"workflow_id"`
	Version     int    `gorm:"not null" json:"version"`
	Name        string `gorm:"not null;size:255" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	Definition  JSONB  `gorm:"type:jsonb;not null" json:"definition"`
	Hash        string `gorm:"not null;size:64" json:"hash"` // SHA256 of definition
	ChangeLog   string `gorm:"type:text" json:"change_log"`
	IsActive    bool   `gorm:"not null;default:false" json:"is_active"`
	CreatedBy   string `gorm:"type:uuid;not null" json:"created_by"`
	
	// Relationships
	Workflow Workflow `gorm:"foreignKey:WorkflowID" json:"workflow,omitempty"`
	Creator  User     `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`
}

// TableName specifies the table name
func (WorkflowVersion) TableName() string {
	return "workflow_versions"
}

// AuditLog model for comprehensive audit trail
type AuditLog struct {
	BaseModel
	OrganizationID string `gorm:"type:uuid;not null;index" json:"organization_id"`
	ActorType      string `gorm:"not null;size:50" json:"actor_type"` // user, system, api, service
	ActorID        string `gorm:"type:uuid" json:"actor_id,omitempty"`
	EventType      string `gorm:"not null;size:100;index" json:"event_type"`
	ResourceType   string `gorm:"not null;size:100;index" json:"resource_type"`
	ResourceID     string `gorm:"type:uuid;not null;index" json:"resource_id"`
	
	Details   JSONB  `gorm:"type:jsonb;not null;default:'{}'" json:"details"`
	IPAddress string `gorm:"size:45" json:"ip_address"`
	UserAgent string `gorm:"type:text" json:"user_agent"`
	Success   bool   `gorm:"not null;default:true" json:"success"`
	ErrorMessage string `gorm:"type:text" json:"error_message,omitempty"`
	
	SessionID string `gorm:"size:255" json:"session_id,omitempty"`
	RequestID string `gorm:"size:255" json:"request_id,omitempty"`
	Severity  string `gorm:"not null;default:'medium'" json:"severity"` // low, medium, high, critical
	
	// Relationships
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// TableName specifies the table name
func (AuditLog) TableName() string {
	return "audit_logs"
}

// Session model for tracking user sessions
type Session struct {
	BaseModel
	UserID          string     `gorm:"type:uuid;not null;index" json:"user_id"`
	RefreshTokenHash string    `gorm:"uniqueIndex;not null;size:255" json:"-"`
	IPAddress       string     `gorm:"not null;size:45;index" json:"ip_address"`
	UserAgent       string     `gorm:"not null;type:text" json:"user_agent"`
	Location        string     `gorm:"size:255" json:"location,omitempty"`
	IsActive        bool       `gorm:"not null;default:true;index" json:"is_active"`
	ExpiresAt       time.Time  `gorm:"not null;index" json:"expires_at"`
	LastSeenAt      time.Time  `gorm:"not null" json:"last_seen_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	
	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name
func (Session) TableName() string {
	return "sessions"
}

// Custom query scopes for common operations

// Active returns only non-soft-deleted records
func Active(db *gorm.DB) *gorm.DB {
	return db.Where("deleted_at IS NULL")
}

// ByOrganization filters by organization ID
func ByOrganization(orgID string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("organization_id = ?", orgID)
	}
}

// ByTeam filters by team ID
func ByTeam(teamID string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("team_id = ?", teamID)
	}
}

// ByStatus filters by status
func ByStatus(status string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("status = ?", status)
	}
}

// Recent orders by created_at DESC
func Recent(db *gorm.DB) *gorm.DB {
	return db.Order("created_at DESC")
}

// Paginate applies limit and offset
func Paginate(page, pageSize int) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if page <= 0 {
			page = 1
		}
		
		offset := (page - 1) * pageSize
		return db.Offset(offset).Limit(pageSize)
	}
}

// WithPreloads preloads common associations
func WithPreloads(associations ...string) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		for _, assoc := range associations {
			db = db.Preload(assoc)
		}
		return db
	}
}

// APIKey model for API key management
type APIKey struct {
	BaseModel
	UserID         string                 `gorm:"type:uuid;not null;index" json:"user_id"`
	OrganizationID string                 `gorm:"type:uuid;not null;index" json:"organization_id"`
	Name           string                 `gorm:"not null;size:255" json:"name"`
	Description    string                 `gorm:"type:text" json:"description"`
	KeyHash        string                 `gorm:"not null;size:255" json:"-"`
	KeyPrefix      string                 `gorm:"not null;size:20;index" json:"key_prefix"`
	Permissions    StringSlice            `gorm:"type:jsonb" json:"permissions"`
	Scopes         StringSlice            `gorm:"type:jsonb" json:"scopes"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time             `json:"last_used_at,omitempty"`
	UsageCount     int64                  `gorm:"not null;default:0" json:"usage_count"`
	IsActive       bool                   `gorm:"not null;default:true" json:"is_active"`
	Metadata       JSONB                  `gorm:"type:jsonb;not null;default:'{}'"`
}

// TableName specifies the table name
func (APIKey) TableName() string {
	return "api_keys"
}

// Migration helper to get all models
func GetAllModels() []interface{} {
	return []interface{}{
		&Organization{},
		&Team{},
		&User{},
		&TeamMember{},
		&Workflow{},
		&WorkflowExecution{},
		&WorkflowVersion{},
		&AuditLog{},
		&Session{},
		&APIKey{},
	}
}
