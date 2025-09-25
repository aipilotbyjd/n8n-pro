package auth

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Organization represents a company/organization in n8n Pro
type Organization struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Slug        string                 `json:"slug" db:"slug"`
	Domain      *string                `json:"domain" db:"domain"`
	LogoURL     *string                `json:"logo_url" db:"logo_url"`
	Plan        PlanType               `json:"plan" db:"plan"`
	PlanLimits  PlanLimits             `json:"plan_limits" db:"plan_limits"`
	Settings    OrganizationSettings   `json:"settings" db:"settings"`
	Status      OrganizationStatus     `json:"status" db:"status"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

// PlanType represents different subscription plans
type PlanType string

const (
	PlanFree       PlanType = "free"
	PlanStarter    PlanType = "starter"
	PlanPro        PlanType = "pro"
	PlanEnterprise PlanType = "enterprise"
)

// OrganizationStatus represents organization status
type OrganizationStatus string

const (
	OrgStatusActive    OrganizationStatus = "active"
	OrgStatusSuspended OrganizationStatus = "suspended"
	OrgStatusCanceled  OrganizationStatus = "canceled"
	OrgStatusTrial     OrganizationStatus = "trial"
)

// PlanLimits defines what an organization can do based on their plan
type PlanLimits struct {
	MaxUsers              int  `json:"max_users"`
	MaxWorkflows          int  `json:"max_workflows"`
	MaxExecutionsPerMonth int  `json:"max_executions_per_month"`
	MaxExecutionTime      int  `json:"max_execution_time_seconds"`
	APICallsPerMinute     int  `json:"api_calls_per_minute"`
	DataRetentionDays     int  `json:"data_retention_days"`
	CustomConnections     bool `json:"custom_connections"`
	SSOEnabled            bool `json:"sso_enabled"`
	AuditLogsEnabled      bool `json:"audit_logs_enabled"`
	PrioritySupport       bool `json:"priority_support"`
	AdvancedSecurity      bool `json:"advanced_security"`
	WhiteLabeling         bool `json:"white_labeling"`
}

// OrganizationSettings contains organization-level settings
type OrganizationSettings struct {
	DefaultTimezone           string            `json:"default_timezone"`
	AllowRegistration         bool              `json:"allow_registration"`
	RequireEmailVerification  bool              `json:"require_email_verification"`
	EnforcePasswordPolicy     bool              `json:"enforce_password_policy"`
	PasswordPolicy            PasswordPolicy    `json:"password_policy"`
	SessionTimeoutMinutes     int               `json:"session_timeout_minutes"`
	EnableMFA                 bool              `json:"enable_mfa"`
	SSOConfig                 *SSOConfig        `json:"sso_config,omitempty"`
	WebhookSettings           WebhookSettings   `json:"webhook_settings"`
	SecuritySettings          SecuritySettings  `json:"security_settings"`
	NotificationSettings      map[string]bool   `json:"notification_settings"`
	CustomBranding            *CustomBranding   `json:"custom_branding,omitempty"`
	DataRegion                string            `json:"data_region"`
	ComplianceMode            string            `json:"compliance_mode"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigit   bool `json:"require_digit"`
	RequireSymbol  bool `json:"require_symbol"`
	MaxAge         int  `json:"max_age_days"`
	PreventReuse   int  `json:"prevent_reuse_count"`
}

// SSOConfig contains Single Sign-On configuration
type SSOConfig struct {
	Enabled    bool              `json:"enabled"`
	Provider   string            `json:"provider"`  // saml, oidc, oauth2
	EntityID   string            `json:"entity_id"`
	LoginURL   string            `json:"login_url"`
	LogoutURL  string            `json:"logout_url"`
	CertData   string            `json:"cert_data"`
	Attributes map[string]string `json:"attributes"`
	Settings   map[string]string `json:"settings"`
}

// WebhookSettings contains webhook-related settings
type WebhookSettings struct {
	MaxRetries        int    `json:"max_retries"`
	RetryDelay        int    `json:"retry_delay_seconds"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	AllowedHosts      []string `json:"allowed_hosts"`
	BlockedHosts      []string `json:"blocked_hosts"`
	EnableRateLimit   bool   `json:"enable_rate_limit"`
	RateLimitPerHour  int    `json:"rate_limit_per_hour"`
}

// SecuritySettings contains security-related configuration
type SecuritySettings struct {
	IPWhitelist            []string `json:"ip_whitelist"`
	IPBlacklist            []string `json:"ip_blacklist"`
	MaxLoginAttempts       int      `json:"max_login_attempts"`
	AccountLockoutMinutes  int      `json:"account_lockout_minutes"`
	EnableAuditLog         bool     `json:"enable_audit_log"`
	DataEncryptionEnabled  bool     `json:"data_encryption_enabled"`
	ApiKeyRotationDays     int      `json:"api_key_rotation_days"`
}

// CustomBranding for white-labeling
type CustomBranding struct {
	CompanyName  string `json:"company_name"`
	LogoURL      string `json:"logo_url"`
	FaviconURL   string `json:"favicon_url"`
	PrimaryColor string `json:"primary_color"`
	SecondaryColor string `json:"secondary_color"`
	CustomCSS    string `json:"custom_css"`
}

// Team represents a team within an organization
type Team struct {
	ID             string             `json:"id" db:"id"`
	OrganizationID string             `json:"organization_id" db:"organization_id"`
	Name           string             `json:"name" db:"name"`
	Description    *string            `json:"description" db:"description"`
	Settings       TeamSettings       `json:"settings" db:"settings"`
	CreatedAt      time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at" db:"updated_at"`
	DeletedAt      *time.Time         `json:"deleted_at,omitempty" db:"deleted_at"`
	
	// Computed fields
	MemberCount    int                `json:"member_count,omitempty" db:"-"`
	WorkflowCount  int                `json:"workflow_count,omitempty" db:"-"`
}

// TeamSettings contains team-specific settings
type TeamSettings struct {
	DefaultRole         RoleType `json:"default_role"`
	AllowMemberInvite   bool     `json:"allow_member_invite"`
	RequireApproval     bool     `json:"require_approval"`
	WorkflowSharing     string   `json:"workflow_sharing"` // "private", "team", "organization"
	CredentialSharing   string   `json:"credential_sharing"`
}

// Enhanced User model with organization support
type EnhancedUser struct {
	ID                         string                 `json:"id" db:"id"`
	OrganizationID             string                 `json:"organization_id" db:"organization_id"`
	Email                      string                 `json:"email" db:"email"`
	FirstName                  string                 `json:"first_name" db:"first_name"`
	LastName                   string                 `json:"last_name" db:"last_name"`
	FullName                   string                 `json:"full_name" db:"full_name"`
	PasswordHash               string                 `json:"-" db:"password_hash"`
	Status                     UserStatus             `json:"status" db:"status"`
	Role                       RoleType               `json:"role" db:"role"`
	Permissions               []Permission            `json:"permissions" db:"-"`
	Profile                   UserProfile             `json:"profile" db:"profile"`
	Settings                  UserSettings            `json:"settings" db:"settings"`
	CreatedAt                 time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt                 time.Time               `json:"updated_at" db:"updated_at"`
	DeletedAt                 *time.Time              `json:"deleted_at,omitempty" db:"deleted_at"`

	// Security fields
	EmailVerified              bool                   `json:"email_verified" db:"email_verified"`
	EmailVerificationToken     *string                `json:"-" db:"email_verification_token"`
	EmailVerificationExpiresAt *time.Time             `json:"-" db:"email_verification_expires_at"`
	PasswordResetToken         *string                `json:"-" db:"password_reset_token"`
	PasswordResetExpiresAt     *time.Time             `json:"-" db:"password_reset_expires_at"`
	MFAEnabled                 bool                   `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret                  *string                `json:"-" db:"mfa_secret"`
	MFABackupCodes             []string               `json:"-" db:"mfa_backup_codes"`
	APIKey                     *string                `json:"-" db:"api_key"`
	APIKeyCreatedAt            *time.Time             `json:"api_key_created_at,omitempty" db:"api_key_created_at"`

	// Activity tracking
	LastLoginAt                *time.Time             `json:"last_login_at" db:"last_login_at"`
	LastLoginIP                *string                `json:"last_login_ip" db:"last_login_ip"`
	LoginCount                 int                    `json:"login_count" db:"login_count"`
	FailedLoginAttempts        int                    `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil                *time.Time             `json:"locked_until,omitempty" db:"locked_until"`
	PasswordChangedAt          time.Time              `json:"password_changed_at" db:"password_changed_at"`

	// Computed fields (not stored)
	Teams                      []TeamMembership       `json:"teams,omitempty" db:"-"`
	Organization               *Organization          `json:"organization,omitempty" db:"-"`
}

// UserStatus represents user account status
type UserStatus string

const (
	UserStatusPending    UserStatus = "pending"    // Account created, email not verified
	UserStatusActive     UserStatus = "active"     // Account active and verified
	UserStatusSuspended  UserStatus = "suspended"  // Temporarily disabled by admin
	UserStatusInactive   UserStatus = "inactive"   // Disabled by user
	UserStatusDeleted    UserStatus = "deleted"    // Soft deleted
)

// RoleType represents different user roles
type RoleType string

const (
	RoleOwner        RoleType = "owner"        // Organization owner
	RoleAdmin        RoleType = "admin"        // Organization admin
	RoleMember       RoleType = "member"       // Regular team member
	RoleViewer       RoleType = "viewer"       // Read-only access
	RoleGuest        RoleType = "guest"        // Limited access
	RoleAPIOnly      RoleType = "api_only"     // API access only
)

// Permission represents a specific permission
type Permission string

// PermissionSet represents a set of permissions
type PermissionSet map[Permission]bool

// Has checks if the permission set has a specific permission
func (ps PermissionSet) Has(permission Permission) bool {
	return ps[permission] || ps[PermissionAdminAll]
}

// HasAny checks if the permission set has any of the given permissions
func (ps PermissionSet) HasAny(permissions ...Permission) bool {
	if ps[PermissionAdminAll] {
		return true
	}
	for _, perm := range permissions {
		if ps[perm] {
			return true
		}
	}
	return false
}

// HasAll checks if the permission set has all of the given permissions
func (ps PermissionSet) HasAll(permissions ...Permission) bool {
	if ps[PermissionAdminAll] {
		return true
	}
	for _, perm := range permissions {
		if !ps[perm] {
			return false
		}
	}
	return true
}

// Add adds permissions to the set
func (ps PermissionSet) Add(permissions ...Permission) {
	for _, perm := range permissions {
		ps[perm] = true
	}
}

// Remove removes permissions from the set
func (ps PermissionSet) Remove(permissions ...Permission) {
	for _, perm := range permissions {
		delete(ps, perm)
	}
}

// ToSlice converts permission set to slice of strings
func (ps PermissionSet) ToSlice() []string {
	var perms []string
	for perm := range ps {
		perms = append(perms, string(perm))
	}
	return perms
}

const (
	// User management
	PermissionUsersRead   Permission = "users:read"
	PermissionUsersWrite  Permission = "users:write"
	PermissionUsersDelete Permission = "users:delete"

	// Workflow permissions
	PermissionWorkflowsRead   Permission = "workflows:read"
	PermissionWorkflowsWrite  Permission = "workflows:write"
	PermissionWorkflowsDelete Permission = "workflows:delete"
	PermissionWorkflowsShare  Permission = "workflows:share"

	// Execution permissions
	PermissionExecutionsRead   Permission = "executions:read"
	PermissionExecutionsWrite  Permission = "executions:write"
	PermissionExecutionsDelete Permission = "executions:delete"

	// Credential permissions
	PermissionCredentialsRead   Permission = "credentials:read"
	PermissionCredentialsWrite  Permission = "credentials:write"
	PermissionCredentialsDelete Permission = "credentials:delete"
	PermissionCredentialsShare  Permission = "credentials:share"

	// Organization management
	PermissionOrganizationRead     Permission = "organization:read"
	PermissionOrganizationWrite    Permission = "organization:write"
	PermissionOrganizationSettings Permission = "organization:settings"
	PermissionOrganizationBilling  Permission = "organization:billing"

	// Team management
	PermissionTeamsRead   Permission = "teams:read"
	PermissionTeamsWrite  Permission = "teams:write"
	PermissionTeamsDelete Permission = "teams:delete"

	// Admin permissions
	PermissionAuditLogs    Permission = "audit_logs:read"
	PermissionSystemConfig Permission = "system:config"
	PermissionAPIKeys      Permission = "api_keys:manage"
	PermissionAdminAll     Permission = "admin:all"
	
	// Organization member management
	PermissionOrgManageMembers Permission = "organization:manage_members"
	PermissionOrgInviteUsers   Permission = "organization:invite_users"
	
	// Team member management
	PermissionTeamManageMembers Permission = "teams:manage_members"
	PermissionTeamInviteUsers   Permission = "teams:invite_users"
)

// UserProfile contains user profile information
type UserProfile struct {
	AvatarURL   *string `json:"avatar_url"`
	Bio         *string `json:"bio"`
	Location    *string `json:"location"`
	Website     *string `json:"website"`
	PhoneNumber *string `json:"phone_number"`
	JobTitle    *string `json:"job_title"`
	Department  *string `json:"department"`
}

// UserSettings contains user preferences
type UserSettings struct {
	Timezone              string            `json:"timezone"`
	Language              string            `json:"language"`
	Theme                 string            `json:"theme"`
	NotificationSettings  map[string]bool   `json:"notification_settings"`
	WorkflowDefaults      map[string]interface{} `json:"workflow_defaults"`
	KeyboardShortcuts     map[string]string `json:"keyboard_shortcuts"`
	PrivacySettings       map[string]bool   `json:"privacy_settings"`
}

// TeamMembership represents user's membership in a team
type TeamMembership struct {
	ID        string    `json:"id" db:"id"`
	TeamID    string    `json:"team_id" db:"team_id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Role      RoleType  `json:"role" db:"role"`
	JoinedAt  time.Time `json:"joined_at" db:"joined_at"`
	
	// Computed fields
	Team      *Team     `json:"team,omitempty" db:"-"`
	User      *EnhancedUser `json:"user,omitempty" db:"-"`
}

// Invitation represents user invitations to teams/organizations
type Invitation struct {
	ID             string         `json:"id" db:"id"`
	OrganizationID string         `json:"organization_id" db:"organization_id"`
	TeamID         *string        `json:"team_id" db:"team_id"`
	Email          string         `json:"email" db:"email"`
	Role           RoleType       `json:"role" db:"role"`
	InvitedBy      string         `json:"invited_by" db:"invited_by"`
	Token          string         `json:"-" db:"token"`
	Status         InviteStatus   `json:"status" db:"status"`
	ExpiresAt      time.Time      `json:"expires_at" db:"expires_at"`
	CreatedAt      time.Time      `json:"created_at" db:"created_at"`
	AcceptedAt     *time.Time     `json:"accepted_at,omitempty" db:"accepted_at"`
	
	// Computed fields
	Organization   *Organization  `json:"organization,omitempty" db:"-"`
	Team           *Team          `json:"team,omitempty" db:"-"`
	InvitedByUser  *EnhancedUser  `json:"invited_by_user,omitempty" db:"-"`
}

// InviteStatus represents invitation status
type InviteStatus string

const (
	InviteStatusPending  InviteStatus = "pending"
	InviteStatusAccepted InviteStatus = "accepted"
	InviteStatusDeclined InviteStatus = "declined"
	InviteStatusExpired  InviteStatus = "expired"
	InviteStatusRevoked  InviteStatus = "revoked"
)

// APIKey represents API keys for programmatic access
type APIKey struct {
	ID          string     `json:"id" db:"id"`
	UserID      string     `json:"user_id" db:"user_id"`
	Name        string     `json:"name" db:"name"`
	Key         string     `json:"-" db:"key_hash"`
	Permissions []Permission `json:"permissions" db:"permissions"`
	LastUsedAt  *time.Time `json:"last_used_at" db:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// AuditLog represents audit trail entries
type AuditLog struct {
	ID             string                 `json:"id" db:"id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	UserID         *string                `json:"user_id" db:"user_id"`
	Action         string                 `json:"action" db:"action"`
	Resource       string                 `json:"resource" db:"resource"`
	ResourceID     *string                `json:"resource_id" db:"resource_id"`
	Details        map[string]interface{} `json:"details" db:"details"`
	IPAddress      string                 `json:"ip_address" db:"ip_address"`
	UserAgent      string                 `json:"user_agent" db:"user_agent"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	
	// Computed fields
	User           *EnhancedUser          `json:"user,omitempty" db:"-"`
}

// Session represents user sessions for tracking active logins
type Session struct {
	ID            string     `json:"id" db:"id"`
	UserID        string     `json:"user_id" db:"user_id"`
	RefreshToken  string     `json:"-" db:"refresh_token_hash"`
	IPAddress     string     `json:"ip_address" db:"ip_address"`
	UserAgent     string     `json:"user_agent" db:"user_agent"`
	Location      *string    `json:"location" db:"location"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	LastSeenAt    time.Time  `json:"last_seen_at" db:"last_seen_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// GetRolePermissions returns default permissions for each role
func GetRolePermissions(role RoleType) PermissionSet {
	perms := make(PermissionSet)

	switch role {
	case RoleOwner:
		perms.Add(
			PermissionAdminAll, // Owner has all permissions
			PermissionUsersRead, PermissionUsersWrite, PermissionUsersDelete,
			PermissionWorkflowsRead, PermissionWorkflowsWrite, PermissionWorkflowsDelete, PermissionWorkflowsShare,
			PermissionExecutionsRead, PermissionExecutionsWrite, PermissionExecutionsDelete,
			PermissionCredentialsRead, PermissionCredentialsWrite, PermissionCredentialsDelete, PermissionCredentialsShare,
			PermissionOrganizationRead, PermissionOrganizationWrite, PermissionOrganizationSettings, PermissionOrganizationBilling,
			PermissionTeamsRead, PermissionTeamsWrite, PermissionTeamsDelete,
			PermissionAuditLogs, PermissionSystemConfig, PermissionAPIKeys,
		)
	case RoleAdmin:
		perms.Add(
			PermissionUsersRead, PermissionUsersWrite,
			PermissionWorkflowsRead, PermissionWorkflowsWrite, PermissionWorkflowsDelete, PermissionWorkflowsShare,
			PermissionExecutionsRead, PermissionExecutionsWrite, PermissionExecutionsDelete,
			PermissionCredentialsRead, PermissionCredentialsWrite, PermissionCredentialsDelete, PermissionCredentialsShare,
			PermissionOrganizationRead,
			PermissionTeamsRead, PermissionTeamsWrite,
			PermissionAuditLogs, PermissionAPIKeys,
		)
	case RoleMember:
		perms.Add(
			PermissionWorkflowsRead, PermissionWorkflowsWrite, PermissionWorkflowsShare,
			PermissionExecutionsRead, PermissionExecutionsWrite,
			PermissionCredentialsRead, PermissionCredentialsWrite, PermissionCredentialsShare,
		)
	case RoleViewer:
		perms.Add(
			PermissionWorkflowsRead,
			PermissionExecutionsRead,
			PermissionCredentialsRead,
		)
	case RoleGuest:
		perms.Add(
			PermissionWorkflowsRead,
		)
	case RoleAPIOnly:
		perms.Add(
			PermissionWorkflowsRead, PermissionWorkflowsWrite,
			PermissionExecutionsRead, PermissionExecutionsWrite,
		)
	}

	return perms
}

// GetPlanLimits returns default limits for each plan
func GetPlanLimits(plan PlanType) PlanLimits {
	switch plan {
	case PlanFree:
		return PlanLimits{
			MaxUsers:              2,
			MaxWorkflows:          5,
			MaxExecutionsPerMonth: 5000,
			MaxExecutionTime:      300,  // 5 minutes
			APICallsPerMinute:     100,
			DataRetentionDays:     7,
			CustomConnections:     false,
			SSOEnabled:            false,
			AuditLogsEnabled:      false,
			PrioritySupport:       false,
			AdvancedSecurity:      false,
			WhiteLabeling:         false,
		}
	case PlanStarter:
		return PlanLimits{
			MaxUsers:              10,
			MaxWorkflows:          50,
			MaxExecutionsPerMonth: 100000,
			MaxExecutionTime:      900,  // 15 minutes
			APICallsPerMinute:     500,
			DataRetentionDays:     30,
			CustomConnections:     true,
			SSOEnabled:            false,
			AuditLogsEnabled:      false,
			PrioritySupport:       false,
			AdvancedSecurity:      false,
			WhiteLabeling:         false,
		}
	case PlanPro:
		return PlanLimits{
			MaxUsers:              100,
			MaxWorkflows:          500,
			MaxExecutionsPerMonth: 1000000,
			MaxExecutionTime:      1800,  // 30 minutes
			APICallsPerMinute:     1000,
			DataRetentionDays:     90,
			CustomConnections:     true,
			SSOEnabled:            true,
			AuditLogsEnabled:      true,
			PrioritySupport:       true,
			AdvancedSecurity:      true,
			WhiteLabeling:         false,
		}
	case PlanEnterprise:
		return PlanLimits{
			MaxUsers:              -1,  // Unlimited
			MaxWorkflows:          -1,  // Unlimited
			MaxExecutionsPerMonth: -1,  // Unlimited
			MaxExecutionTime:      3600, // 1 hour
			APICallsPerMinute:     5000,
			DataRetentionDays:     365,
			CustomConnections:     true,
			SSOEnabled:            true,
			AuditLogsEnabled:      true,
			PrioritySupport:       true,
			AdvancedSecurity:      true,
			WhiteLabeling:         true,
		}
	default:
		return GetPlanLimits(PlanFree)
	}
}

// Database marshaling/unmarshaling for JSON fields

// Value implements the driver.Valuer interface for PlanLimits
func (pl PlanLimits) Value() (driver.Value, error) {
	return json.Marshal(pl)
}

// Scan implements the sql.Scanner interface for PlanLimits
func (pl *PlanLimits) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, pl)
	case string:
		return json.Unmarshal([]byte(v), pl)
	default:
		return fmt.Errorf("cannot scan %T into PlanLimits", value)
	}
}

// Value implements the driver.Valuer interface for OrganizationSettings
func (os OrganizationSettings) Value() (driver.Value, error) {
	return json.Marshal(os)
}

// Scan implements the sql.Scanner interface for OrganizationSettings
func (os *OrganizationSettings) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, os)
	case string:
		return json.Unmarshal([]byte(v), os)
	default:
		return fmt.Errorf("cannot scan %T into OrganizationSettings", value)
	}
}

// Value implements the driver.Valuer interface for TeamSettings
func (ts TeamSettings) Value() (driver.Value, error) {
	return json.Marshal(ts)
}

// Scan implements the sql.Scanner interface for TeamSettings
func (ts *TeamSettings) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, ts)
	case string:
		return json.Unmarshal([]byte(v), ts)
	default:
		return fmt.Errorf("cannot scan %T into TeamSettings", value)
	}
}

// Value implements the driver.Valuer interface for UserProfile
func (up UserProfile) Value() (driver.Value, error) {
	return json.Marshal(up)
}

// Scan implements the sql.Scanner interface for UserProfile
func (up *UserProfile) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, up)
	case string:
		return json.Unmarshal([]byte(v), up)
	default:
		return fmt.Errorf("cannot scan %T into UserProfile", value)
	}
}

// Value implements the driver.Valuer interface for UserSettings
func (us UserSettings) Value() (driver.Value, error) {
	return json.Marshal(us)
}

// Scan implements the sql.Scanner interface for UserSettings
func (us *UserSettings) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, us)
	case string:
		return json.Unmarshal([]byte(v), us)
	default:
		return fmt.Errorf("cannot scan %T into UserSettings", value)
	}
}