// Package user contains the user domain logic
package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"n8n-pro/internal/domain/common/errors"
	"n8n-pro/internal/domain/common/events"
	"n8n-pro/internal/domain/common/value_objects"
)

// User represents a user aggregate in the system
type User struct {
	id             value_objects.ID
	organizationID value_objects.ID
	email          value_objects.Email
	firstName      string
	lastName       string
	role           value_objects.Role
	status         Status
	profile        Profile
	settings       Settings
	securityInfo   SecurityInfo
	activityInfo   ActivityInfo
	createdAt      time.Time
	updatedAt      time.Time
	domainEvents   []events.DomainEvent
}

// Profile contains user profile information
type Profile struct {
	AvatarURL   *string `json:"avatar_url"`
	Bio         *string `json:"bio"`
	Location    *string `json:"location"`
	Website     *string `json:"website"`
	PhoneNumber *string `json:"phone_number"`
	JobTitle    *string `json:"job_title"`
	Department  *string `json:"department"`
}

// Settings contains user preferences
type Settings struct {
	Timezone              string            `json:"timezone"`
	Language              string            `json:"language"`
	Theme                 string            `json:"theme"`
	NotificationSettings  map[string]bool   `json:"notification_settings"`
	WorkflowDefaults      map[string]interface{} `json:"workflow_defaults"`
	KeyboardShortcuts     map[string]string `json:"keyboard_shortcuts"`
	PrivacySettings       map[string]bool   `json:"privacy_settings"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	EmailVerified              bool
	EmailVerificationToken     *string
	EmailVerificationExpiresAt *time.Time
	PasswordResetToken         *string
	PasswordResetExpiresAt     *time.Time
	MFAEnabled                 bool
	MFASecret                  *string
	MFABackupCodes             []string
	APIKey                     *string
	APIKeyCreatedAt            *time.Time
}

// ActivityInfo tracks user activity
type ActivityInfo struct {
	LastLoginAt         *time.Time
	LastLoginIP         *string
	LoginCount          int64
	FailedLoginAttempts int
	LockedUntil         *time.Time
	PasswordChangedAt   time.Time
}

// UserRole represents user role (extends common Role with user-specific roles)
type UserRole string

const (
	UserRoleOwner    UserRole = "owner"
	UserRoleAdmin    UserRole = "admin"
	UserRoleMember   UserRole = "member"
	UserRoleViewer   UserRole = "viewer"
	UserRoleGuest    UserRole = "guest"
	UserRoleAPIOnly  UserRole = "api_only"
)

// Status represents user status
type Status string

const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusInactive  Status = "inactive"
	StatusDeleted   Status = "deleted"
)

// Repository defines the interface for user data access
type Repository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter ListFilter) ([]*User, int, error)
	GetByOrganization(ctx context.Context, orgID string) ([]*User, error)
}

// Service defines user business logic interface
type Service interface {
	CreateUser(ctx context.Context, cmd CreateUserCommand) (*User, error)
	GetUser(ctx context.Context, id string) (*User, error)
	UpdateUser(ctx context.Context, cmd UpdateUserCommand) (*User, error)
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, query ListUsersQuery) ([]*User, int, error)
	VerifyPassword(ctx context.Context, email, password string) (*User, error)
	ChangePassword(ctx context.Context, cmd ChangePasswordCommand) error
	EnableMFA(ctx context.Context, cmd EnableMFACommand) error
	DisableMFA(ctx context.Context, userID string) error
}

// Commands and Queries
type CreateUserCommand struct {
	OrganizationID string
	Email          string
	FirstName      string
	LastName       string
	Password       string
	Role           Role
	JobTitle       string
	Department     string
}

type UpdateUserCommand struct {
	ID        string
	FirstName *string
	LastName  *string
	Role      *Role
	Status    *Status
	Profile   *Profile
	Settings  *Settings
}

type ChangePasswordCommand struct {
	UserID      string
	OldPassword string
	NewPassword string
}

type EnableMFACommand struct {
	UserID      string
	Secret      string
	BackupCodes []string
}

type ListUsersQuery struct {
	OrganizationID string
	Status         *Status
	Role           *Role
	Search         string
	Limit          int
	Offset         int
	SortBy         string
	SortOrder      string
}

type ListFilter struct {
	OrganizationID string
	Status         *Status
	Role           *Role
	Search         string
	Limit          int
	Offset         int
	SortBy         string
	SortOrder      string
}

// Domain errors
type Error struct {
	Code    string
	Message string
	Details map[string]interface{}
}

func (e Error) Error() string {
	return e.Message
}

var (
	ErrUserNotFound       = Error{Code: "USER_NOT_FOUND", Message: "User not found"}
	ErrUserAlreadyExists  = Error{Code: "USER_ALREADY_EXISTS", Message: "User already exists"}
	ErrInvalidCredentials = Error{Code: "INVALID_CREDENTIALS", Message: "Invalid credentials"}
	ErrUserLocked         = Error{Code: "USER_LOCKED", Message: "User account is locked"}
	ErrInvalidInput       = Error{Code: "INVALID_INPUT", Message: "Invalid input"}
)

// NewUser creates a new user with domain validation
func NewUser(organizationID, email, firstName, lastName string, role value_objects.Role) (*User, error) {
	// Validate required fields
	if firstName == "" {
		return nil, errors.NewValidationError("first_name", "first name is required")
	}
	if lastName == "" {
		return nil, errors.NewValidationError("last_name", "last name is required")
	}

	// Create value objects
	id := value_objects.NewID()
	orgID, err := value_objects.NewIDFromString(organizationID)
	if err != nil {
		return nil, errors.NewValidationError("organization_id", "invalid organization ID")
	}

	userEmail, err := value_objects.NewEmail(email)
	if err != nil {
		return nil, errors.NewValidationError("email", err.Error())
	}

	now := time.Now().UTC()
	user := &User{
		id:             id,
		organizationID: orgID,
		email:          userEmail,
		firstName:      firstName,
		lastName:       lastName,
		role:           role,
		status:         StatusPending,
		profile:        Profile{},
		settings:       DefaultSettings(),
		securityInfo:   SecurityInfo{},
		activityInfo:   ActivityInfo{PasswordChangedAt: now},
		createdAt:      now,
		updatedAt:      now,
		domainEvents:   []events.DomainEvent{},
	}

	// Add domain event
	event := events.NewUserCreatedEvent(id.Value(), email, role.String(), &organizationID)
	user.AddDomainEvent(event)

	return user, nil
}

// Getters (public access to private fields)
func (u *User) ID() value_objects.ID          { return u.id }
func (u *User) OrganizationID() value_objects.ID { return u.organizationID }
func (u *User) Email() value_objects.Email    { return u.email }
func (u *User) FirstName() string             { return u.firstName }
func (u *User) LastName() string              { return u.lastName }
func (u *User) Role() value_objects.Role      { return u.role }
func (u *User) Status() Status                { return u.status }
func (u *User) Profile() Profile              { return u.profile }
func (u *User) Settings() Settings            { return u.settings }
func (u *User) SecurityInfo() SecurityInfo    { return u.securityInfo }
func (u *User) ActivityInfo() ActivityInfo    { return u.activityInfo }
func (u *User) CreatedAt() time.Time          { return u.createdAt }
func (u *User) UpdatedAt() time.Time          { return u.updatedAt }
func (u *User) DomainEvents() []events.DomainEvent { return u.domainEvents }

// Business methods
func (u *User) FullName() string {
	return u.firstName + " " + u.lastName
}

func (u *User) IsActive() bool {
	return u.status == StatusActive
}

func (u *User) IsLocked() bool {
	return u.activityInfo.LockedUntil != nil && u.activityInfo.LockedUntil.After(time.Now())
}

func (u *User) Activate() error {
	if u.status == StatusActive {
		return errors.NewBusinessRuleError("user_activation", "user is already active")
	}
	if u.status == StatusDeleted {
		return errors.NewBusinessRuleError("user_activation", "cannot activate deleted user")
	}

	u.status = StatusActive
	u.updatedAt = time.Now().UTC()
	return nil
}

func (u *User) Deactivate() error {
	if u.status == StatusDeleted {
		return errors.NewBusinessRuleError("user_deactivation", "cannot deactivate deleted user")
	}

	u.status = StatusInactive
	u.updatedAt = time.Now().UTC()
	return nil
}

func (u *User) UpdateProfile(profile Profile) {
	u.profile = profile
	u.updatedAt = time.Now().UTC()
}

func (u *User) UpdateSettings(settings Settings) {
	u.settings = settings
	u.updatedAt = time.Now().UTC()
}

func (u *User) ChangeEmail(newEmail string) error {
	email, err := value_objects.NewEmail(newEmail)
	if err != nil {
		return errors.NewValidationError("email", err.Error())
	}

	if u.email.Value() == email.Value() {
		return errors.NewBusinessRuleError("email_change", "new email is same as current email")
	}

	u.email = email
	u.securityInfo.EmailVerified = false
	u.updatedAt = time.Now().UTC()
	return nil
}

func (u *User) RecordLoginAttempt(successful bool, ip string) {
	now := time.Now().UTC()

	if successful {
		u.activityInfo.LastLoginAt = &now
		u.activityInfo.LastLoginIP = &ip
		u.activityInfo.LoginCount++
		u.activityInfo.FailedLoginAttempts = 0 // Reset failed attempts
		u.activityInfo.LockedUntil = nil       // Unlock if locked
	} else {
		u.activityInfo.FailedLoginAttempts++
		// Lock account after 5 failed attempts for 30 minutes
		if u.activityInfo.FailedLoginAttempts >= 5 {
			lockUntil := now.Add(30 * time.Minute)
			u.activityInfo.LockedUntil = &lockUntil
		}
	}

	u.updatedAt = now
}

func (u *User) EnableMFA(secret string, backupCodes []string) error {
	if u.securityInfo.MFAEnabled {
		return errors.NewBusinessRuleError("mfa_enable", "MFA is already enabled")
	}

	u.securityInfo.MFAEnabled = true
	u.securityInfo.MFASecret = &secret
	u.securityInfo.MFABackupCodes = backupCodes
	u.updatedAt = time.Now().UTC()
	return nil
}

func (u *User) DisableMFA() error {
	if !u.securityInfo.MFAEnabled {
		return errors.NewBusinessRuleError("mfa_disable", "MFA is not enabled")
	}

	u.securityInfo.MFAEnabled = false
	u.securityInfo.MFASecret = nil
	u.securityInfo.MFABackupCodes = nil
	u.updatedAt = time.Now().UTC()
	return nil
}

func (u *User) GenerateAPIKey() (string, error) {
	// Generate random API key
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	apiKey := base64.URLEncoding.EncodeToString(bytes)
	now := time.Now().UTC()

	u.securityInfo.APIKey = &apiKey
	u.securityInfo.APIKeyCreatedAt = &now
	u.updatedAt = now

	return apiKey, nil
}

func (u *User) CanPerformAction(action string) bool {
	if !u.IsActive() || u.IsLocked() {
		return false
	}

	// Use role-based permissions from value object
	switch action {
	case "read_public":
		return true // All active users can read public content
	case "read":
		return u.role.HasPermission(value_objects.RoleGuest)
	case "create_workflow", "execute_workflow":
		return u.role.HasPermission(value_objects.RoleMember)
	case "manage_team":
		return u.role.HasPermission(value_objects.RoleAdmin)
	case "billing", "delete_organization":
		return u.role.HasPermission(value_objects.RoleOwner)
	case "api_access":
		return u.securityInfo.APIKey != nil
	default:
		return false
	}
}

// Domain events management
func (u *User) AddDomainEvent(event events.DomainEvent) {
	u.domainEvents = append(u.domainEvents, event)
}

func (u *User) ClearDomainEvents() {
	u.domainEvents = []events.DomainEvent{}
}

// DefaultSettings returns default user settings
func DefaultSettings() Settings {
	return Settings{
		Timezone:              "UTC",
		Language:              "en",
		Theme:                 "light",
		NotificationSettings:  map[string]bool{
			"email_workflow_completed": true,
			"email_workflow_failed":    true,
			"email_weekly_report":      true,
		},
		WorkflowDefaults:      map[string]interface{}{},
		KeyboardShortcuts:     map[string]string{},
		PrivacySettings:       map[string]bool{
			"profile_visible": true,
			"activity_visible": false,
		},
	}
}
