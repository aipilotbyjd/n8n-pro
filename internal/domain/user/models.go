package user

import (
	"time"
)

// User represents a user entity
type User struct {
	ID             string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email          string                 `json:"email" gorm:"uniqueIndex;not null;size:255"`
	FirstName      string                 `json:"first_name" gorm:"not null;size:255"`
	LastName       string                 `json:"last_name" gorm:"not null;size:255"`
	PasswordHash   string                 `json:"-" gorm:"not null;size:255"`
	OrganizationID string                 `json:"organization_id" gorm:"type:uuid;not null;index"`
	TeamID         string                 `json:"team_id" gorm:"type:uuid;index"`
	Status         string                 `json:"status" gorm:"not null;default:'active'"`
	Role           string                 `json:"role" gorm:"not null;default:'member'"`
	Profile        map[string]interface{} `json:"profile" gorm:"type:jsonb;not null;default:'{}'"`
	Settings       map[string]interface{} `json:"settings" gorm:"type:jsonb;not null;default:'{}'"`

	// Security fields
	EmailVerified              bool       `json:"email_verified" gorm:"not null;default:false"`
	EmailVerificationToken     string     `json:"-" gorm:"size:255"`
	EmailVerificationExpiresAt *time.Time `json:"-" gorm:"index"`
	PasswordResetToken         string     `json:"-" gorm:"size:255"`
	PasswordResetExpiresAt     *time.Time `json:"-" gorm:"index"`
	MFAEnabled                 bool       `json:"mfa_enabled" gorm:"not null;default:false"`
	MFASecret                  string     `json:"-" gorm:"size:255"`
	APIKey                     string     `json:"-" gorm:"uniqueIndex;size:255"`
	APIKeyCreatedAt            *time.Time `json:"api_key_created_at,omitempty"`

	// Activity tracking
	LastLoginAt         *time.Time `json:"last_login_at" gorm:"index"`
	LastLoginIP         string     `json:"last_login_ip" gorm:"size:45"`
	LoginCount          int64      `json:"login_count" gorm:"not null;default:0"`
	FailedLoginAttempts int        `json:"failed_login_attempts" gorm:"not null;default:0"`
	LockedUntil         *time.Time `json:"locked_until,omitempty" gorm:"index"`
	PasswordChangedAt   time.Time  `json:"password_changed_at" gorm:"not null"`

	// Timestamps
	CreatedAt time.Time      `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"not null"`
	DeletedAt *time.Time     `json:"deleted_at,omitempty" gorm:"index"`
	CreatedBy string         `json:"created_by" gorm:"type:uuid;not null"`
	UpdatedBy string         `json:"updated_by" gorm:"type:uuid;not null"`
}

// FullName returns the user's full name
func (u *User) FullName() string {
	if u.FirstName != "" && u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	if u.FirstName != "" {
		return u.FirstName
	}
	if u.LastName != "" {
		return u.LastName
	}
	return u.Email
}

// Validate checks if the user entity is valid
func (u *User) Validate() error {
	// Add validation logic here
	if u.Email == "" {
		return ValidationError("email is required")
	}
	if u.FirstName == "" {
		return ValidationError("first name is required")
	}
	if u.LastName == "" {
		return ValidationError("last name is required")
	}
	if u.OrganizationID == "" {
		return ValidationError("organization ID is required")
	}
	return nil
}

// Activate activates the user account
func (u *User) Activate() {
	u.Status = "active"
	u.EmailVerified = true
	u.UpdatedAt = time.Now()
}

// Deactivate deactivates the user account
func (u *User) Deactivate() {
	u.Status = "inactive"
	u.UpdatedAt = time.Now()
}

// ValidationError represents a validation error
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}