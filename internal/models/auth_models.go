package models

import (
	"time"

	"gorm.io/gorm"
)

// PasswordHistory stores historical passwords for a user
type PasswordHistory struct {
	ID           string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID       string    `gorm:"type:uuid;not null;index" json:"user_id"`
	PasswordHash string    `gorm:"type:varchar(255);not null" json:"-"`
	CreatedAt    time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// Session represents an active user session with enhanced security tracking
type AuthSession struct {
	ID               string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID           string    `gorm:"type:uuid;not null;index" json:"user_id"`
	RefreshTokenHash string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"-"`
	AccessTokenHash  string    `gorm:"type:varchar(255);index" json:"-"`

	// Device information
	DeviceID        string `gorm:"type:varchar(255);index" json:"device_id"`
	DeviceName      string `gorm:"type:varchar(255)" json:"device_name"`
	DeviceType      string `gorm:"type:varchar(50)" json:"device_type"` // mobile, desktop, tablet
	Browser         string `gorm:"type:varchar(100)" json:"browser"`
	BrowserVersion  string `gorm:"type:varchar(50)" json:"browser_version"`
	OS              string `gorm:"type:varchar(100)" json:"os"`
	OSVersion       string `gorm:"type:varchar(50)" json:"os_version"`

	// Location and network
	IPAddress    string `gorm:"type:varchar(45);not null" json:"ip_address"`
	IPLocation   string `gorm:"type:varchar(255)" json:"ip_location"`
	CountryCode  string `gorm:"type:varchar(2)" json:"country_code"`
	City         string `gorm:"type:varchar(255)" json:"city"`

	// Session metadata
	UserAgent    string     `gorm:"type:text;not null" json:"user_agent"`
	IsActive     bool       `gorm:"default:true;index" json:"is_active"`
	IsTrusted    bool       `gorm:"default:false" json:"is_trusted"`
	MFAVerified  bool       `gorm:"default:false" json:"mfa_verified"`

	// Timestamps
	ExpiresAt      time.Time  `gorm:"not null;index" json:"expires_at"`
	LastActivityAt time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_activity_at"`
	CreatedAt      time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	RevokedAt      *time.Time `gorm:"index" json:"revoked_at,omitempty"`
	RevokedReason  string     `gorm:"type:varchar(255)" json:"revoked_reason,omitempty"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// EmailToken represents tokens used for email verification, password reset, etc.
type EmailToken struct {
	ID         string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID     string    `gorm:"type:uuid;not null;index" json:"user_id"`
	TokenType  string    `gorm:"type:varchar(50);not null;index" json:"token_type"` // verification, password_reset, email_change, magic_link
	TokenHash  string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"-"`
	Email      string    `gorm:"type:varchar(255);not null;index" json:"email"`
	NewEmail   string    `gorm:"type:varchar(255)" json:"new_email,omitempty"` // For email change tokens

	// Metadata
	IPAddress string `gorm:"type:varchar(45);not null" json:"ip_address"`
	UserAgent string `gorm:"type:text" json:"user_agent"`

	// Timestamps
	ExpiresAt  time.Time  `gorm:"not null;index" json:"expires_at"`
	ConsumedAt *time.Time `gorm:"index" json:"consumed_at,omitempty"`
	CreatedAt  time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// LoginAttempt tracks login attempts for security monitoring
type LoginAttempt struct {
	ID          string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID      *string   `gorm:"type:uuid;index" json:"user_id,omitempty"`
	Email       string    `gorm:"type:varchar(255);not null;index" json:"email"`
	IPAddress   string    `gorm:"type:varchar(45);not null;index" json:"ip_address"`
	UserAgent   string    `gorm:"type:text" json:"user_agent"`

	// Attempt details
	AttemptType    string `gorm:"type:varchar(50);not null;default:'password'" json:"attempt_type"` // password, mfa, social, magic_link, api_key
	Status         string `gorm:"type:varchar(50);not null;index" json:"status"` // success, failed, blocked, suspicious
	FailureReason  string `gorm:"type:varchar(255)" json:"failure_reason,omitempty"`

	// Risk assessment
	RiskScore     int   `gorm:"default:0;check:risk_score >= 0 AND risk_score <= 100" json:"risk_score"`
	RiskFactors   JSONB `gorm:"type:jsonb" json:"risk_factors,omitempty"`

	// Metadata
	DeviceFingerprint string    `gorm:"type:varchar(255)" json:"device_fingerprint,omitempty"`
	Location          string    `gorm:"type:varchar(255)" json:"location,omitempty"`
	CreatedAt         time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// MFABackupCode stores backup codes for MFA recovery
type MFABackupCode struct {
	ID       string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID   string     `gorm:"type:uuid;not null;index" json:"user_id"`
	CodeHash string     `gorm:"type:varchar(255);not null;uniqueIndex:idx_user_code" json:"-"`
	UsedAt   *time.Time `gorm:"index" json:"used_at,omitempty"`
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// TrustedDevice represents a device that has been trusted by the user
type TrustedDevice struct {
	ID                string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID            string    `gorm:"type:uuid;not null;index" json:"user_id"`
	DeviceFingerprint string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_user_device" json:"device_fingerprint"`
	DeviceName        string    `gorm:"type:varchar(255)" json:"device_name"`

	// Trust information
	TrustTokenHash string `gorm:"type:varchar(255);not null;uniqueIndex" json:"-"`
	IsActive       bool   `gorm:"default:true;index" json:"is_active"`

	// Device details
	DeviceType    string `gorm:"type:varchar(50)" json:"device_type"`
	Browser       string `gorm:"type:varchar(100)" json:"browser"`
	OS            string `gorm:"type:varchar(100)" json:"os"`
	LastIPAddress string `gorm:"type:varchar(45)" json:"last_ip_address"`
	LastLocation  string `gorm:"type:varchar(255)" json:"last_location"`

	// Timestamps
	LastUsedAt time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_used_at"`
	ExpiresAt  time.Time  `gorm:"not null;index" json:"expires_at"`
	CreatedAt  time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// SecurityEvent tracks security-related events for auditing
type SecurityEvent struct {
	ID            string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID        *string   `gorm:"type:uuid;index" json:"user_id,omitempty"`
	EventType     string    `gorm:"type:varchar(100);not null;index" json:"event_type"`
	EventCategory string    `gorm:"type:varchar(50);not null;index" json:"event_category"` // auth, access, modification, security, compliance
	Severity      string    `gorm:"type:varchar(20);not null;index" json:"severity"` // info, warning, error, critical

	// Event details
	Description string `gorm:"type:text;not null" json:"description"`
	Details     JSONB  `gorm:"type:jsonb" json:"details,omitempty"`

	// Context
	IPAddress string  `gorm:"type:varchar(45)" json:"ip_address,omitempty"`
	UserAgent string  `gorm:"type:text" json:"user_agent,omitempty"`
	SessionID string  `gorm:"type:varchar(255);index" json:"session_id,omitempty"`

	// Response
	ActionTaken string    `gorm:"type:varchar(255)" json:"action_taken,omitempty"`
	AlertSent   bool      `gorm:"default:false" json:"alert_sent"`
	CreatedAt   time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// RateLimitBucket stores rate limiting data persistently
type RateLimitBucket struct {
	ID         string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	BucketKey  string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"bucket_key"` // e.g., "login:ip:192.168.1.1"
	BucketType string    `gorm:"type:varchar(50);not null;index" json:"bucket_type"`

	// Token bucket algorithm
	Tokens       int       `gorm:"not null;default:0" json:"tokens"`
	MaxTokens    int       `gorm:"not null" json:"max_tokens"`
	RefillRate   int       `gorm:"not null" json:"refill_rate"` // tokens per minute
	LastRefillAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_refill_at"`

	// Timestamps
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP;index" json:"updated_at"`
}

// EnhancedUser extends the base User model with additional security fields
type EnhancedUser struct {
	User

	// Suspension fields
	SuspendedAt       *time.Time `gorm:"index" json:"suspended_at,omitempty"`
	SuspensionReason  string     `gorm:"type:varchar(255)" json:"suspension_reason,omitempty"`

	// Password policy
	PasswordHistoryLimit     int  `gorm:"not null;default:5" json:"password_history_limit"`
	RequiresPasswordChange   bool `gorm:"not null;default:false" json:"requires_password_change"`

	// Security settings
	SecurityQuestions JSONB        `gorm:"type:jsonb" json:"security_questions,omitempty"`
	TrustedIPs        StringSlice  `gorm:"type:jsonb;default:'[]'" json:"trusted_ips"`

	// Session settings
	SessionTimeoutMinutes   *int `json:"session_timeout_minutes,omitempty"`
	MaxConcurrentSessions   *int `json:"max_concurrent_sessions,omitempty"`

	// Relationships
	PasswordHistory []PasswordHistory `gorm:"foreignKey:UserID" json:"-"`
	Sessions        []Session          `gorm:"foreignKey:UserID" json:"-"`
	EmailTokens     []EmailToken       `gorm:"foreignKey:UserID" json:"-"`
	LoginAttempts   []LoginAttempt     `gorm:"foreignKey:UserID" json:"-"`
	MFABackupCodes  []MFABackupCode    `gorm:"foreignKey:UserID" json:"-"`
	TrustedDevices  []TrustedDevice    `gorm:"foreignKey:UserID" json:"-"`
	SecurityEvents  []SecurityEvent    `gorm:"foreignKey:UserID" json:"-"`
}

// TableName overrides the table name for EnhancedUser
func (EnhancedUser) TableName() string {
	return "users"
}

// BeforeCreate hook for AuthSession
func (s *AuthSession) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = generateUUID()
	}
	s.CreatedAt = time.Now()
	s.LastActivityAt = time.Now()
	return nil
}

// BeforeCreate hooks for other models
func (p *PasswordHistory) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = generateUUID()
	}
	return nil
}

func (e *EmailToken) BeforeCreate(tx *gorm.DB) error {
	if e.ID == "" {
		e.ID = generateUUID()
	}
	return nil
}

func (l *LoginAttempt) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = generateUUID()
	}
	return nil
}

func (m *MFABackupCode) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = generateUUID()
	}
	return nil
}

func (t *TrustedDevice) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = generateUUID()
	}
	return nil
}

func (s *SecurityEvent) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = generateUUID()
	}
	return nil
}

func (r *RateLimitBucket) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		r.ID = generateUUID()
	}
	r.CreatedAt = time.Now()
	r.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate hook for RateLimitBucket
func (r *RateLimitBucket) BeforeUpdate(tx *gorm.DB) error {
	r.UpdatedAt = time.Now()
	return nil
}

// Helper function to generate UUID (you can use google/uuid package)
func generateUUID() string {
	// This should use the uuid package in real implementation
	// return uuid.New().String()
	return "" // Placeholder
}