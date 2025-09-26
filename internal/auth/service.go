package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User represents a user in the auth service - this is now an alias for the GORM model
type User = models.User

// UserAdapter provides methods to work with the GORM User model
type UserAdapter struct{}

// NewUserAdapter creates a new user adapter
func NewUserAdapter() *UserAdapter {
	return &UserAdapter{}
}

// GetFullName returns the user's full name
func (ua *UserAdapter) GetFullName(user *User) string {
	return strings.TrimSpace(user.FirstName + " " + user.LastName)
}

// IsActive checks if user is active
func (ua *UserAdapter) IsActive(user *User) bool {
	return user.Status == "active"
}

// GetPassword returns the password hash
func (ua *UserAdapter) GetPassword(user *User) string {
	return user.PasswordHash
}

// Stub types for compatibility
type Session struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type APIKey struct {
	ID     string    `json:"id"`
	UserID string    `json:"user_id"`
	Name   string    `json:"name"`
	Key    string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type MFASetupData struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

type OrganizationStatus string

// Repository defines the auth data access interface
type Repository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, teamID string) ([]*User, error)
	GetUserByEmailVerificationToken(ctx context.Context, token string) (*User, error)
	GetUserByPasswordResetToken(ctx context.Context, token string) (*User, error)
	IncrementFailedLoginAtomic(ctx context.Context, userID string) error
	UpdateLastLoginAtomic(ctx context.Context, userID, ipAddress string) error
}


// Service provides authentication services
type Service struct {
	repo   Repository
	logger logger.Logger
}

// PostgresRepository implements Repository for PostgreSQL using GORM
type PostgresRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewPostgresRepository creates a new PostgreSQL auth repository
func NewPostgresRepository(db *gorm.DB) Repository {
	return &PostgresRepository{
		db:     db,
		logger: logger.New("auth-repository"),
	}
}

// NewService creates a new auth service
func NewService(repo Repository) *Service {
	return &Service{
		repo:   repo,
		logger: logger.New("auth-service"),
	}
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, user *User) error {
	return s.repo.CreateUser(ctx, user)
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(ctx context.Context, id string) (*User, error) {
	return s.repo.GetUserByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.repo.GetUserByEmail(ctx, email)
}

// UpdateUser updates a user
func (s *Service) UpdateUser(ctx context.Context, user *User) error {
	return s.repo.UpdateUser(ctx, user)
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	return s.repo.DeleteUser(ctx, id)
}

// ListUsers lists users for a team
func (s *Service) ListUsers(ctx context.Context, teamID string) ([]*User, error) {
	return s.repo.ListUsers(ctx, teamID)
}

// Additional service methods for enhanced functionality

// UpdateLastLogin updates the user's last login information
func (s *Service) UpdateLastLogin(ctx context.Context, userID, ipAddress string) error {
	// Use atomic update to prevent race conditions
	return s.repo.UpdateLastLoginAtomic(ctx, userID, ipAddress)
}

// IncrementFailedLogin increments the failed login attempts and locks account if necessary
// This method is now atomic to prevent race conditions
func (s *Service) IncrementFailedLogin(ctx context.Context, userID string) error {
	// Use atomic increment to prevent race conditions
	return s.repo.IncrementFailedLoginAtomic(ctx, userID)
}

// IsAccountLocked checks if user account is currently locked
func (s *Service) IsAccountLocked(ctx context.Context, userID string) (bool, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if user.LockedUntil == nil {
		return false, nil
	}

	return time.Now().Before(*user.LockedUntil), nil
}

// UnlockAccount unlocks a user account
func (s *Service) UnlockAccount(ctx context.Context, userID string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	user.LockedUntil = nil
	user.FailedLoginAttempts = 0

	return s.repo.UpdateUser(ctx, user)
}

// GenerateSecureToken generates a cryptographically secure random token
func (s *Service) GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// SetEmailVerificationToken sets email verification token for a user
func (s *Service) SetEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	token, err := s.GenerateSecureToken()
	if err != nil {
		return "", err
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(24 * time.Hour) // Token expires in 24 hours
	user.EmailVerificationToken = token
	user.EmailVerificationExpiresAt = &expiresAt

	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyEmail verifies user email using token
func (s *Service) VerifyEmail(ctx context.Context, token string) (*User, error) {
	user, err := s.repo.GetUserByEmailVerificationToken(ctx, token)
	if err != nil {
		return nil, err
	}

	user.EmailVerified = true
	user.EmailVerificationToken = ""
	user.EmailVerificationExpiresAt = nil

	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// SetPasswordResetToken sets password reset token for a user
func (s *Service) SetPasswordResetToken(ctx context.Context, email string) (string, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	token, err := s.GenerateSecureToken()
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(1 * time.Hour) // Token expires in 1 hour
	user.PasswordResetToken = token
	user.PasswordResetExpiresAt = &expiresAt

	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		return "", err
	}

	return token, nil
}

// ResetPassword resets user password using token
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) (*User, error) {
	user, err := s.repo.GetUserByPasswordResetToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Hash the new password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Failed to hash password during reset", "user_id", user.ID, "error", err)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to process password")
	}
	user.PasswordHash = string(hashedPassword)
	user.PasswordResetToken = ""
	user.PasswordResetExpiresAt = nil
	user.PasswordChangedAt = time.Now()
	user.FailedLoginAttempts = 0 // Reset failed attempts
	user.LockedUntil = nil       // Unlock account

	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Repository implementation

// CreateUser creates a new user in the database using GORM
func (r *PostgresRepository) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.NewValidationError("user cannot be nil")
	}

	// Validate required fields
	if user.Email == "" {
		return errors.NewValidationError("email is required")
	}
	if user.FirstName == "" {
		return errors.NewValidationError("first name is required")
	}
	if user.PasswordHash == "" {
		return errors.NewValidationError("password hash is required")
	}

	// Use GORM to create the user
	result := r.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		r.logger.Error("Failed to create user", "error", result.Error, "email", user.Email)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to create user")
	}

	r.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
	return nil
}

// GetUserByID retrieves a user by ID using GORM
func (r *PostgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	var user User
	result := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", id).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by ID", "error", result.Error, "user_id", id)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email using GORM
func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, errors.NewValidationError("email is required")
	}

	var user User
	result := r.db.WithContext(ctx).Where("email = ? AND deleted_at IS NULL", email).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by email", "error", result.Error, "email", email)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// UpdateUser updates a user in the database using GORM
func (r *PostgresRepository) UpdateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.NewValidationError("user cannot be nil")
	}
	if user.ID == "" {
		return errors.NewValidationError("user ID is required")
	}

	// Use GORM to save the user
	result := r.db.WithContext(ctx).Save(user)
	if result.Error != nil {
		r.logger.Error("Failed to update user", "error", result.Error, "user_id", user.ID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to update user")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("User updated successfully", "user_id", user.ID)
	return nil
}

// DeleteUser soft deletes a user (sets deleted_at timestamp)
func (r *PostgresRepository) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("user ID is required")
	}

	// Use GORM's Delete method for soft delete
	result := r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id)
	if result.Error != nil {
		r.logger.Error("Failed to delete user", "error", result.Error, "user_id", id)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to delete user")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("User deleted successfully", "user_id", id)
	return nil
}

// ListUsers lists users for a team with optional filtering
func (r *PostgresRepository) ListUsers(ctx context.Context, teamID string) ([]*User, error) {
	var users []*User
	var result *gorm.DB

	if teamID != "" {
		result = r.db.WithContext(ctx).Where("team_id = ?", teamID).Order("created_at DESC").Find(&users)
	} else {
		result = r.db.WithContext(ctx).Order("created_at DESC").Find(&users)
	}

	if result.Error != nil {
		r.logger.Error("Failed to list users", "error", result.Error, "team_id", teamID)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to list users")
	}

	r.logger.Info("Users listed successfully", "count", len(users), "team_id", teamID)
	return users, nil
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (r *PostgresRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	var user User
	result := r.db.WithContext(ctx).Where("email_verification_token = ? AND email_verification_expires_at > ?", token, time.Now()).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("invalid or expired verification token")
		}
		r.logger.Error("Failed to get user by verification token", "error", result.Error)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (r *PostgresRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	var user User
	result := r.db.WithContext(ctx).Where("password_reset_token = ? AND password_reset_expires_at > ?", token, time.Now()).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("invalid or expired reset token")
		}
		r.logger.Error("Failed to get user by reset token", "error", result.Error)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// IncrementFailedLoginAtomic atomically increments failed login attempts
func (r *PostgresRepository) IncrementFailedLoginAtomic(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	// Use GORM's raw SQL for this complex atomic update
	result := r.db.WithContext(ctx).Exec(`
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1,
			locked_until = CASE 
				WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
				ELSE locked_until
			END,
			updated_at = NOW()
		WHERE id = ? AND deleted_at IS NULL`, userID)

	if result.Error != nil {
		r.logger.Error("Failed to increment failed login attempts", "error", result.Error, "user_id", userID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to update failed login attempts")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Failed login attempts incremented atomically", "user_id", userID)
	return nil
}

// UpdateLastLoginAtomic atomically updates last login information
func (r *PostgresRepository) UpdateLastLoginAtomic(ctx context.Context, userID, ipAddress string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	// Use GORM's raw SQL for this atomic update
	result := r.db.WithContext(ctx).Exec(`
		UPDATE users SET
			last_login_at = NOW(),
			last_login_ip = ?,
			login_count = login_count + 1,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = NOW()
		WHERE id = ? AND deleted_at IS NULL`, ipAddress, userID)

	if result.Error != nil {
		r.logger.Error("Failed to update last login", "error", result.Error, "user_id", userID)
	return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to update last login")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Last login updated atomically", "user_id", userID)
	return nil
}

// Additional service methods for extended functionality

// SetEmailChangeToken sets an email change token for a user
func (s *Service) SetEmailChangeToken(ctx context.Context, userID, newEmail string) (string, error) {
	token, err := s.GenerateSecureToken()
	if err != nil {
		return "", err
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	// For now, store this in settings - in production, you'd have a separate table
	if user.Settings == nil {
		user.Settings = make(map[string]interface{})
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	user.Settings["email_change_token"] = token
	user.Settings["email_change_new_email"] = newEmail
	user.Settings["email_change_expires_at"] = expiresAt

	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		return "", err
	}

	return token, nil
}

// UpdatePassword updates a user's password
func (s *Service) UpdatePassword(ctx context.Context, userID, hashedPassword string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	user.PasswordHash = hashedPassword
	user.PasswordChangedAt = time.Now()
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil

	return s.repo.UpdateUser(ctx, user)
}

// InvalidateOtherSessions invalidates all sessions except the current one (stub)
func (s *Service) InvalidateOtherSessions(ctx context.Context, userID, currentSessionID string) error {
	// For now, this is a stub - in production you'd have a sessions table
	s.logger.Info("Invalidating other sessions", "user_id", userID, "current_session_id", currentSessionID)
	return nil
}

// GetUserSessions returns all sessions for a user (stub)
func (s *Service) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	// For now, this is a stub - in production you'd have a sessions table
	s.logger.Info("Getting user sessions", "user_id", userID)
	return []*Session{}, nil
}

// RevokeSession revokes a specific session (stub)
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	// For now, this is a stub - in production you'd have a sessions table
	s.logger.Info("Revoking session", "user_id", userID, "session_id", sessionID)
	return nil
}

// RevokeAllSessions revokes all sessions for a user (stub)
func (s *Service) RevokeAllSessions(ctx context.Context, userID string) error {
	// For now, this is a stub - in production you'd have a sessions table
	s.logger.Info("Revoking all sessions", "user_id", userID)
	return nil
}

// SetupMFA sets up MFA for user (stub)
func (s *Service) SetupMFA(ctx context.Context, userID string) (*MFASetupData, error) {
	// For now, this is a stub - in production you'd implement TOTP
	s.logger.Info("Setting up MFA", "user_id", userID)
	return &MFASetupData{
		Secret:      "JBSWY3DPEHPK3PXP",
		QRCodeURL:   "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Example:user@example.com%3Fsecret=JBSWY3DPEHPK3PXP%26issuer=Example",
		BackupCodes: []string{"123456", "789012"},
	}, nil
}

// VerifyAndEnableMFA verifies and enables MFA (stub)
func (s *Service) VerifyAndEnableMFA(ctx context.Context, userID, code string) error {
	// For now, this is a stub - in production you'd verify TOTP
	s.logger.Info("Verifying and enabling MFA", "user_id", userID)
	return nil
}

// DisableMFA disables MFA (stub)
func (s *Service) DisableMFA(ctx context.Context, userID string) error {
	// For now, this is a stub
	s.logger.Info("Disabling MFA", "user_id", userID)
	return nil
}

// GenerateBackupCodes generates backup codes (stub)
func (s *Service) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// For now, this is a stub
	s.logger.Info("Generating backup codes", "user_id", userID)
	return []string{"123456", "789012", "345678"}, nil
}


// RevokeAPIKey revokes an API key (stub)
func (s *Service) RevokeAPIKey(ctx context.Context, keyID, userID, ipAddress string) error {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Revoking API key", "key_id", keyID, "user_id", userID, "ip", ipAddress)
	return nil
}

// GetOrganizationAPIKeys gets organization API keys (stub)
func (s *Service) GetOrganizationAPIKeys(ctx context.Context, orgID string, page, limit int) ([]*APIKey, int, error) {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Getting organization API keys", "org_id", orgID, "page", page, "limit", limit)
	return []*APIKey{}, 0, nil
}

// GetAllOrganizations gets all organizations (stub)
func (s *Service) GetAllOrganizations(ctx context.Context, page, limit int, status, search string) ([]*Organization, int, error) {
	// For now, this is a stub - in production you'd have an organizations table
	s.logger.Info("Getting all organizations", "page", page, "limit", limit, "status", status, "search", search)
	return []*Organization{}, 0, nil
}

// UpdateOrganizationStatus updates organization status (stub)
func (s *Service) UpdateOrganizationStatus(ctx context.Context, orgID string, status OrganizationStatus) error {
	// For now, this is a stub - in production you'd have an organizations table
	s.logger.Info("Updating organization status", "org_id", orgID, "status", status)
	return nil
}

// CreateAPIKey creates a new API key (stub)
func (s *Service) CreateAPIKey(ctx context.Context, userID, name, description string, permissions []string, expiresAt *time.Time) (*APIKey, string, error) {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Creating API key", "user_id", userID, "name", name)
	key := &APIKey{
		ID:        "api_key_123",
		UserID:    userID,
		Name:      name,
		Key:       "sk_test_1234567890",
		CreatedAt: time.Now(),
	}
	return key, "sk_test_1234567890", nil
}

// GetUserAPIKeys gets user's API keys (stub)
func (s *Service) GetUserAPIKeys(ctx context.Context, userID string, page, limit int) ([]*APIKey, int, error) {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Getting user API keys", "user_id", userID, "page", page, "limit", limit)
	return []*APIKey{}, 0, nil
}

// GetAPIKey gets an API key by ID (stub)
func (s *Service) GetAPIKey(ctx context.Context, keyID, userID string) (*APIKey, error) {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Getting API key", "key_id", keyID, "user_id", userID)
	return nil, errors.NewNotFoundError("API key not found")
}

// UpdateAPIKey updates an API key (stub)
func (s *Service) UpdateAPIKey(ctx context.Context, keyID, userID, name, description string, permissions []string) error {
	// For now, this is a stub - in production you'd have an API keys table
	s.logger.Info("Updating API key", "key_id", keyID, "user_id", userID, "name", name)
	return nil
}
