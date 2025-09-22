package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"n8n-pro/internal/storage/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jackc/pgx/v5"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	Password  string    `json:"-" db:"password_hash"`
	Active    bool      `json:"active" db:"active"`
	TeamID    string    `json:"team_id" db:"team_id"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Email verification
	EmailVerified              bool       `json:"email_verified" db:"email_verified"`
	EmailVerificationToken     *string    `json:"-" db:"email_verification_token"`
	EmailVerificationExpiresAt *time.Time `json:"-" db:"email_verification_expires_at"`

	// Password reset
	PasswordResetToken     *string    `json:"-" db:"password_reset_token"`
	PasswordResetExpiresAt *time.Time `json:"-" db:"password_reset_expires_at"`

	// Profile information
	AvatarURL *string `json:"avatar_url" db:"avatar_url"`
	Timezone  string  `json:"timezone" db:"timezone"`
	Language  string  `json:"language" db:"language"`

	// Activity tracking
	LastLoginAt    *time.Time `json:"last_login_at" db:"last_login_at"`
	LastLoginIP    *string    `json:"last_login_ip" db:"last_login_ip"`
	LoginCount     int        `json:"login_count" db:"login_count"`

	// Account security
	FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until" db:"locked_until"`
	PasswordChangedAt   time.Time  `json:"password_changed_at" db:"password_changed_at"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata" db:"metadata"`

	// Soft delete
	DeletedAt *time.Time `json:"deleted_at" db:"deleted_at"`
}

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
}

// Team represents a team in the system
type Team struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Slug        string                 `json:"slug" db:"slug"`
	Description *string                `json:"description" db:"description"`
	Plan        string                 `json:"plan" db:"plan"`
	MaxUsers    int                    `json:"max_users" db:"max_users"`
	Settings    map[string]interface{} `json:"settings" db:"settings"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// Service provides authentication services
type Service struct {
	repo   Repository
	logger logger.Logger
}

// PostgresRepository implements Repository for PostgreSQL
type PostgresRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresRepository creates a new PostgreSQL auth repository
func NewPostgresRepository(db *postgres.DB) Repository {
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
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	user.LoginCount++
	user.FailedLoginAttempts = 0 // Reset failed attempts on successful login

	return s.repo.UpdateUser(ctx, user)
}

// IncrementFailedLogin increments the failed login attempts and locks account if necessary
func (s *Service) IncrementFailedLogin(ctx context.Context, userID string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	user.FailedLoginAttempts++
	
	// Lock account after 5 failed attempts for 30 minutes
	if user.FailedLoginAttempts >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		user.LockedUntil = &lockUntil
	}

	return s.repo.UpdateUser(ctx, user)
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
	user.EmailVerificationToken = &token
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
	user.EmailVerificationToken = nil
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
	user.PasswordResetToken = &token
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

	user.Password = newPassword // This should be hashed by the caller
	user.PasswordResetToken = nil
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

// CreateUser creates a new user in the database
func (r *PostgresRepository) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.NewValidationError("user cannot be nil")
	}

	// Validate required fields
	if user.Email == "" {
		return errors.NewValidationError("email is required")
	}
	if user.Name == "" {
		return errors.NewValidationError("name is required")
	}
	if user.Password == "" {
		return errors.NewValidationError("password is required")
	}

	query := `
		INSERT INTO users (
			id, email, name, password_hash, active, team_id, role,
			email_verified, timezone, language, password_changed_at,
			metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		user.ID, user.Email, user.Name, user.Password, user.Active,
		user.TeamID, user.Role, user.EmailVerified, user.Timezone,
		user.Language, now, user.Metadata, now, now,
	)

	if err != nil {
		r.logger.Error("Failed to create user", "error", err, "email", user.Email)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to create user")
	}

	r.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
	return nil
}

// GetUserByID retrieves a user by ID
func (r *PostgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	query := `
		SELECT 
			id, email, name, password_hash, active, team_id, role,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			avatar_url, timezone, language,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at,
			metadata, created_at, updated_at, deleted_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	var user User
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Name, &user.Password, &user.Active,
		&user.TeamID, &user.Role, &user.EmailVerified,
		&user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.AvatarURL, &user.Timezone, &user.Language,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
		&user.Metadata, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by ID", "error", err, "user_id", id)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, errors.NewValidationError("email is required")
	}

	query := `
		SELECT 
			id, email, name, password_hash, active, team_id, role,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			avatar_url, timezone, language,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at,
			metadata, created_at, updated_at, deleted_at
		FROM users 
		WHERE email = $1 AND deleted_at IS NULL`

	var user User
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Name, &user.Password, &user.Active,
		&user.TeamID, &user.Role, &user.EmailVerified,
		&user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.AvatarURL, &user.Timezone, &user.Language,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
		&user.Metadata, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by email", "error", err, "email", email)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// UpdateUser updates a user in the database
func (r *PostgresRepository) UpdateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.NewValidationError("user cannot be nil")
	}
	if user.ID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET
			email = $2, name = $3, password_hash = $4, active = $5,
			team_id = $6, role = $7, email_verified = $8,
			email_verification_token = $9, email_verification_expires_at = $10,
			password_reset_token = $11, password_reset_expires_at = $12,
			avatar_url = $13, timezone = $14, language = $15,
			last_login_at = $16, last_login_ip = $17, login_count = $18,
			failed_login_attempts = $19, locked_until = $20, password_changed_at = $21,
			metadata = $22, updated_at = $23
		WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query,
		user.ID, user.Email, user.Name, user.Password, user.Active,
		user.TeamID, user.Role, user.EmailVerified,
		user.EmailVerificationToken, user.EmailVerificationExpiresAt,
		user.PasswordResetToken, user.PasswordResetExpiresAt,
		user.AvatarURL, user.Timezone, user.Language,
		user.LastLoginAt, user.LastLoginIP, user.LoginCount,
		user.FailedLoginAttempts, user.LockedUntil, user.PasswordChangedAt,
		user.Metadata, now,
	)

	if err != nil {
		r.logger.Error("Failed to update user", "error", err, "user_id", user.ID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to update user")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
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

	query := `UPDATE users SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.logger.Error("Failed to delete user", "error", err, "user_id", id)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to delete user")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("User deleted successfully", "user_id", id)
	return nil
}

// ListUsers lists users for a team with optional filtering
func (r *PostgresRepository) ListUsers(ctx context.Context, teamID string) ([]*User, error) {
	var query string
	var args []interface{}

	if teamID != "" {
		query = `
			SELECT 
				id, email, name, password_hash, active, team_id, role,
				email_verified, email_verification_token, email_verification_expires_at,
				password_reset_token, password_reset_expires_at,
				avatar_url, timezone, language,
				last_login_at, last_login_ip, login_count,
				failed_login_attempts, locked_until, password_changed_at,
				metadata, created_at, updated_at, deleted_at
			FROM users 
			WHERE team_id = $1 AND deleted_at IS NULL
			ORDER BY created_at DESC`
		args = append(args, teamID)
	} else {
		query = `
			SELECT 
				id, email, name, password_hash, active, team_id, role,
				email_verified, email_verification_token, email_verification_expires_at,
				password_reset_token, password_reset_expires_at,
				avatar_url, timezone, language,
				last_login_at, last_login_ip, login_count,
				failed_login_attempts, locked_until, password_changed_at,
				metadata, created_at, updated_at, deleted_at
			FROM users 
			WHERE deleted_at IS NULL
			ORDER BY created_at DESC`
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list users", "error", err, "team_id", teamID)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to list users")
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID, &user.Email, &user.Name, &user.Password, &user.Active,
			&user.TeamID, &user.Role, &user.EmailVerified,
			&user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
			&user.PasswordResetToken, &user.PasswordResetExpiresAt,
			&user.AvatarURL, &user.Timezone, &user.Language,
			&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
			&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
			&user.Metadata, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan user row", "error", err)
			return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to scan user data")
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating user rows", "error", err)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to iterate user data")
	}

	r.logger.Info("Users listed successfully", "count", len(users), "team_id", teamID)
	return users, nil
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (r *PostgresRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	query := `
		SELECT 
			id, email, name, password_hash, active, team_id, role,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			avatar_url, timezone, language,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at,
			metadata, created_at, updated_at, deleted_at
		FROM users 
		WHERE email_verification_token = $1 AND deleted_at IS NULL
		  AND email_verification_expires_at > NOW()`

	var user User
	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.Email, &user.Name, &user.Password, &user.Active,
		&user.TeamID, &user.Role, &user.EmailVerified,
		&user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.AvatarURL, &user.Timezone, &user.Language,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
		&user.Metadata, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("invalid or expired verification token")
		}
		r.logger.Error("Failed to get user by verification token", "error", err)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (r *PostgresRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	query := `
		SELECT 
			id, email, name, password_hash, active, team_id, role,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			avatar_url, timezone, language,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at,
			metadata, created_at, updated_at, deleted_at
		FROM users 
		WHERE password_reset_token = $1 AND deleted_at IS NULL
		  AND password_reset_expires_at > NOW()`

	var user User
	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.Email, &user.Name, &user.Password, &user.Active,
		&user.TeamID, &user.Role, &user.EmailVerified,
		&user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.AvatarURL, &user.Timezone, &user.Language,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
		&user.Metadata, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("invalid or expired reset token")
		}
		r.logger.Error("Failed to get user by reset token", "error", err)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve user")
	}

	return &user, nil
}