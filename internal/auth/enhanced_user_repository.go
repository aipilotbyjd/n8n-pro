package auth

import (
	"context"
	"strings"
	"time"

	"n8n-pro/internal/storage/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jackc/pgx/v5"
)

// PostgresEnhancedUserRepository implements EnhancedUserRepository
type PostgresEnhancedUserRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresEnhancedUserRepository creates a new enhanced user repository
func NewPostgresEnhancedUserRepository(db *postgres.DB) EnhancedUserRepository {
	return &PostgresEnhancedUserRepository{
		db:     db,
		logger: logger.New("enhanced-user-repository"),
	}
}

// CreateUser creates a new enhanced user
func (r *PostgresEnhancedUserRepository) CreateUser(ctx context.Context, user *EnhancedUser) error {
	if user == nil {
		return errors.NewValidationError("user cannot be nil")
	}

	// Validate required fields
	if user.OrganizationID == "" {
		return errors.NewValidationError("organization ID is required")
	}
	if user.Email == "" {
		return errors.NewValidationError("email is required")
	}
	if user.FirstName == "" {
		return errors.NewValidationError("first name is required")
	}
	if user.LastName == "" {
		return errors.NewValidationError("last name is required")
	}
	if user.PasswordHash == "" {
		return errors.NewValidationError("password hash is required")
	}

	query := `
		INSERT INTO users (
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, email_verified, mfa_enabled,
			api_key, api_key_created_at, password_changed_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		user.ID, user.OrganizationID, user.Email, user.FirstName, user.LastName,
		user.PasswordHash, user.Status, user.Role, user.Profile, user.Settings,
		user.EmailVerified, user.MFAEnabled, user.APIKey, user.APIKeyCreatedAt,
		user.PasswordChangedAt, now, now,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			if strings.Contains(err.Error(), "email") {
				return errors.NewValidationError("email already exists in this organization")
			}
			if strings.Contains(err.Error(), "api_key") {
				return errors.NewValidationError("API key already exists")
			}
			return errors.NewValidationError("user already exists")
		}
		r.logger.Error("Failed to create user", "error", err, "email", user.Email)
		return errors.InternalError("failed to create user")
	}

	r.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email, "org_id", user.OrganizationID)
	return nil
}

// GetUserByID retrieves a user by ID
func (r *PostgresEnhancedUserRepository) GetUserByID(ctx context.Context, id string) (*EnhancedUser, error) {
	if id == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by ID", "error", err, "user_id", id)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email (first match across all organizations)
func (r *PostgresEnhancedUserRepository) GetUserByEmail(ctx context.Context, email string) (*EnhancedUser, error) {
	if email == "" {
		return nil, errors.NewValidationError("email is required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE email = $1 AND deleted_at IS NULL
		ORDER BY created_at ASC
		LIMIT 1`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by email", "error", err, "email", email)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}

// GetUserByEmailInOrganization retrieves a user by email within a specific organization
func (r *PostgresEnhancedUserRepository) GetUserByEmailInOrganization(ctx context.Context, email, orgID string) (*EnhancedUser, error) {
	if email == "" || orgID == "" {
		return nil, errors.NewValidationError("email and organization ID are required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE email = $1 AND organization_id = $2 AND deleted_at IS NULL`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, email, orgID).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("user not found")
		}
		r.logger.Error("Failed to get user by email in organization", "error", err, "email", email, "org_id", orgID)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}

// GetUsersByOrganization retrieves users for an organization with pagination
func (r *PostgresEnhancedUserRepository) GetUsersByOrganization(ctx context.Context, orgID string, limit, offset int) ([]*EnhancedUser, error) {
	if orgID == "" {
		return nil, errors.NewValidationError("organization ID is required")
	}

	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE organization_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, orgID, limit, offset)
	if err != nil {
		r.logger.Error("Failed to get users by organization", "error", err, "org_id", orgID)
		return nil, errors.InternalError("failed to retrieve users")
	}
	defer rows.Close()

	var users []*EnhancedUser
	for rows.Next() {
		var user EnhancedUser
		err := rows.Scan(
			&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
			&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
			&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
			&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
			&user.PasswordResetToken, &user.PasswordResetExpiresAt,
			&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
			&user.APIKey, &user.APIKeyCreatedAt,
			&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
			&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan user row", "error", err)
			return nil, errors.InternalError("failed to scan user data")
		}

		// Set computed permissions based on role
		permSet := GetRolePermissions(user.Role)
		user.Permissions = make([]Permission, 0, len(permSet))
		for perm := range permSet {
			user.Permissions = append(user.Permissions, perm)
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating user rows", "error", err)
		return nil, errors.InternalError("failed to iterate user data")
	}

	return users, nil
}

// UpdateUser updates a user
func (r *PostgresEnhancedUserRepository) UpdateUser(ctx context.Context, user *EnhancedUser) error {
	if user == nil || user.ID == "" {
		return errors.NewValidationError("user and ID are required")
	}

	query := `
		UPDATE users SET
			email = $2, first_name = $3, last_name = $4, password_hash = $5,
			status = $6, role = $7, profile = $8, settings = $9,
			email_verified = $10, email_verification_token = $11, email_verification_expires_at = $12,
			password_reset_token = $13, password_reset_expires_at = $14,
			mfa_enabled = $15, mfa_secret = $16, mfa_backup_codes = $17,
			api_key = $18, api_key_created_at = $19,
			last_login_at = $20, last_login_ip = $21, login_count = $22,
			failed_login_attempts = $23, locked_until = $24, password_changed_at = $25,
			updated_at = $26
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query,
		user.ID, user.Email, user.FirstName, user.LastName, user.PasswordHash,
		user.Status, user.Role, user.Profile, user.Settings,
		user.EmailVerified, user.EmailVerificationToken, user.EmailVerificationExpiresAt,
		user.PasswordResetToken, user.PasswordResetExpiresAt,
		user.MFAEnabled, user.MFASecret, user.MFABackupCodes,
		user.APIKey, user.APIKeyCreatedAt,
		user.LastLoginAt, user.LastLoginIP, user.LoginCount,
		user.FailedLoginAttempts, user.LockedUntil, user.PasswordChangedAt,
		time.Now(),
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			if strings.Contains(err.Error(), "email") {
				return errors.NewValidationError("email already exists in this organization")
			}
			if strings.Contains(err.Error(), "api_key") {
				return errors.NewValidationError("API key already exists")
			}
		}
		r.logger.Error("Failed to update user", "error", err, "user_id", user.ID)
		return errors.InternalError("failed to update user")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("User updated successfully", "user_id", user.ID)
	return nil
}

// DeleteUser soft deletes a user
func (r *PostgresEnhancedUserRepository) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `UPDATE users SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.logger.Error("Failed to delete user", "error", err, "user_id", id)
		return errors.InternalError("failed to delete user")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("User deleted successfully", "user_id", id)
	return nil
}

// UpdatePassword updates user's password hash and resets related fields
func (r *PostgresEnhancedUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	if userID == "" || passwordHash == "" {
		return errors.NewValidationError("user ID and password hash are required")
	}

	query := `
		UPDATE users SET 
			password_hash = $2,
			password_changed_at = $3,
			password_reset_token = NULL,
			password_reset_expires_at = NULL,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, userID, passwordHash, now)
	if err != nil {
		r.logger.Error("Failed to update password", "error", err, "user_id", userID)
		return errors.InternalError("failed to update password")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Password updated successfully", "user_id", userID)
	return nil
}

// UpdateLastLogin atomically updates last login information and clears failed attempts
func (r *PostgresEnhancedUserRepository) UpdateLastLogin(ctx context.Context, userID, ipAddress string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET
			last_login_at = NOW(),
			last_login_ip = $2,
			login_count = login_count + 1,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID, ipAddress)
	if err != nil {
		r.logger.Error("Failed to update last login", "error", err, "user_id", userID)
		return errors.InternalError("failed to update last login")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Last login updated successfully", "user_id", userID)
	return nil
}

// IncrementFailedLogin atomically increments failed login attempts and locks account if necessary
func (r *PostgresEnhancedUserRepository) IncrementFailedLogin(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1,
			locked_until = CASE 
				WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
				ELSE locked_until
			END,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to increment failed login attempts", "error", err, "user_id", userID)
		return errors.InternalError("failed to increment failed login attempts")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Failed login attempts incremented", "user_id", userID)
	return nil
}

// ResetFailedLogins resets failed login attempts to 0
func (r *PostgresEnhancedUserRepository) ResetFailedLogins(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET 
			failed_login_attempts = 0, 
			locked_until = NULL, 
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to reset failed logins", "error", err, "user_id", userID)
		return errors.InternalError("failed to reset failed logins")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Failed login attempts reset", "user_id", userID)
	return nil
}

// SetAccountLock locks an account until a specific time
func (r *PostgresEnhancedUserRepository) SetAccountLock(ctx context.Context, userID string, lockUntil time.Time) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET 
			locked_until = $2, 
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID, lockUntil)
	if err != nil {
		r.logger.Error("Failed to set account lock", "error", err, "user_id", userID)
		return errors.InternalError("failed to set account lock")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Account locked", "user_id", userID, "lock_until", lockUntil)
	return nil
}

// ClearAccountLock unlocks an account
func (r *PostgresEnhancedUserRepository) ClearAccountLock(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `
		UPDATE users SET 
			locked_until = NULL, 
			failed_login_attempts = 0,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to clear account lock", "error", err, "user_id", userID)
		return errors.InternalError("failed to clear account lock")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("user not found")
	}

	r.logger.Info("Account unlocked", "user_id", userID)
	return nil
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (r *PostgresEnhancedUserRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*EnhancedUser, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE email_verification_token = $1 AND deleted_at IS NULL
		  AND email_verification_expires_at > NOW()`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("invalid or expired verification token")
		}
		r.logger.Error("Failed to get user by verification token", "error", err)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (r *PostgresEnhancedUserRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*EnhancedUser, error) {
	if token == "" {
		return nil, errors.NewValidationError("token is required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE password_reset_token = $1 AND deleted_at IS NULL
		  AND password_reset_expires_at > NOW()`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, token).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("invalid or expired reset token")
		}
		r.logger.Error("Failed to get user by reset token", "error", err)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}

// GetUserByAPIKey retrieves a user by their API key
func (r *PostgresEnhancedUserRepository) GetUserByAPIKey(ctx context.Context, apiKey string) (*EnhancedUser, error) {
	if apiKey == "" {
		return nil, errors.NewValidationError("API key is required")
	}

	query := `
		SELECT 
			id, organization_id, email, first_name, last_name, password_hash,
			status, role, profile, settings, created_at, updated_at, deleted_at,
			email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at,
			mfa_enabled, mfa_secret, mfa_backup_codes,
			api_key, api_key_created_at,
			last_login_at, last_login_ip, login_count,
			failed_login_attempts, locked_until, password_changed_at
		FROM users 
		WHERE api_key = $1 AND deleted_at IS NULL AND status = 'active'`

	var user EnhancedUser
	err := r.db.QueryRow(ctx, query, apiKey).Scan(
		&user.ID, &user.OrganizationID, &user.Email, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Status, &user.Role, &user.Profile, &user.Settings,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		&user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpiresAt,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt,
		&user.MFAEnabled, &user.MFASecret, &user.MFABackupCodes,
		&user.APIKey, &user.APIKeyCreatedAt,
		&user.LastLoginAt, &user.LastLoginIP, &user.LoginCount,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.PasswordChangedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("invalid API key or inactive user")
		}
		r.logger.Error("Failed to get user by API key", "error", err)
		return nil, errors.InternalError("failed to retrieve user")
	}

	// Set computed permissions based on role
	permSet := GetRolePermissions(user.Role)
	user.Permissions = make([]Permission, 0, len(permSet))
	for perm := range permSet {
		user.Permissions = append(user.Permissions, perm)
	}

	return &user, nil
}
