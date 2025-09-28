package auth

import (
	"context"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/logger"

	"gorm.io/gorm"
)

// Service provides backwards compatibility with the old auth service interface
// This wraps the new AuthService to work with existing code
type Service struct {
	authService *AuthService
	repo        Repository
	logger      logger.Logger
}

// NewService creates a new compatibility service wrapper
func NewService(repo Repository) *Service {
	return &Service{
		repo:   repo,
		logger: logger.New("auth-service-compat"),
	}
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, user *models.User) error {
	return s.repo.CreateUser(ctx, user)
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.repo.GetUserByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.repo.GetUserByEmail(ctx, email)
}

// UpdateUser updates a user
func (s *Service) UpdateUser(ctx context.Context, user *models.User) error {
	return s.repo.UpdateUser(ctx, user)
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	return s.repo.DeleteUser(ctx, id)
}

// ListUsers lists users for a team
func (s *Service) ListUsers(ctx context.Context, teamID string) ([]*models.User, error) {
	return s.repo.ListUsers(ctx, teamID)
}

// Repository defines the auth data access interface
type Repository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, teamID string) ([]*models.User, error)
	GetUserByEmailVerificationToken(ctx context.Context, token string) (*models.User, error)
	GetUserByPasswordResetToken(ctx context.Context, token string) (*models.User, error)
	IncrementFailedLoginAtomic(ctx context.Context, userID string) error
	UpdateLastLoginAtomic(ctx context.Context, userID, ipAddress string) error
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

// CreateUser creates a new user
func (r *PostgresRepository) CreateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

// GetUserByID retrieves a user by ID
func (r *PostgresRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates a user
func (r *PostgresRepository) UpdateUser(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// DeleteUser deletes a user
func (r *PostgresRepository) DeleteUser(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.User{}).Error
}

// ListUsers lists users for a team/organization
func (r *PostgresRepository) ListUsers(ctx context.Context, teamID string) ([]*models.User, error) {
	var users []*models.User
	err := r.db.WithContext(ctx).Where("organization_id = ?", teamID).Find(&users).Error
	return users, err
}

// GetUserByEmailVerificationToken retrieves a user by email verification token
func (r *PostgresRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email_verification_token = ?", token).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByPasswordResetToken retrieves a user by password reset token
func (r *PostgresRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("password_reset_token = ?", token).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// IncrementFailedLoginAtomic atomically increments failed login attempts
func (r *PostgresRepository) IncrementFailedLoginAtomic(ctx context.Context, userID string) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"failed_login_attempts": gorm.Expr("failed_login_attempts + ?", 1),
			"updated_at":           time.Now(),
		})
	
	if result.Error != nil {
		return result.Error
	}

	// Check if we need to lock the account (after 5 attempts)
	var user models.User
	if err := r.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}

	if user.FailedLoginAttempts >= 5 && user.LockedUntil == nil {
		lockUntil := time.Now().Add(30 * time.Minute)
		return r.db.WithContext(ctx).Model(&models.User{}).
			Where("id = ?", userID).
			Update("locked_until", lockUntil).Error
	}

	return nil
}

// UpdateLastLoginAtomic atomically updates last login information
func (r *PostgresRepository) UpdateLastLoginAtomic(ctx context.Context, userID, ipAddress string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"last_login_at":        now,
			"last_login_ip":        ipAddress,
			"failed_login_attempts": 0,
			"locked_until":         nil,
			"updated_at":           now,
		}).Error
}