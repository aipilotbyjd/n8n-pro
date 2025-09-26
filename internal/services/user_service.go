// Package services provides business logic and data access services for n8n-pro
// Following patterns used by GitHub, GitLab, Stripe, and other production applications
package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"n8n-pro/internal/database"
	"n8n-pro/internal/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UserService handles all user-related business logic
type UserService struct {
	db *database.Database
}

// NewUserService creates a new user service instance
func NewUserService(db *database.Database) *UserService {
	return &UserService{
		db: db,
	}
}

// CreateUser creates a new user in the system
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*models.User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		OrganizationID: req.OrganizationID,
		Email:          req.Email,
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		PasswordHash:   string(hashedPassword),
		Status:         "pending",
		Role:           req.Role,
		Profile: models.JSONB{
			"avatar_url":   nil,
			"bio":          "",
			"location":     "",
			"website":      "",
			"phone_number": "",
			"job_title":    req.JobTitle,
			"department":   req.Department,
		},
		Settings: models.JSONB{
			"timezone":    "UTC",
			"language":    "en",
			"theme":       "light",
			"notifications": map[string]bool{
				"email_workflow_success": false,
				"email_workflow_failure": true,
				"email_security_alerts":  true,
				"desktop_notifications":  true,
			},
		},
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("Organization").
		Preload("TeamMembers.Team").
		First(&user, "id = ?", userID).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).
		Preload("Organization").
		First(&user, "email = ? AND deleted_at IS NULL", email).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Update fields
	updates := make(map[string]interface{})
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Role != "" {
		updates["role"] = req.Role
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.Profile != nil {
		updates["profile"] = req.Profile
	}
	if req.Settings != nil {
		updates["settings"] = req.Settings
	}

	if err := s.db.WithContext(ctx).Model(&user).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Reload user with associations
	return s.GetUserByID(ctx, userID)
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	result := s.db.WithContext(ctx).Delete(&models.User{}, "id = ?", userID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ListUsers retrieves paginated list of users
func (s *UserService) ListUsers(ctx context.Context, req ListUsersRequest) (*PaginatedResponse[models.User], error) {
	query := s.db.WithContext(ctx).Model(&models.User{})

	// Apply filters
	if req.OrganizationID != "" {
		query = query.Where("organization_id = ?", req.OrganizationID)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.Role != "" {
		query = query.Where("role = ?", req.Role)
	}
	if req.Search != "" {
		query = query.Where("(first_name ILIKE ? OR last_name ILIKE ? OR email ILIKE ?)",
			"%"+req.Search+"%", "%"+req.Search+"%", "%"+req.Search+"%")
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	// Apply sorting and pagination
	orderBy := "created_at DESC"
	if req.SortBy != "" {
		direction := "ASC"
		if req.SortOrder == "desc" {
			direction = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", req.SortBy, direction)
	}

	var users []models.User
	err := query.
		Preload("Organization").
		Order(orderBy).
		Offset(req.Offset).
		Limit(req.Limit).
		Find(&users).Error

	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return &PaginatedResponse[models.User]{
		Data:       users,
		Total:      int(total),
		Page:       (req.Offset / req.Limit) + 1,
		PageSize:   req.Limit,
		TotalPages: int((total + int64(req.Limit) - 1) / int64(req.Limit)),
		HasNext:    req.Offset+req.Limit < int(total),
		HasPrev:    req.Offset > 0,
	}, nil
}

// VerifyPassword verifies user password
func (s *UserService) VerifyPassword(ctx context.Context, email, password string) (*models.User, error) {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Update failed login attempts
		s.updateFailedLoginAttempts(ctx, user.ID)
		return nil, ErrInvalidCredentials
	}

	// Reset failed login attempts and update login info
	s.updateSuccessfulLogin(ctx, user.ID)

	return user, nil
}

// ChangePassword changes user password
func (s *UserService) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	now := time.Now()
	updates := map[string]interface{}{
		"password_hash":      string(hashedPassword),
		"password_changed_at": now,
	}

	if err := s.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// EnableMFA enables multi-factor authentication for user
func (s *UserService) EnableMFA(ctx context.Context, userID, secret string, backupCodes []string) error {
	updates := map[string]interface{}{
		"mfa_enabled":     true,
		"mfa_secret":      secret,
		"mfa_backup_codes": models.StringSlice(backupCodes),
	}

	if err := s.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	return nil
}

// DisableMFA disables multi-factor authentication for user
func (s *UserService) DisableMFA(ctx context.Context, userID string) error {
	updates := map[string]interface{}{
		"mfa_enabled":     false,
		"mfa_secret":      "",
		"mfa_backup_codes": models.StringSlice{},
	}

	if err := s.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	return nil
}

// GetUsersByOrganization gets all users in an organization
func (s *UserService) GetUsersByOrganization(ctx context.Context, orgID string) ([]models.User, error) {
	var users []models.User
	err := s.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Preload("TeamMembers.Team").
		Order("created_at DESC").
		Find(&users).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get users by organization: %w", err)
	}

	return users, nil
}

// Helper methods

func (s *UserService) updateFailedLoginAttempts(ctx context.Context, userID string) {
	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		UpdateColumn("failed_login_attempts", gorm.Expr("failed_login_attempts + 1")).
		Error

	if err != nil {
		log.Printf("Failed to update failed login attempts for user %s: %v", userID, err)
	}

	// Check if user should be locked
	var user models.User
	if err := s.db.WithContext(ctx).First(&user, "id = ?", userID).Error; err == nil {
		if user.FailedLoginAttempts >= 5 { // Configurable threshold
			lockUntil := time.Now().Add(30 * time.Minute) // Configurable duration
			s.db.WithContext(ctx).
				Model(&models.User{}).
				Where("id = ?", userID).
				Update("locked_until", lockUntil)
		}
	}
}

func (s *UserService) updateSuccessfulLogin(ctx context.Context, userID string) {
	now := time.Now()
	updates := map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
		"last_login_at":         now,
		"login_count":           gorm.Expr("login_count + 1"),
	}

	err := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Updates(updates).
		Error

	if err != nil {
		log.Printf("Failed to update successful login for user %s: %v", userID, err)
	}
}

// Request/Response types

type CreateUserRequest struct {
	OrganizationID string `json:"organization_id" validate:"required,uuid"`
	Email          string `json:"email" validate:"required,email"`
	FirstName      string `json:"first_name" validate:"required,min=1,max=255"`
	LastName       string `json:"last_name" validate:"required,min=1,max=255"`
	Password       string `json:"password" validate:"required,min=8"`
	Role           string `json:"role" validate:"required"`
	JobTitle       string `json:"job_title,omitempty"`
	Department     string `json:"department,omitempty"`
}

type UpdateUserRequest struct {
	FirstName string         `json:"first_name,omitempty"`
	LastName  string         `json:"last_name,omitempty"`
	Role      string         `json:"role,omitempty"`
	Status    string         `json:"status,omitempty"`
	Profile   models.JSONB   `json:"profile,omitempty"`
	Settings  models.JSONB   `json:"settings,omitempty"`
}

type ListUsersRequest struct {
	OrganizationID string `json:"organization_id,omitempty"`
	Status         string `json:"status,omitempty"`
	Role           string `json:"role,omitempty"`
	Search         string `json:"search,omitempty"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
	SortBy         string `json:"sort_by,omitempty"`
	SortOrder      string `json:"sort_order,omitempty"`
}

// Common response types
type PaginatedResponse[T any] struct {
	Data       []T  `json:"data"`
	Total      int  `json:"total"`
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}

// Common errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserLocked         = errors.New("user account is locked")
)