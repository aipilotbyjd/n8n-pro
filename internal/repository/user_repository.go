package repository

import (
	"context"
	"errors"
	"fmt"

	"n8n-pro/internal/domain/user"
	"n8n-pro/internal/models"

	"gorm.io/gorm"
)

// UserRepository implements the user.Repository interface
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create creates a new user in the database
func (r *UserRepository) Create(ctx context.Context, user *user.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	// Convert domain model to GORM model
	userModel := &models.User{
		BaseModel: models.BaseModel{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
		OrganizationID: user.OrganizationID,
		Email:          user.Email,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		PasswordHash:   user.PasswordHash,
		Status:         user.Status,
		Role:           user.Role,
		Profile:        models.JSONB(user.Profile),
		Settings:       models.JSONB(user.Settings),
		EmailVerified:  user.EmailVerified,
		MFAEnabled:     user.MFAEnabled,
		APIKey:         user.APIKey,
		LastLoginAt:    user.LastLoginAt,
		LastLoginIP:    user.LastLoginIP,
		LoginCount:     user.LoginCount,
		LockedUntil:    user.LockedUntil,
		PasswordChangedAt: user.PasswordChangedAt,
	}

	// Set default values if not provided
	if userModel.APIKeyCreatedAt == nil && userModel.APIKey != "" {
		userModel.APIKeyCreatedAt = user.APIKeyCreatedAt
	}

	// Create the user in the database
	result := r.db.WithContext(ctx).Create(userModel)
	if result.Error != nil {
		return fmt.Errorf("failed to create user: %w", result.Error)
	}

	// Update the domain model with the created ID if it was auto-generated
	if user.ID == "" {
		user.ID = userModel.ID
	}

	return nil
}

// Update updates an existing user in the database
func (r *UserRepository) Update(ctx context.Context, user *user.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	if user.ID == "" {
		return errors.New("user ID cannot be empty")
	}

	// Convert domain model to GORM model for updates
	updates := map[string]interface{}{
		"first_name":         user.FirstName,
		"last_name":          user.LastName,
		"status":             user.Status,
		"role":               user.Role,
		"profile":            models.JSONB(user.Profile),
		"settings":           models.JSONB(user.Settings),
		"email_verified":     user.EmailVerified,
		"mfa_enabled":        user.MFAEnabled,
		"last_login_at":      user.LastLoginAt,
		"last_login_ip":      user.LastLoginIP,
		"login_count":        user.LoginCount,
		"locked_until":       user.LockedUntil,
		"password_changed_at": user.PasswordChangedAt,
		"updated_at":         user.UpdatedAt,
	}

	// Only update email if it's different (to maintain uniqueness constraints)
	if user.Email != "" {
		updates["email"] = user.Email
	}

	// Only update organization ID if it's different
	if user.OrganizationID != "" {
		updates["organization_id"] = user.OrganizationID
	}

	// Update the user in the database
	result := r.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", user.ID).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("failed to update user: %w", result.Error)
	}

	// Check if any rows were affected
	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Delete removes a user from the database (soft delete)
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("user ID cannot be empty")
	}

	// Delete the user (soft delete)
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.User{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}

	// Check if any rows were affected
	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id string) (*user.User, error) {
	if id == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	var userModel models.User
	result := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", id).First(&userModel)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", result.Error)
	}

	// Convert GORM model to domain model
	domainUser := &user.User{
		ID:               userModel.ID,
		Email:            userModel.Email,
		FirstName:        userModel.FirstName,
		LastName:         userModel.LastName,
		PasswordHash:     userModel.PasswordHash,
		OrganizationID:   userModel.OrganizationID,
		Status:           userModel.Status,
		Role:             userModel.Role,
		Profile:          map[string]interface{}(userModel.Profile),
		Settings:         map[string]interface{}(userModel.Settings),
		EmailVerified:    userModel.EmailVerified,
		MFAEnabled:       userModel.MFAEnabled,
		APIKey:           userModel.APIKey,
		APIKeyCreatedAt:  userModel.APIKeyCreatedAt,
		LastLoginAt:      userModel.LastLoginAt,
		LastLoginIP:      userModel.LastLoginIP,
		LoginCount:       userModel.LoginCount,
		FailedLoginAttempts: userModel.FailedLoginAttempts,
		LockedUntil:      userModel.LockedUntil,
		PasswordChangedAt: userModel.PasswordChangedAt,
		CreatedAt:        userModel.CreatedAt,
		UpdatedAt:        userModel.UpdatedAt,
		CreatedBy:        "", // This would come from audit trail
		UpdatedBy:        "", // This would come from audit trail
	}

	return domainUser, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	if email == "" {
		return nil, errors.New("email cannot be empty")
	}

	var userModel models.User
	result := r.db.WithContext(ctx).Where("LOWER(email) = LOWER(?) AND deleted_at IS NULL", email).First(&userModel)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", result.Error)
	}

	// Convert GORM model to domain model
	domainUser := &user.User{
		ID:               userModel.ID,
		Email:            userModel.Email,
		FirstName:        userModel.FirstName,
		LastName:         userModel.LastName,
		PasswordHash:     userModel.PasswordHash,
		OrganizationID:   userModel.OrganizationID,
		Status:           userModel.Status,
		Role:             userModel.Role,
		Profile:          map[string]interface{}(userModel.Profile),
		Settings:         map[string]interface{}(userModel.Settings),
		EmailVerified:    userModel.EmailVerified,
		MFAEnabled:       userModel.MFAEnabled,
		APIKey:           userModel.APIKey,
		APIKeyCreatedAt:  userModel.APIKeyCreatedAt,
		LastLoginAt:      userModel.LastLoginAt,
		LastLoginIP:      userModel.LastLoginIP,
		LoginCount:       userModel.LoginCount,
		FailedLoginAttempts: userModel.FailedLoginAttempts,
		LockedUntil:      userModel.LockedUntil,
		PasswordChangedAt: userModel.PasswordChangedAt,
		CreatedAt:        userModel.CreatedAt,
		UpdatedAt:        userModel.UpdatedAt,
		CreatedBy:        "", // This would come from audit trail
		UpdatedBy:        "", // This would come from audit trail
	}

	return domainUser, nil
}

// GetByTeam retrieves users by team ID
func (r *UserRepository) GetByTeam(ctx context.Context, teamID string) ([]*user.User, error) {
	if teamID == "" {
		return nil, errors.New("team ID cannot be empty")
	}

	// Note: This assumes there's a team_members table or similar to link users to teams
	// For now, we'll look for users with the team ID in their profile or settings
	// This might need to be adjusted based on the actual team membership implementation

	var userModels []models.User
	result := r.db.WithContext(ctx).
		Where("organization_id = ? AND deleted_at IS NULL", teamID).
		Order("created_at DESC").
		Find(&userModels)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to get users by team: %w", result.Error)
	}

	return r.convertUserModelsToDomain(userModels), nil
}

// GetByOrganization retrieves users by organization ID
func (r *UserRepository) GetByOrganization(ctx context.Context, orgID string) ([]*user.User, error) {
	if orgID == "" {
		return nil, errors.New("organization ID cannot be empty")
	}

	var userModels []models.User
	result := r.db.WithContext(ctx).
		Where("organization_id = ? AND deleted_at IS NULL", orgID).
		Order("created_at DESC").
		Find(&userModels)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to get users by organization: %w", result.Error)
	}

	return r.convertUserModelsToDomain(userModels), nil
}

// List retrieves users based on filters
func (r *UserRepository) List(ctx context.Context, filters map[string]interface{}) ([]*user.User, error) {
	var userModels []models.User

	// Start building the query
	query := r.db.WithContext(ctx).Where("deleted_at IS NULL").Order("created_at DESC")

	// Apply filters
	if status, ok := filters["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}

	if orgID, ok := filters["organization_id"].(string); ok && orgID != "" {
		query = query.Where("organization_id = ?", orgID)
	}

	if email, ok := filters["email"].(string); ok && email != "" {
		query = query.Where("email ILIKE ?", "%"+email+"%")
	}

	if role, ok := filters["role"].(string); ok && role != "" {
		query = query.Where("role = ?", role)
	}

	// Execute the query
	result := query.Find(&userModels)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to list users: %w", result.Error)
	}

	return r.convertUserModelsToDomain(userModels), nil
}

// convertUserModelsToDomain converts GORM models to domain models
func (r *UserRepository) convertUserModelsToDomain(userModels []models.User) []*user.User {
	users := make([]*user.User, 0, len(userModels))

	for _, userModel := range userModels {
		domainUser := &user.User{
			ID:               userModel.ID,
			Email:            userModel.Email,
			FirstName:        userModel.FirstName,
			LastName:         userModel.LastName,
			PasswordHash:     userModel.PasswordHash,
			OrganizationID:   userModel.OrganizationID,
			Status:           userModel.Status,
			Role:             userModel.Role,
			Profile:          map[string]interface{}(userModel.Profile),
			Settings:         map[string]interface{}(userModel.Settings),
			EmailVerified:    userModel.EmailVerified,
			MFAEnabled:       userModel.MFAEnabled,
			APIKey:           userModel.APIKey,
			APIKeyCreatedAt:  userModel.APIKeyCreatedAt,
			LastLoginAt:      userModel.LastLoginAt,
			LastLoginIP:      userModel.LastLoginIP,
			LoginCount:       userModel.LoginCount,
			FailedLoginAttempts: userModel.FailedLoginAttempts,
			LockedUntil:      userModel.LockedUntil,
			PasswordChangedAt: userModel.PasswordChangedAt,
			CreatedAt:        userModel.CreatedAt,
			UpdatedAt:        userModel.UpdatedAt,
			CreatedBy:        "", // This would come from audit trail
			UpdatedBy:        "", // This would come from audit trail
		}

		users = append(users, domainUser)
	}

	return users
}