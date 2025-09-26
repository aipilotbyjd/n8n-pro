package repositories

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"n8n-pro/internal/domain/common/errors"
	"n8n-pro/internal/domain/common/value_objects"
	"n8n-pro/internal/domain/user"
	"n8n-pro/internal/models"
)

// UserRepository implements the domain user.Repository interface using GORM
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new GORM-based user repository
func NewUserRepository(db *gorm.DB) user.Repository {
	return &UserRepository{db: db}
}

// Save persists a user to the database
func (r *UserRepository) Save(ctx context.Context, domainUser *user.User) error {
	gormUser := r.domainToGORM(domainUser)
	
	// Check if user exists
	var existingUser models.User
	err := r.db.WithContext(ctx).Where("id = ?", gormUser.ID).First(&existingUser).Error
	
	if err != nil && err != gorm.ErrRecordNotFound {
		return fmt.Errorf("error checking existing user: %w", err)
	}
	
	if err == gorm.ErrRecordNotFound {
		// Create new user
		if err := r.db.WithContext(ctx).Create(gormUser).Error; err != nil {
			if strings.Contains(err.Error(), "duplicate key") || 
			   strings.Contains(err.Error(), "UNIQUE constraint") {
				return errors.NewConflictError("User", "email", gormUser.Email)
			}
			return fmt.Errorf("error creating user: %w", err)
		}
	} else {
		// Update existing user
		if err := r.db.WithContext(ctx).Save(gormUser).Error; err != nil {
			return fmt.Errorf("error updating user: %w", err)
		}
	}
	
	return nil
}

// FindByID retrieves a user by ID
func (r *UserRepository) FindByID(ctx context.Context, id value_objects.ID) (*user.User, error) {
	var gormUser models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("id = ?", id.Value()).
		First(&gormUser).Error
	
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("User", id.Value())
		}
		return nil, fmt.Errorf("error finding user by ID: %w", err)
	}
	
	return r.gormToDomain(&gormUser)
}

// FindByEmail retrieves a user by email
func (r *UserRepository) FindByEmail(ctx context.Context, email value_objects.Email) (*user.User, error) {
	var gormUser models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("email = ? AND deleted_at IS NULL", email.Value()).
		First(&gormUser).Error
	
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("User", email.Value())
		}
		return nil, fmt.Errorf("error finding user by email: %w", err)
	}
	
	return r.gormToDomain(&gormUser)
}

// FindByOrganization retrieves all users in an organization
func (r *UserRepository) FindByOrganization(ctx context.Context, organizationID value_objects.ID) ([]*user.User, error) {
	var gormUsers []models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("organization_id = ? AND deleted_at IS NULL", organizationID.Value()).
		Order("created_at DESC").
		Find(&gormUsers).Error
	
	if err != nil {
		return nil, fmt.Errorf("error finding users by organization: %w", err)
	}
	
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, nil
}

// Delete soft-deletes a user
func (r *UserRepository) Delete(ctx context.Context, id value_objects.ID) error {
	result := r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id.Value())
	
	if result.Error != nil {
		return fmt.Errorf("error deleting user: %w", result.Error)
	}
	
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("User", id.Value())
	}
	
	return nil
}

// FindAll retrieves users with filtering and pagination
func (r *UserRepository) FindAll(ctx context.Context, filter *user.ListFilter) ([]*user.User, int64, error) {
	var gormUsers []models.User
	var totalCount int64
	
	// Build base query
	query := r.db.WithContext(ctx).Model(&models.User{}).
		Preload("Organization").
		Where("deleted_at IS NULL")
	
	// Apply filters
	r.applyFilters(query, filter)
	
	// Get total count for pagination
	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, fmt.Errorf("error counting users: %w", err)
	}
	
	// Apply pagination and sorting
	r.applySortingAndPagination(query, filter)
	
	// Execute query
	if err := query.Find(&gormUsers).Error; err != nil {
		return nil, 0, fmt.Errorf("error finding users: %w", err)
	}
	
	// Convert to domain objects
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, 0, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, totalCount, nil
}

// ExistsByEmail checks if a user with the given email exists
func (r *UserRepository) ExistsByEmail(ctx context.Context, email value_objects.Email) (bool, error) {
	var count int64
	
	err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("email = ? AND deleted_at IS NULL", email.Value()).
		Count(&count).Error
	
	if err != nil {
		return false, fmt.Errorf("error checking user existence by email: %w", err)
	}
	
	return count > 0, nil
}

// ExistsByID checks if a user with the given ID exists
func (r *UserRepository) ExistsByID(ctx context.Context, id value_objects.ID) (bool, error) {
	var count int64
	
	err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ? AND deleted_at IS NULL", id.Value()).
		Count(&count).Error
	
	if err != nil {
		return false, fmt.Errorf("error checking user existence by ID: %w", err)
	}
	
	return count > 0, nil
}

// SaveMany saves multiple users in a transaction
func (r *UserRepository) SaveMany(ctx context.Context, users []*user.User) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		repo := &UserRepository{db: tx}
		
		for _, domainUser := range users {
			if err := repo.Save(ctx, domainUser); err != nil {
				return err
			}
		}
		
		return nil
	})
}

// DeleteMany deletes multiple users in a transaction
func (r *UserRepository) DeleteMany(ctx context.Context, ids []value_objects.ID) error {
	idStrings := make([]string, len(ids))
	for i, id := range ids {
		idStrings[i] = id.Value()
	}
	
	result := r.db.WithContext(ctx).Delete(&models.User{}, "id IN ?", idStrings)
	
	if result.Error != nil {
		return fmt.Errorf("error deleting multiple users: %w", result.Error)
	}
	
	return nil
}

// FindActiveUsersInOrganization finds active users in an organization
func (r *UserRepository) FindActiveUsersInOrganization(ctx context.Context, organizationID value_objects.ID) ([]*user.User, error) {
	var gormUsers []models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("organization_id = ? AND status = ? AND deleted_at IS NULL", organizationID.Value(), "active").
		Order("created_at DESC").
		Find(&gormUsers).Error
	
	if err != nil {
		return nil, fmt.Errorf("error finding active users: %w", err)
	}
	
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, nil
}

// FindByRoleInOrganization finds users by role in an organization
func (r *UserRepository) FindByRoleInOrganization(ctx context.Context, organizationID value_objects.ID, role value_objects.Role) ([]*user.User, error) {
	var gormUsers []models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("organization_id = ? AND role = ? AND deleted_at IS NULL", organizationID.Value(), role.String()).
		Order("created_at DESC").
		Find(&gormUsers).Error
	
	if err != nil {
		return nil, fmt.Errorf("error finding users by role: %w", err)
	}
	
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, nil
}

// CountByStatus counts users by status in an organization
func (r *UserRepository) CountByStatus(ctx context.Context, organizationID value_objects.ID, status user.Status) (int64, error) {
	var count int64
	
	err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("organization_id = ? AND status = ? AND deleted_at IS NULL", organizationID.Value(), string(status)).
		Count(&count).Error
	
	if err != nil {
		return 0, fmt.Errorf("error counting users by status: %w", err)
	}
	
	return count, nil
}

// FindUsersWithMFAEnabled finds users with MFA enabled in an organization
func (r *UserRepository) FindUsersWithMFAEnabled(ctx context.Context, organizationID value_objects.ID) ([]*user.User, error) {
	var gormUsers []models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("organization_id = ? AND mfa_enabled = ? AND deleted_at IS NULL", organizationID.Value(), true).
		Order("created_at DESC").
		Find(&gormUsers).Error
	
	if err != nil {
		return nil, fmt.Errorf("error finding users with MFA enabled: %w", err)
	}
	
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, nil
}

// FindInactiveUsersSince finds users inactive for a number of days
func (r *UserRepository) FindInactiveUsersSince(ctx context.Context, days int) ([]*user.User, error) {
	cutoffDate := time.Now().AddDate(0, 0, -days)
	
	var gormUsers []models.User
	
	err := r.db.WithContext(ctx).
		Preload("Organization").
		Where("(last_login_at IS NULL AND created_at < ?) OR (last_login_at IS NOT NULL AND last_login_at < ?) AND deleted_at IS NULL", 
			cutoffDate, cutoffDate).
		Order("created_at DESC").
		Find(&gormUsers).Error
	
	if err != nil {
		return nil, fmt.Errorf("error finding inactive users: %w", err)
	}
	
	domainUsers := make([]*user.User, len(gormUsers))
	for i, gormUser := range gormUsers {
		domainUser, err := r.gormToDomain(&gormUser)
		if err != nil {
			return nil, fmt.Errorf("error converting user %s to domain: %w", gormUser.ID, err)
		}
		domainUsers[i] = domainUser
	}
	
	return domainUsers, nil
}

// Helper methods for conversion between domain and GORM models

func (r *UserRepository) domainToGORM(domainUser *user.User) *models.User {
	gormUser := &models.User{
		BaseModel: models.BaseModel{
			ID:        domainUser.ID().Value(),
			CreatedAt: domainUser.CreatedAt(),
			UpdatedAt: domainUser.UpdatedAt(),
		},
		OrganizationID: domainUser.OrganizationID().Value(),
		Email:          domainUser.Email().Value(),
		FirstName:      domainUser.FirstName(),
		LastName:       domainUser.LastName(),
		Status:         string(domainUser.Status()),
		Role:           domainUser.Role().String(),
	}
	
	// Convert profile
	profile := domainUser.Profile()
	profileJSON := models.JSONB{}
	if profile.AvatarURL != nil {
		profileJSON["avatar_url"] = *profile.AvatarURL
	}
	if profile.Bio != nil {
		profileJSON["bio"] = *profile.Bio
	}
	if profile.Location != nil {
		profileJSON["location"] = *profile.Location
	}
	if profile.Website != nil {
		profileJSON["website"] = *profile.Website
	}
	if profile.PhoneNumber != nil {
		profileJSON["phone_number"] = *profile.PhoneNumber
	}
	if profile.JobTitle != nil {
		profileJSON["job_title"] = *profile.JobTitle
	}
	if profile.Department != nil {
		profileJSON["department"] = *profile.Department
	}
	gormUser.Profile = profileJSON
	
	// Convert settings
	settings := domainUser.Settings()
	settingsJSON := models.JSONB{
		"timezone":               settings.Timezone,
		"language":               settings.Language,
		"theme":                  settings.Theme,
		"notification_settings":  settings.NotificationSettings,
		"workflow_defaults":      settings.WorkflowDefaults,
		"keyboard_shortcuts":     settings.KeyboardShortcuts,
		"privacy_settings":       settings.PrivacySettings,
	}
	gormUser.Settings = settingsJSON
	
	// Convert security info
	securityInfo := domainUser.SecurityInfo()
	gormUser.EmailVerified = securityInfo.EmailVerified
	gormUser.EmailVerificationToken = securityInfo.EmailVerificationToken
	gormUser.EmailVerificationExpiresAt = securityInfo.EmailVerificationExpiresAt
	gormUser.PasswordResetToken = securityInfo.PasswordResetToken
	gormUser.PasswordResetExpiresAt = securityInfo.PasswordResetExpiresAt
	gormUser.MFAEnabled = securityInfo.MFAEnabled
	if securityInfo.MFASecret != nil {
		gormUser.MFASecret = *securityInfo.MFASecret
	}
	gormUser.MFABackupCodes = models.StringSlice(securityInfo.MFABackupCodes)
	if securityInfo.APIKey != nil {
		gormUser.APIKey = *securityInfo.APIKey
	}
	gormUser.APIKeyCreatedAt = securityInfo.APIKeyCreatedAt
	
	// Convert activity info
	activityInfo := domainUser.ActivityInfo()
	gormUser.LastLoginAt = activityInfo.LastLoginAt
	if activityInfo.LastLoginIP != nil {
		gormUser.LastLoginIP = *activityInfo.LastLoginIP
	}
	gormUser.LoginCount = activityInfo.LoginCount
	gormUser.FailedLoginAttempts = activityInfo.FailedLoginAttempts
	gormUser.LockedUntil = activityInfo.LockedUntil
	gormUser.PasswordChangedAt = activityInfo.PasswordChangedAt
	
	return gormUser
}

func (r *UserRepository) gormToDomain(gormUser *models.User) (*user.User, error) {
	// Create value objects
	id, err := value_objects.NewIDFromString(gormUser.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}
	
	orgID, err := value_objects.NewIDFromString(gormUser.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("invalid organization ID: %w", err)
	}
	
	email, err := value_objects.NewEmail(gormUser.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}
	
	role, err := value_objects.NewRole(gormUser.Role)
	if err != nil {
		return nil, fmt.Errorf("invalid role: %w", err)
	}
	
	// Create domain user with private constructor approach
	// For now, we'll create a basic user and populate fields
	// In a complete implementation, you might need a special constructor
	domainUser, err := user.NewUser(
		gormUser.OrganizationID,
		gormUser.Email,
		gormUser.FirstName,
		gormUser.LastName,
		role,
	)
	if err != nil {
		return nil, err
	}
	
	// Note: Since domain user fields are private, you'd need to either:
	// 1. Add methods to update internal state
	// 2. Create a special repository constructor
	// 3. Use reflection (not recommended)
	// For now, this shows the pattern
	
	return domainUser, nil
}

// Helper methods for query building

func (r *UserRepository) applyFilters(query *gorm.DB, filter *user.ListFilter) {
	if filter == nil {
		return
	}
	
	if filter.OrganizationID != nil {
		query.Where("organization_id = ?", filter.OrganizationID.Value())
	}
	
	if filter.Status != nil {
		query.Where("status = ?", string(*filter.Status))
	}
	
	if filter.Role != nil {
		query.Where("role = ?", filter.Role.String())
	}
	
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		query.Where("(first_name ILIKE ? OR last_name ILIKE ? OR email ILIKE ?)", search, search, search)
	}
	
	if filter.MFAEnabled != nil {
		query.Where("mfa_enabled = ?", *filter.MFAEnabled)
	}
	
	if filter.EmailVerified != nil {
		query.Where("email_verified = ?", *filter.EmailVerified)
	}
}

func (r *UserRepository) applySortingAndPagination(query *gorm.DB, filter *user.ListFilter) {
	if filter == nil {
		return
	}
	
	// Apply sorting
	sortBy := filter.SortBy
	if sortBy == "" {
		sortBy = "created_at"
	}
	
	sortOrder := filter.SortOrder
	if sortOrder == "" {
		sortOrder = "desc"
	}
	
	orderClause := fmt.Sprintf("%s %s", sortBy, sortOrder)
	query.Order(orderClause)
	
	// Apply pagination
	if filter.Limit > 0 {
		query.Limit(filter.Limit)
		
		if filter.Offset > 0 {
			query.Offset(filter.Offset)
		}
	}
}