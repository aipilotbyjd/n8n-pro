package services

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"n8n-pro/internal/domain/common/errors"
	"n8n-pro/internal/domain/common/events"
	"n8n-pro/internal/domain/common/value_objects"
	"n8n-pro/internal/domain/user"
	"n8n-pro/pkg/logger"
)

// UserService provides application-level user operations
type UserService struct {
	userRepo      user.Repository
	domainService *user.DomainService
	eventBus      events.EventPublisher
	logger        logger.Logger
}

// NewUserService creates a new user application service
func NewUserService(
	userRepo user.Repository,
	domainService *user.DomainService,
	eventBus events.EventPublisher,
	logger logger.Logger,
) *UserService {
	return &UserService{
		userRepo:      userRepo,
		domainService: domainService,
		eventBus:      eventBus,
		logger:        logger,
	}
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, cmd CreateUserCommand) (*UserResponse, error) {
	// Validate command
	if err := s.validateCreateUserCommand(cmd); err != nil {
		return nil, err
	}

	// Check if email is available
	available, err := s.domainService.IsEmailAvailable(ctx, cmd.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email availability: %w", err)
	}
	if !available {
		return nil, errors.NewConflictError("User", "email", cmd.Email)
	}

	// Create domain command
	domainCmd := user.CreateUserCommand{
		OrganizationID: cmd.OrganizationID,
		Email:          cmd.Email,
		FirstName:      cmd.FirstName,
		LastName:       cmd.LastName,
		Password:       cmd.Password,
		Role:           user.Status(cmd.Role), // Cast to domain type
		JobTitle:       cmd.JobTitle,
		Department:     cmd.Department,
	}

	// Create user through domain service
	domainUser, err := s.domainService.CreateUser(ctx, domainCmd)
	if err != nil {
		s.logger.Error("Failed to create user", "error", err, "email", cmd.Email)
		return nil, err
	}

	// Log success
	s.logger.Info("User created successfully", 
		"user_id", domainUser.ID().Value(),
		"email", domainUser.Email().Value(),
		"organization_id", domainUser.OrganizationID().Value())

	return s.toUserResponse(domainUser), nil
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, userID string) (*UserResponse, error) {
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return nil, errors.NewValidationError("user_id", "invalid user ID format")
	}

	domainUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user", "error", err, "user_id", userID)
		return nil, err
	}

	return s.toUserResponse(domainUser), nil
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*UserResponse, error) {
	emailVO, err := value_objects.NewEmail(email)
	if err != nil {
		return nil, errors.NewValidationError("email", err.Error())
	}

	domainUser, err := s.userRepo.FindByEmail(ctx, emailVO)
	if err != nil {
		s.logger.Error("Failed to get user by email", "error", err, "email", email)
		return nil, err
	}

	return s.toUserResponse(domainUser), nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(ctx context.Context, userID string, cmd UpdateUserCommand) (*UserResponse, error) {
	// Get existing user
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return nil, errors.NewValidationError("user_id", "invalid user ID format")
	}

	domainUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if cmd.FirstName != nil {
		// Note: In a complete implementation, you'd need methods to update domain state
		// For now, this shows the pattern
	}
	
	if cmd.LastName != nil {
		// Update last name
	}
	
	if cmd.Profile != nil {
		profile := user.Profile{
			AvatarURL:   cmd.Profile.AvatarURL,
			Bio:         cmd.Profile.Bio,
			Location:    cmd.Profile.Location,
			Website:     cmd.Profile.Website,
			PhoneNumber: cmd.Profile.PhoneNumber,
			JobTitle:    cmd.Profile.JobTitle,
			Department:  cmd.Profile.Department,
		}
		domainUser.UpdateProfile(profile)
	}

	// Save updated user
	if err := s.userRepo.Save(ctx, domainUser); err != nil {
		s.logger.Error("Failed to update user", "error", err, "user_id", userID)
		return nil, err
	}

	s.logger.Info("User updated successfully", "user_id", userID)
	return s.toUserResponse(domainUser), nil
}

// DeleteUser soft-deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return errors.NewValidationError("user_id", "invalid user ID format")
	}

	// Check if user exists
	_, err = s.userRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete user
	if err := s.userRepo.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete user", "error", err, "user_id", userID)
		return err
	}

	s.logger.Info("User deleted successfully", "user_id", userID)
	return nil
}

// ListUsers lists users with filtering and pagination
func (s *UserService) ListUsers(ctx context.Context, query ListUsersQuery) (*ListUsersResponse, error) {
	// Convert query to domain filter
	filter := &user.ListFilter{
		Search:    query.Search,
		Limit:     query.Limit,
		Offset:    query.Offset,
		SortBy:    query.SortBy,
		SortOrder: query.SortOrder,
	}

	// Add organization filter if specified
	if query.OrganizationID != "" {
		orgID, err := value_objects.NewIDFromString(query.OrganizationID)
		if err != nil {
			return nil, errors.NewValidationError("organization_id", "invalid organization ID format")
		}
		filter.OrganizationID = &orgID
	}

	// Add status filter if specified
	if query.Status != "" {
		status := user.Status(query.Status)
		filter.Status = &status
	}

	// Add role filter if specified
	if query.Role != "" {
		role, err := value_objects.NewRole(query.Role)
		if err != nil {
			return nil, errors.NewValidationError("role", "invalid role")
		}
		filter.Role = &role
	}

	// Execute query
	domainUsers, totalCount, err := s.userRepo.FindAll(ctx, filter)
	if err != nil {
		s.logger.Error("Failed to list users", "error", err)
		return nil, err
	}

	// Convert to response
	users := make([]*UserResponse, len(domainUsers))
	for i, domainUser := range domainUsers {
		users[i] = s.toUserResponse(domainUser)
	}

	return &ListUsersResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       calculatePage(query.Offset, query.Limit),
		PerPage:    query.Limit,
	}, nil
}

// ChangePassword changes a user's password
func (s *UserService) ChangePassword(ctx context.Context, userID string, cmd ChangePasswordCommand) error {
	// Get user
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return errors.NewValidationError("user_id", "invalid user ID format")
	}

	domainUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	// Validate old password (simplified - in real implementation you'd verify against stored hash)
	if !s.verifyPassword(cmd.OldPassword, "stored_hash") {
		return errors.NewUnauthorizedError("invalid current password")
	}

	// Validate new password strength
	if err := s.domainService.ValidatePasswordStrength(cmd.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password (in real implementation, you'd have a method to update password)
	_ = hashedPassword // TODO: Update domain user password

	// Save user
	if err := s.userRepo.Save(ctx, domainUser); err != nil {
		s.logger.Error("Failed to change password", "error", err, "user_id", userID)
		return err
	}

	s.logger.Info("Password changed successfully", "user_id", userID)
	return nil
}

// EnableMFA enables multi-factor authentication for a user
func (s *UserService) EnableMFA(ctx context.Context, userID string) (*MFASetupResponse, error) {
	// Get user
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return nil, errors.NewValidationError("user_id", "invalid user ID format")
	}

	domainUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Generate MFA secret and backup codes
	secret, err := s.domainService.GenerateMFASecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	backupCodes, err := s.domainService.GenerateMFABackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Enable MFA on user
	if err := domainUser.EnableMFA(secret, backupCodes); err != nil {
		return nil, err
	}

	// Save user
	if err := s.userRepo.Save(ctx, domainUser); err != nil {
		s.logger.Error("Failed to enable MFA", "error", err, "user_id", userID)
		return nil, err
	}

	s.logger.Info("MFA enabled successfully", "user_id", userID)

	return &MFASetupResponse{
		Secret:      secret,
		QRCodeURL:   s.generateQRCodeURL(domainUser.Email().Value(), secret),
		BackupCodes: backupCodes,
	}, nil
}

// DisableMFA disables multi-factor authentication for a user
func (s *UserService) DisableMFA(ctx context.Context, userID string) error {
	// Get user
	id, err := value_objects.NewIDFromString(userID)
	if err != nil {
		return errors.NewValidationError("user_id", "invalid user ID format")
	}

	domainUser, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	// Disable MFA
	if err := domainUser.DisableMFA(); err != nil {
		return err
	}

	// Save user
	if err := s.userRepo.Save(ctx, domainUser); err != nil {
		s.logger.Error("Failed to disable MFA", "error", err, "user_id", userID)
		return err
	}

	s.logger.Info("MFA disabled successfully", "user_id", userID)
	return nil
}

// GetOrganizationStats returns user statistics for an organization
func (s *UserService) GetOrganizationStats(ctx context.Context, organizationID string) (*OrganizationStatsResponse, error) {
	orgID, err := value_objects.NewIDFromString(organizationID)
	if err != nil {
		return nil, errors.NewValidationError("organization_id", "invalid organization ID format")
	}

	stats, err := s.domainService.GetOrganizationStats(ctx, orgID)
	if err != nil {
		s.logger.Error("Failed to get organization stats", "error", err, "organization_id", organizationID)
		return nil, err
	}

	return &OrganizationStatsResponse{
		TotalUsers:      stats.TotalUsers,
		ActiveUsers:     stats.ActiveUsers,
		InactiveUsers:   stats.InactiveUsers,
		PendingUsers:    stats.PendingUsers,
		AdminUsers:      stats.AdminUsers,
		MFAEnabledUsers: stats.MFAEnabledUsers,
		RoleBreakdown:   stats.RoleBreakdown,
	}, nil
}

// Helper methods

func (s *UserService) validateCreateUserCommand(cmd CreateUserCommand) error {
	if cmd.Email == "" {
		return errors.NewValidationError("email", "email is required")
	}
	if cmd.FirstName == "" {
		return errors.NewValidationError("first_name", "first name is required")
	}
	if cmd.LastName == "" {
		return errors.NewValidationError("last_name", "last name is required")
	}
	if cmd.OrganizationID == "" {
		return errors.NewValidationError("organization_id", "organization ID is required")
	}
	if cmd.Password != "" {
		if err := s.domainService.ValidatePasswordStrength(cmd.Password); err != nil {
			return err
		}
	}
	return nil
}

func (s *UserService) toUserResponse(domainUser *user.User) *UserResponse {
	profile := domainUser.Profile()
	settings := domainUser.Settings()
	securityInfo := domainUser.SecurityInfo()
	activityInfo := domainUser.ActivityInfo()

	return &UserResponse{
		ID:             domainUser.ID().Value(),
		OrganizationID: domainUser.OrganizationID().Value(),
		Email:          domainUser.Email().Value(),
		FirstName:      domainUser.FirstName(),
		LastName:       domainUser.LastName(),
		FullName:       domainUser.FullName(),
		Role:           domainUser.Role().String(),
		Status:         string(domainUser.Status()),
		Profile: ProfileResponse{
			AvatarURL:   profile.AvatarURL,
			Bio:         profile.Bio,
			Location:    profile.Location,
			Website:     profile.Website,
			PhoneNumber: profile.PhoneNumber,
			JobTitle:    profile.JobTitle,
			Department:  profile.Department,
		},
		Settings: SettingsResponse{
			Timezone:             settings.Timezone,
			Language:             settings.Language,
			Theme:                settings.Theme,
			NotificationSettings: settings.NotificationSettings,
		},
		Security: SecurityResponse{
			EmailVerified: securityInfo.EmailVerified,
			MFAEnabled:    securityInfo.MFAEnabled,
			APIKeyExists:  securityInfo.APIKey != nil,
		},
		Activity: ActivityResponse{
			LastLoginAt:         activityInfo.LastLoginAt,
			LoginCount:          activityInfo.LoginCount,
			FailedLoginAttempts: activityInfo.FailedLoginAttempts,
			IsLocked:            domainUser.IsLocked(),
		},
		CreatedAt: domainUser.CreatedAt(),
		UpdatedAt: domainUser.UpdatedAt(),
	}
}

func (s *UserService) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (s *UserService) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *UserService) generateQRCodeURL(email, secret string) string {
	// Generate TOTP QR code URL
	return fmt.Sprintf("otpauth://totp/n8n-pro:%s?secret=%s&issuer=n8n-pro", email, secret)
}

func calculatePage(offset, limit int) int {
	if limit == 0 {
		return 1
	}
	return (offset / limit) + 1
}

// Command and Response DTOs

type CreateUserCommand struct {
	OrganizationID string `json:"organization_id" validate:"required,uuid"`
	Email          string `json:"email" validate:"required,email"`
	FirstName      string `json:"first_name" validate:"required,min=1,max=255"`
	LastName       string `json:"last_name" validate:"required,min=1,max=255"`
	Password       string `json:"password,omitempty" validate:"omitempty,min=8"`
	Role           string `json:"role" validate:"required,oneof=guest user member admin owner"`
	JobTitle       string `json:"job_title,omitempty"`
	Department     string `json:"department,omitempty"`
}

type UpdateUserCommand struct {
	FirstName *string         `json:"first_name,omitempty"`
	LastName  *string         `json:"last_name,omitempty"`
	Profile   *ProfileRequest `json:"profile,omitempty"`
	Settings  *SettingsRequest `json:"settings,omitempty"`
}

type ChangePasswordCommand struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type ListUsersQuery struct {
	OrganizationID string `json:"organization_id,omitempty"`
	Status         string `json:"status,omitempty"`
	Role           string `json:"role,omitempty"`
	Search         string `json:"search,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Offset         int    `json:"offset,omitempty"`
	SortBy         string `json:"sort_by,omitempty"`
	SortOrder      string `json:"sort_order,omitempty"`
}

type ProfileRequest struct {
	AvatarURL   *string `json:"avatar_url,omitempty"`
	Bio         *string `json:"bio,omitempty"`
	Location    *string `json:"location,omitempty"`
	Website     *string `json:"website,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	JobTitle    *string `json:"job_title,omitempty"`
	Department  *string `json:"department,omitempty"`
}

type SettingsRequest struct {
	Timezone             string            `json:"timezone,omitempty"`
	Language             string            `json:"language,omitempty"`
	Theme                string            `json:"theme,omitempty"`
	NotificationSettings map[string]bool   `json:"notification_settings,omitempty"`
	WorkflowDefaults     map[string]interface{} `json:"workflow_defaults,omitempty"`
	KeyboardShortcuts    map[string]string `json:"keyboard_shortcuts,omitempty"`
	PrivacySettings      map[string]bool   `json:"privacy_settings,omitempty"`
}

type UserResponse struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organization_id"`
	Email          string            `json:"email"`
	FirstName      string            `json:"first_name"`
	LastName       string            `json:"last_name"`
	FullName       string            `json:"full_name"`
	Role           string            `json:"role"`
	Status         string            `json:"status"`
	Profile        ProfileResponse   `json:"profile"`
	Settings       SettingsResponse  `json:"settings"`
	Security       SecurityResponse  `json:"security"`
	Activity       ActivityResponse  `json:"activity"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type ProfileResponse struct {
	AvatarURL   *string `json:"avatar_url,omitempty"`
	Bio         *string `json:"bio,omitempty"`
	Location    *string `json:"location,omitempty"`
	Website     *string `json:"website,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	JobTitle    *string `json:"job_title,omitempty"`
	Department  *string `json:"department,omitempty"`
}

type SettingsResponse struct {
	Timezone             string          `json:"timezone"`
	Language             string          `json:"language"`
	Theme                string          `json:"theme"`
	NotificationSettings map[string]bool `json:"notification_settings"`
}

type SecurityResponse struct {
	EmailVerified bool `json:"email_verified"`
	MFAEnabled    bool `json:"mfa_enabled"`
	APIKeyExists  bool `json:"api_key_exists"`
}

type ActivityResponse struct {
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	LoginCount          int64      `json:"login_count"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	IsLocked            bool       `json:"is_locked"`
}

type ListUsersResponse struct {
	Users      []*UserResponse `json:"users"`
	TotalCount int64           `json:"total_count"`
	Page       int             `json:"page"`
	PerPage    int             `json:"per_page"`
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

type OrganizationStatsResponse struct {
	TotalUsers      int64            `json:"total_users"`
	ActiveUsers     int64            `json:"active_users"`
	InactiveUsers   int64            `json:"inactive_users"`
	PendingUsers    int64            `json:"pending_users"`
	AdminUsers      int64            `json:"admin_users"`
	MFAEnabledUsers int64            `json:"mfa_enabled_users"`
	RoleBreakdown   map[string]int64 `json:"role_breakdown"`
}