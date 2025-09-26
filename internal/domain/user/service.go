package user

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"n8n-pro/internal/domain/common/errors"
	"n8n-pro/internal/domain/common/events"
	"n8n-pro/internal/domain/common/value_objects"
)

// DomainService encapsulates user business logic that doesn't naturally fit in entities
type DomainService struct {
	repository Repository
	publisher  events.EventPublisher
}

// NewDomainService creates a new user domain service
func NewDomainService(repository Repository, publisher events.EventPublisher) *DomainService {
	return &DomainService{
		repository: repository,
		publisher:  publisher,
	}
}

// CreateUser creates a new user with all business rule validation
func (s *DomainService) CreateUser(ctx context.Context, cmd CreateUserCommand) (*User, error) {
	// Validate email uniqueness
	emailVO, err := value_objects.NewEmail(cmd.Email)
	if err != nil {
		return nil, errors.NewValidationError("email", err.Error())
	}

	exists, err := s.repository.ExistsByEmail(ctx, emailVO)
	if err != nil {
		return nil, fmt.Errorf("failed to check email uniqueness: %w", err)
	}
	if exists {
		return nil, errors.NewConflictError("User", "email", cmd.Email)
	}

	// Validate role
	role, err := value_objects.NewRole(string(cmd.Role))
	if err != nil {
		return nil, errors.NewValidationError("role", err.Error())
	}

	// Create user entity
	user, err := NewUser(cmd.OrganizationID, cmd.Email, cmd.FirstName, cmd.LastName, role)
	if err != nil {
		return nil, err
	}

	// Hash password if provided
	if cmd.Password != "" {
		hashedPassword, err := s.hashPassword(cmd.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		
		// Store hashed password (in a real implementation, you'd have a password field)
		secInfo := user.securityInfo
		secInfo.PasswordChangedAt = time.Now().UTC()
		user.securityInfo = secInfo
	}

	// Set additional profile information
	if cmd.JobTitle != "" || cmd.Department != "" {
		profile := user.profile
		if cmd.JobTitle != "" {
			profile.JobTitle = &cmd.JobTitle
		}
		if cmd.Department != "" {
			profile.Department = &cmd.Department
		}
		user.UpdateProfile(profile)
	}

	// Save user
	if err := s.repository.Save(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Publish domain events
	if s.publisher != nil && len(user.DomainEvents()) > 0 {
		if err := s.publisher.Publish(ctx, user.DomainEvents()...); err != nil {
			// Log error but don't fail the operation
			// In a real app, you might use a saga or outbox pattern
			fmt.Printf("Failed to publish user events: %v\n", err)
		}
		user.ClearDomainEvents()
	}

	return user, nil
}

// ValidatePasswordStrength validates password according to business rules
func (s *DomainService) ValidatePasswordStrength(password string) error {
	_, err := value_objects.NewPassword(password)
	return err
}

// GenerateMFASecret generates a new MFA secret for a user
func (s *DomainService) GenerateMFASecret() (string, error) {
	// Generate 32-byte random secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	// Encode as base32 (standard for TOTP)
	return strings.ToUpper(base32.StdEncoding.EncodeToString(secret)), nil
}

// GenerateMFABackupCodes generates backup codes for MFA
func (s *DomainService) GenerateMFABackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	
	for i := 0; i < count; i++ {
		// Generate 8-byte random code
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		
		// Format as hex string
		codes[i] = fmt.Sprintf("%X", bytes)
	}
	
	return codes, nil
}

// VerifyPasswordComplexity checks if password meets organization policies
func (s *DomainService) VerifyPasswordComplexity(password string, organizationPolicies map[string]interface{}) error {
	// Start with basic validation
	if err := s.ValidatePasswordStrength(password); err != nil {
		return err
	}

	// Apply organization-specific policies
	if minLength, ok := organizationPolicies["min_length"].(int); ok {
		if len(password) < minLength {
			return errors.NewValidationError("password", fmt.Sprintf("password must be at least %d characters long", minLength))
		}
	}

	if requireNumbers, ok := organizationPolicies["require_numbers"].(bool); ok && requireNumbers {
		hasNumber := false
		for _, char := range password {
			if char >= '0' && char <= '9' {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return errors.NewValidationError("password", "password must contain at least one number")
		}
	}

	if requireSymbols, ok := organizationPolicies["require_symbols"].(bool); ok && requireSymbols {
		hasSymbol := false
		symbols := "!@#$%^&*(),.?\":{}|<>"
		for _, char := range password {
			if strings.ContainsRune(symbols, char) {
				hasSymbol = true
				break
			}
		}
		if !hasSymbol {
			return errors.NewValidationError("password", "password must contain at least one special character")
		}
	}

	return nil
}

// CanUserPerformAction checks if a user can perform a specific action based on business rules
func (s *DomainService) CanUserPerformAction(ctx context.Context, userID value_objects.ID, action string, resource string) (bool, error) {
	user, err := s.repository.FindByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to find user: %w", err)
	}

	if user == nil {
		return false, errors.NewNotFoundError("User", userID.Value())
	}

	// Check basic user status
	if !user.IsActive() {
		return false, nil
	}

	if user.IsLocked() {
		return false, nil
	}

	// Apply business rules based on action and resource
	switch {
	case strings.HasPrefix(action, "admin:"):
		return user.Role().IsAdmin(), nil
	case strings.HasPrefix(action, "owner:"):
		return user.Role().HasPermission(value_objects.RoleOwner), nil
	case action == "workflow:execute" && resource != "":
		// Check if user can execute workflows in their organization
		return user.CanPerformAction("execute_workflow"), nil
	case action == "credential:create":
		// Users can create credentials if they can create workflows
		return user.CanPerformAction("create_workflow"), nil
	default:
		return user.CanPerformAction(action), nil
	}
}

// IsEmailAvailable checks if an email address is available for registration
func (s *DomainService) IsEmailAvailable(ctx context.Context, email string) (bool, error) {
	emailVO, err := value_objects.NewEmail(email)
	if err != nil {
		return false, errors.NewValidationError("email", err.Error())
	}

	exists, err := s.repository.ExistsByEmail(ctx, emailVO)
	if err != nil {
		return false, fmt.Errorf("failed to check email availability: %w", err)
	}

	return !exists, nil
}

// GetOrganizationStats returns statistics about users in an organization
func (s *DomainService) GetOrganizationStats(ctx context.Context, organizationID value_objects.ID) (*OrganizationUserStats, error) {
	// Get all users in organization
	users, err := s.repository.FindByOrganization(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to find users in organization: %w", err)
	}

	stats := &OrganizationUserStats{
		TotalUsers:    int64(len(users)),
		ActiveUsers:   0,
		InactiveUsers: 0,
		PendingUsers:  0,
		AdminUsers:    0,
		MFAEnabledUsers: 0,
		RoleBreakdown: make(map[string]int64),
	}

	for _, user := range users {
		// Count by status
		switch user.Status() {
		case StatusActive:
			stats.ActiveUsers++
		case StatusInactive:
			stats.InactiveUsers++
		case StatusPending:
			stats.PendingUsers++
		}

		// Count admins
		if user.Role().IsAdmin() {
			stats.AdminUsers++
		}

		// Count MFA enabled
		if user.SecurityInfo().MFAEnabled {
			stats.MFAEnabledUsers++
		}

		// Count by role
		role := user.Role().String()
		stats.RoleBreakdown[role]++
	}

	return stats, nil
}

// Helper methods
func (s *DomainService) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (s *DomainService) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// OrganizationUserStats represents user statistics for an organization
type OrganizationUserStats struct {
	TotalUsers      int64            `json:"total_users"`
	ActiveUsers     int64            `json:"active_users"`
	InactiveUsers   int64            `json:"inactive_users"`
	PendingUsers    int64            `json:"pending_users"`
	AdminUsers      int64            `json:"admin_users"`
	MFAEnabledUsers int64            `json:"mfa_enabled_users"`
	RoleBreakdown   map[string]int64 `json:"role_breakdown"`
}