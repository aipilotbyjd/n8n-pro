package user

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// NewUser creates a new user instance
func NewUser(email, firstName, lastName, organizationID, teamID string) *User {
	id := uuid.New().String()
	apiKey := "n8n_" + uuid.New().String()
	now := time.Now()

	return &User{
		ID:               id,
		Email:            email,
		FirstName:        firstName,
		LastName:         lastName,
		OrganizationID:   organizationID,
		TeamID:           teamID,
		Status:           "pending",
		Role:             "member",
		Profile:          make(map[string]interface{}),
		Settings:         make(map[string]interface{}),
		EmailVerified:    false,
		LoginCount:       0,
		FailedLoginAttempts: 0,
		PasswordChangedAt: now,
		CreatedAt:       now,
		UpdatedAt:       now,
		CreatedBy:       id, // User creates themselves
		UpdatedBy:       id,
		APIKey:          apiKey,
		APIKeyCreatedAt: &now,
	}
}

// Repository interface for user data access
type Repository interface {
	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByTeam(ctx context.Context, teamID string) ([]*User, error)
	GetByOrganization(ctx context.Context, orgID string) ([]*User, error)
	List(ctx context.Context, filters map[string]interface{}) ([]*User, error)
}

// Service represents the user domain service
type Service struct {
	repo Repository
}

// NewService creates a new user service
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
	}
}

// Create creates a new user
func (s *Service) Create(ctx context.Context, user *User) error {
	if user == nil {
		return ValidationError("user cannot be nil")
	}

	// Validate user
	if err := user.Validate(); err != nil {
		return err
	}

	// Set default values if not provided
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now

	// Create the user
	return s.repo.Create(ctx, user)
}

// GetByID retrieves a user by ID
func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, ValidationError("user ID cannot be empty")
	}

	return s.repo.GetByID(ctx, id)
}

// GetByEmail retrieves a user by email
func (s *Service) GetByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, ValidationError("email cannot be empty")
	}

	return s.repo.GetByEmail(ctx, email)
}

// Update updates an existing user
func (s *Service) Update(ctx context.Context, user *User) error {
	if user == nil {
		return ValidationError("user cannot be nil")
	}

	if user.ID == "" {
		return ValidationError("user ID cannot be empty")
	}

	// Update timestamp
	user.UpdatedAt = time.Now()

	return s.repo.Update(ctx, user)
}

// Delete deletes a user by ID
func (s *Service) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ValidationError("user ID cannot be empty")
	}

	return s.repo.Delete(ctx, id)
}

// List retrieves users based on filters
func (s *Service) List(ctx context.Context, filters map[string]interface{}) ([]*User, error) {
	return s.repo.List(ctx, filters)
}