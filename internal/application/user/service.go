package user

import (
	"context"

	"n8n-pro/internal/domain/user"
	"n8n-pro/pkg/logger"
)

// ApplicationService represents the user application service
type ApplicationService struct {
	userService *user.Service
	logger      logger.Logger
}

// NewApplicationService creates a new user application service
func NewApplicationService(
	userService *user.Service,
	logger logger.Logger,
) *ApplicationService {
	return &ApplicationService{
		userService: userService,
		logger:      logger,
	}
}

// CreateUser creates a new user
func (s *ApplicationService) CreateUser(ctx context.Context, user *user.User) error {
	s.logger.Info("Creating user", "email", user.Email)

	if err := s.userService.Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user", "error", err, "email", user.Email)
		return err
	}

	s.logger.Info("User created successfully", "id", user.ID, "email", user.Email)
	return nil
}

// GetUserByID retrieves a user by ID
func (s *ApplicationService) GetUserByID(ctx context.Context, id string) (*user.User, error) {
	s.logger.Info("Retrieving user", "id", id)

	user, err := s.userService.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to retrieve user", "error", err, "id", id)
		return nil, err
	}

	s.logger.Info("User retrieved successfully", "id", id)
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *ApplicationService) GetUserByEmail(ctx context.Context, email string) (*user.User, error) {
	s.logger.Info("Retrieving user by email", "email", email)

	user, err := s.userService.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Failed to retrieve user by email", "error", err, "email", email)
		return nil, err
	}

	s.logger.Info("User retrieved successfully", "email", email)
	return user, nil
}

// UpdateUser updates an existing user
func (s *ApplicationService) UpdateUser(ctx context.Context, user *user.User) error {
	s.logger.Info("Updating user", "id", user.ID, "email", user.Email)

	if err := s.userService.Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user", "error", err, "id", user.ID)
		return err
	}

	s.logger.Info("User updated successfully", "id", user.ID)
	return nil
}

// DeleteUser deletes a user by ID
func (s *ApplicationService) DeleteUser(ctx context.Context, id string) error {
	s.logger.Info("Deleting user", "id", id)

	if err := s.userService.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete user", "error", err, "id", id)
		return err
	}

	s.logger.Info("User deleted successfully", "id", id)
	return nil
}

// ListUsers retrieves users based on filters
func (s *ApplicationService) ListUsers(ctx context.Context, filters map[string]interface{}) ([]*user.User, error) {
	s.logger.Info("Listing users", "filters", filters)

	users, err := s.userService.List(ctx, filters)
	if err != nil {
		s.logger.Error("Failed to list users", "error", err)
		return nil, err
	}

	s.logger.Info("Users listed successfully", "count", len(users))
	return users, nil
}