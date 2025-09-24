package auth

import (
	"context"
	"testing"
	"time"

	"n8n-pro/pkg/errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthRepository for testing
type MockAuthRepository struct {
	mock.Mock
}

func (m *MockAuthRepository) CreateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockAuthRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockAuthRepository) UpdateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthRepository) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockAuthRepository) ListUsers(ctx context.Context, teamID string) ([]*User, error) {
	args := m.Called(ctx, teamID)
	return args.Get(0).([]*User), args.Error(1)
}

func (m *MockAuthRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockAuthRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func TestAuthService(t *testing.T) {
	mockRepo := &MockAuthRepository{}
	service := NewService(mockRepo)
	ctx := context.Background()

	t.Run("CreateUser successful", func(t *testing.T) {
		user := &User{
			ID:     uuid.New().String(),
			Email:  "test@example.com",
			Name:   "Test User",
			TeamID: uuid.New().String(),
		}

		mockRepo.On("CreateUser", ctx, user).Return(nil)

		err := service.CreateUser(ctx, user)

		require.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("GetUserByID successful", func(t *testing.T) {
		user := &User{
			ID:    uuid.New().String(),
			Email: "test@example.com",
			Name:  "Test User",
		}

		mockRepo.On("GetUserByID", ctx, user.ID).Return(user, nil)

		result, err := service.GetUserByID(ctx, user.ID)

		require.NoError(t, err)
		assert.Equal(t, user.ID, result.ID)
		assert.Equal(t, user.Email, result.Email)
		mockRepo.AssertExpectations(t)
	})

	t.Run("GetUserByEmail successful", func(t *testing.T) {
		user := &User{
			ID:    uuid.New().String(),
			Email: "test@example.com",
		}

		mockRepo.On("GetUserByEmail", ctx, user.Email).Return(user, nil)

		result, err := service.GetUserByEmail(ctx, user.Email)

		require.NoError(t, err)
		assert.Equal(t, user.Email, result.Email)
		mockRepo.AssertExpectations(t)
	})

	t.Run("UpdateUser successful", func(t *testing.T) {
		user := &User{
			ID:   uuid.New().String(),
			Name: "Updated Name",
		}

		mockRepo.On("UpdateUser", ctx, user).Return(nil)

		err := service.UpdateUser(ctx, user)

		require.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("DeleteUser successful", func(t *testing.T) {
		userID := uuid.New().String()

		mockRepo.On("DeleteUser", ctx, userID).Return(nil)

		err := service.DeleteUser(ctx, userID)

		require.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("ListUsers successful", func(t *testing.T) {
		teamID := uuid.New().String()
		users := []*User{
			{ID: uuid.New().String(), Email: "user1@example.com"},
			{ID: uuid.New().String(), Email: "user2@example.com"},
		}

		mockRepo.On("ListUsers", ctx, teamID).Return(users, nil)

		result, err := service.ListUsers(ctx, teamID)

		require.NoError(t, err)
		assert.Len(t, result, 2)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserModel(t *testing.T) {
	t.Run("User creation with valid data", func(t *testing.T) {
		user := &User{
			ID:        uuid.New().String(),
			Email:     "test@example.com",
			Name:      "Test User",
			Password:  "hashed_password",
			Active:    true,
			TeamID:    uuid.New().String(),
			Role:      "admin",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.Name)
		assert.True(t, user.Active)
		assert.Equal(t, "admin", user.Role)
	})
}

func TestPostgresRepository(t *testing.T) {
	repo := NewPostgresRepository(nil) // Pass nil DB for testing stubs
	ctx := context.Background()

	t.Run("CreateUser returns not implemented", func(t *testing.T) {
		user := &User{ID: "test"}
		err := repo.CreateUser(ctx, user)

		assert.Error(t, err)
		appErr := errors.GetAppError(err)
		require.NotNil(t, appErr)
		assert.Equal(t, errors.ErrorTypeValidation, appErr.Type)
		assert.Equal(t, errors.CodeInvalidInput, appErr.Code)
	})

	t.Run("ListUsers returns empty list", func(t *testing.T) {
		// Skip this test since it requires a real database connection
		t.Skip("Skipping test that requires database connection")
	})
}
