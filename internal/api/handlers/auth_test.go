package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n8n-pro/internal/api/handlers"
	"n8n-pro/internal/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/common"
	"n8n-pro/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockAuthService mocks the auth service
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) CreateUser(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthService) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthService) UpdateUser(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthService) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockAuthService) ListUsers(ctx context.Context, teamID string) ([]*auth.User, error) {
	args := m.Called(ctx, teamID)
	return args.Get(0).([]*auth.User), args.Error(1)
}

func (m *MockAuthService) UpdateLastLogin(ctx context.Context, userID, ipAddress string) error {
	args := m.Called(ctx, userID, ipAddress)
	return args.Error(0)
}

func (m *MockAuthService) IncrementFailedLogin(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthService) IsAccountLocked(ctx context.Context, userID string) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthService) SetEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) VerifyEmail(ctx context.Context, token string) (*auth.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthService) SetPasswordResetToken(ctx context.Context, email string) (string, error) {
	args := m.Called(ctx, email)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ResetPassword(ctx context.Context, token, newPassword string) (*auth.User, error) {
	args := m.Called(ctx, token, newPassword)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func TestAuthHandler_Register(t *testing.T) {
	// Setup
	mockAuthService := &MockAuthService{}
	jwtConfig := &jwt.Config{
		Secret:               "test-secret",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:              "n8n-pro-test",
		Audience:            "n8n-pro-users",
	}
	jwtService := jwt.NewService(jwtConfig)
	logger := logger.New("test")
	
	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful registration", func(t *testing.T) {
		// Setup mocks
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, assert.AnError)
		mockAuthService.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).Return(nil)
		mockAuthService.On("SetEmailVerificationToken", mock.Anything, mock.AnythingOfType("string")).Return("verification-token", nil)

		// Create request
		reqBody := map[string]string{
			"name":     "Test User",
			"email":    "test@example.com",
			"password": "testpassword123",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.Register(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "User registered successfully. Please check your email for verification.", response["message"])
		assert.NotEmpty(t, response["user_id"])
		assert.Equal(t, "test@example.com", response["email"])
		assert.Equal(t, "Test User", response["name"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("registration with existing email", func(t *testing.T) {
		// Setup mocks
		existingUser := &auth.User{
			ID:    "existing-user-id",
			Email: "test@example.com",
			Name:  "Existing User",
		}
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

		// Create request
		reqBody := map[string]string{
			"name":     "Test User",
			"email":    "test@example.com",
			"password": "testpassword123",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.Register(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	// Setup
	mockAuthService := &MockAuthService{}
	jwtConfig := &jwt.Config{
		Secret:               "test-secret",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:              "n8n-pro-test",
		Audience:            "n8n-pro-users",
	}
	jwtService := jwt.NewService(jwtConfig)
	logger := logger.New("test")
	
	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful login", func(t *testing.T) {
		// Create user with hashed password
		password := "testpassword123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		
		user := &auth.User{
			ID:       "user-id",
			Email:    "test@example.com",
			Name:     "Test User",
			Password: string(hashedPassword),
			Active:   true,
			TeamID:   "team-id",
			Role:     "admin",
		}

		// Setup mocks
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		mockAuthService.On("IsAccountLocked", mock.Anything, "user-id").Return(false, nil)
		mockAuthService.On("UpdateLastLogin", mock.Anything, "user-id", mock.AnythingOfType("string")).Return(nil)

		// Create request
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": password,
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.Login(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotEmpty(t, response["access_token"])
		assert.NotEmpty(t, response["refresh_token"])
		assert.Equal(t, "Bearer", response["token_type"])
		assert.NotNil(t, response["user"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("login with invalid password", func(t *testing.T) {
		// Create user with hashed password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
		
		user := &auth.User{
			ID:       "user-id",
			Email:    "test@example.com",
			Password: string(hashedPassword),
			Active:   true,
		}

		// Setup mocks
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		mockAuthService.On("IsAccountLocked", mock.Anything, "user-id").Return(false, nil)
		mockAuthService.On("IncrementFailedLogin", mock.Anything, "user-id").Return(nil)

		// Create request with wrong password
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": "wrongpassword",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.Login(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("login with locked account", func(t *testing.T) {
		user := &auth.User{
			ID:     "user-id",
			Email:  "test@example.com",
			Active: true,
		}

		// Setup mocks
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		mockAuthService.On("IsAccountLocked", mock.Anything, "user-id").Return(true, nil)

		// Create request
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": "testpassword123",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.Login(w, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_ForgotPassword(t *testing.T) {
	// Setup
	mockAuthService := &MockAuthService{}
	jwtConfig := &jwt.Config{
		Secret:               "test-secret",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:              "n8n-pro-test",
		Audience:            "n8n-pro-users",
	}
	jwtService := jwt.NewService(jwtConfig)
	logger := logger.New("test")
	
	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful password reset request", func(t *testing.T) {
		user := &auth.User{
			ID:     "user-id",
			Email:  "test@example.com",
			Active: true,
		}

		// Setup mocks
		mockAuthService.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		mockAuthService.On("SetPasswordResetToken", mock.Anything, "test@example.com").Return("reset-token", nil)

		// Create request
		reqBody := map[string]string{
			"email": "test@example.com",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.ForgotPassword(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Password reset link has been sent to your email", response["message"])

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_ResetPassword(t *testing.T) {
	// Setup
	mockAuthService := &MockAuthService{}
	jwtConfig := &jwt.Config{
		Secret:               "test-secret",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:              "n8n-pro-test",
		Audience:            "n8n-pro-users",
	}
	jwtService := jwt.NewService(jwtConfig)
	logger := logger.New("test")
	
	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful password reset", func(t *testing.T) {
		user := &auth.User{
			ID:    "user-id",
			Email: "test@example.com",
		}

		// Setup mocks
		mockAuthService.On("ResetPassword", mock.Anything, "valid-token", mock.AnythingOfType("string")).Return(user, nil)

		// Create request
		reqBody := map[string]string{
			"token":        "valid-token",
			"new_password": "newpassword123",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()

		// Execute
		handler.ResetPassword(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Password has been reset successfully", response["message"])
		assert.Equal(t, "user-id", response["user_id"])

		mockAuthService.AssertExpectations(t)
	})
}