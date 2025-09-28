package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n8n-pro/internal/presentation/http/handlers"
	"n8n-pro/internal/application/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthService mocks the auth service interface
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.AuthResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.AuthResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *MockAuthService) VerifyEmail(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) RequestPasswordReset(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *MockAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	args := m.Called(ctx, token, newPassword)
	return args.Error(0)
}

func (m *MockAuthService) Logout(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*jwt.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.TokenPair), args.Error(1)
}

func TestAuthHandler_Register(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful registration", func(t *testing.T) {
		// Setup mock response
		expectedUser := &auth.UserResponse{
			ID:            "user-123",
			Email:         "test@example.com",
			FirstName:     "John",
			LastName:      "Doe",
			Status:        "pending",
			Role:          "member",
			EmailVerified: false,
			CreatedAt:     time.Now(),
		}

		expectedResponse := &auth.AuthResponse{
			User:         expectedUser,
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			SessionID:    "session-123",
		}

		mockAuthService.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).
			Return(expectedResponse, nil)

		// Create request
		reqBody := map[string]interface{}{
			"email":             "test@example.com",
			"password":          "securePassword123!",
			"confirm_password":  "securePassword123!",
			"first_name":        "John",
			"last_name":         "Doe",
			"organization_name": "Test Corp",
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.Register(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)

		var response auth.AuthResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser.Email, response.User.Email)
		assert.NotEmpty(t, response.AccessToken)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("registration with validation error", func(t *testing.T) {
		// Setup mock to return validation error
		mockAuthService.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).
			Return(nil, errors.NewValidationError("Email already exists"))

		// Create request with existing email
		reqBody := map[string]interface{}{
			"email":            "existing@example.com",
			"password":         "securePassword123!",
			"confirm_password": "securePassword123!",
			"first_name":       "John",
			"last_name":        "Doe",
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

	t.Run("registration with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.Register(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful login", func(t *testing.T) {
		expectedUser := &auth.UserResponse{
			ID:            "user-123",
			Email:         "test@example.com",
			FirstName:     "John",
			LastName:      "Doe",
			Status:        "active",
			Role:          "member",
			EmailVerified: true,
			CreatedAt:     time.Now(),
		}

		expectedResponse := &auth.AuthResponse{
			User:         expectedUser,
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			SessionID:    "session-123",
		}

		mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).
			Return(expectedResponse, nil)

		// Create request
		reqBody := map[string]interface{}{
			"email":    "test@example.com",
			"password": "securePassword123!",
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.Login(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)

		var response auth.AuthResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser.Email, response.User.Email)
		assert.NotEmpty(t, response.AccessToken)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("login with invalid credentials", func(t *testing.T) {
		mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).
			Return(nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "Invalid email or password"))

		reqBody := map[string]interface{}{
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

	t.Run("login with MFA required", func(t *testing.T) {
		expectedResponse := &auth.AuthResponse{
			RequiresMFA: true,
			MFATypes:    []string{"totp"},
		}

		mockAuthService.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).
			Return(expectedResponse, nil)

		reqBody := map[string]interface{}{
			"email":    "test@example.com",
			"password": "securePassword123!",
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
		assert.True(t, response["requires_mfa"].(bool))

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful token refresh", func(t *testing.T) {
		// Create a valid refresh token first
		tokenPair, err := jwtService.GenerateTokenPair(
			"user-123",
			"test@example.com",
			"member",
			"team-123",
			"Test Team",
			"pro",
			[]string{"read", "write"},
		)
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"refresh_token": tokenPair.RefreshToken,
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.RefreshToken(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)

		var response jwt.TokenPair
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
	})

	t.Run("refresh with invalid token", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"refresh_token": "invalid-token",
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.RefreshToken(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_VerifyEmail(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful email verification", func(t *testing.T) {
		token := "valid-verification-token"
		mockAuthService.On("VerifyEmail", mock.Anything, token).Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token="+token, nil)
		w := httptest.NewRecorder()

		// Execute
		handler.VerifyEmail(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "verified successfully")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("verification with missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email", nil)
		w := httptest.NewRecorder()

		// Execute
		handler.VerifyEmail(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("verification with invalid token", func(t *testing.T) {
		token := "invalid-token"
		mockAuthService.On("VerifyEmail", mock.Anything, token).
			Return(errors.NewValidationError("Invalid or expired verification token"))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token="+token, nil)
		w := httptest.NewRecorder()

		// Execute
		handler.VerifyEmail(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_ForgotPassword(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful password reset request", func(t *testing.T) {
		email := "test@example.com"
		// Note: We don't mock this because the handler always returns success
		// to prevent email enumeration

		reqBody := map[string]interface{}{
			"email": email,
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
		assert.Contains(t, response["message"], "password reset link has been sent")
	})

	t.Run("forgot password with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewBuffer([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.ForgotPassword(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_ResetPassword(t *testing.T) {
	mockAuthService := new(MockAuthService)
	jwtConfig := &jwt.Config{
		Secret:               "test-secret-32-characters-long",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-users",
	}
	jwtService := jwt.New(jwtConfig)
	logger := logger.New("test")

	handler := handlers.NewAuthHandler(mockAuthService, jwtService, logger)

	t.Run("successful password reset", func(t *testing.T) {
		token := "valid-reset-token"
		newPassword := "newSecurePassword123!"

		mockAuthService.On("ResetPassword", mock.Anything, token, newPassword).Return(nil)

		reqBody := map[string]interface{}{
			"token":    token,
			"password": newPassword,
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
		assert.Contains(t, response["message"], "Password reset successfully")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("password reset with invalid token", func(t *testing.T) {
		token := "invalid-token"
		newPassword := "newSecurePassword123!"

		mockAuthService.On("ResetPassword", mock.Anything, token, newPassword).
			Return(errors.NewValidationError("Invalid or expired reset token"))

		reqBody := map[string]interface{}{
			"token":    token,
			"password": newPassword,
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()

		// Execute
		handler.ResetPassword(w, req)

		// Assert
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAuthService.AssertExpectations(t)
	})
}

// Helper function to create a test user
func createTestUser() *models.User {
	now := time.Now()
	return &models.User{
		BaseModel: models.BaseModel{
			ID:        "user-123",
			CreatedAt: now,
			UpdatedAt: now,
		},
		Email:         "test@example.com",
		FirstName:     "John",
		LastName:      "Doe",
		PasswordHash:  "$2a$12$encrypted.password.hash",
		Status:        "active",
		Role:          "member",
		EmailVerified: true,
	}
}

// Helper function to create test auth response
func createTestAuthResponse() *auth.AuthResponse {
	return &auth.AuthResponse{
		User: &auth.UserResponse{
			ID:            "user-123",
			Email:         "test@example.com",
			FirstName:     "John",
			LastName:      "Doe",
			Status:        "active",
			Role:          "member",
			EmailVerified: true,
			CreatedAt:     time.Now(),
		},
		AccessToken:  "access.token.here",
		RefreshToken: "refresh.token.here",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		SessionID:    "session-123",
	}
}
