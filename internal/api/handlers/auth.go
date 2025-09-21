package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	authService *auth.Service
	jwtService  *jwt.Service
	logger      logger.Logger
}

func NewAuthHandler(authService *auth.Service, jwtService *jwt.Service, logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtService:  jwtService,
		logger:      logger,
	}
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	TeamName string `json:"team_name,omitempty"`
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	User         *UserInfo `json:"user"`
}

type UserInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TeamID   string `json:"team_id"`
	IsActive bool   `json:"is_active"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get user by email
	user, err := h.authService.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		h.logger.Warn("Login attempt with invalid email", "email", req.Email)
		writeError(w, errors.NewUnauthorizedError("Invalid credentials"))
		return
	}

	// Check if user is active
	if !user.Active {
		h.logger.Warn("Login attempt for inactive user", "user_id", user.ID, "email", user.Email)
		writeError(w, errors.NewUnauthorizedError("Account is disabled"))
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		h.logger.Warn("Login attempt with invalid password", "user_id", user.ID, "email", user.Email)
		writeError(w, errors.NewUnauthorizedError("Invalid credentials"))
		return
	}

	// Generate tokens
	tokenPair, err := h.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		user.TeamID,
		"", // team name - would be fetched in real implementation
		"premium", // team plan - would be fetched in real implementation
		[]string{"workflows:read", "workflows:write", "workflows:delete", "executions:read"},
	)
	if err != nil {
		h.logger.Error("Failed to generate tokens", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to generate authentication tokens"))
		return
	}

	response := LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		User: &UserInfo{
			ID:       user.ID,
			Name:     user.Name,
			Email:    user.Email,
			Role:     user.Role,
			TeamID:   user.TeamID,
			IsActive: user.Active,
		},
	}

	h.logger.Info("User logged in successfully", "user_id", user.ID, "email", user.Email)
	writeSuccess(w, http.StatusOK, response)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Check if user already exists
	existingUser, _ := h.authService.GetUserByEmail(r.Context(), req.Email)
	if existingUser != nil {
		writeError(w, errors.NewValidationError("User with this email already exists"))
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		writeError(w, errors.NewInternalError("Failed to process password"))
		return
	}

	// Create user
	user := &auth.User{
		ID:       common.GenerateID(),
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		Active:   true,
		TeamID:   common.GenerateID(), // Create new team for user
		Role:     "admin", // First user in team is admin
	}

	if err := h.authService.CreateUser(r.Context(), user); err != nil {
		h.logger.Error("Failed to create user", "email", req.Email, "error", err)
		writeError(w, errors.NewInternalError("Failed to create user account"))
		return
	}

	response := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
		"team_id": user.TeamID,
		"message": "User registered successfully",
	}

	h.logger.Info("User registered successfully", "user_id", user.ID, "email", user.Email)
	writeSuccess(w, http.StatusCreated, response)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.Warn("Invalid refresh token", "error", err)
		writeError(w, errors.NewUnauthorizedError("Invalid refresh token"))
		return
	}

	// Get user to ensure they still exist and are active
	user, err := h.authService.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		h.logger.Warn("Refresh token for non-existent user", "user_id", claims.UserID)
		writeError(w, errors.NewUnauthorizedError("User not found"))
		return
	}

	if !user.Active {
		h.logger.Warn("Refresh token for inactive user", "user_id", user.ID)
		writeError(w, errors.NewUnauthorizedError("Account is disabled"))
		return
	}

	// Generate new token pair
	newTokenPair, err := h.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		user.TeamID,
		"", // team name
		"premium", // team plan
		[]string{"workflows:read", "workflows:write", "workflows:delete", "executions:read"},
	)
	if err != nil {
		h.logger.Error("Failed to generate new tokens", "user_id", user.ID, "error", err)
		writeError(w, errors.NewInternalError("Failed to refresh tokens"))
		return
	}

	response := LoginResponse{
		AccessToken:  newTokenPair.AccessToken,
		RefreshToken: newTokenPair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: &UserInfo{
			ID:       user.ID,
			Name:     user.Name,
			Email:    user.Email,
			Role:     user.Role,
			TeamID:   user.TeamID,
			IsActive: user.Active,
		},
	}

	h.logger.Info("Tokens refreshed successfully", "user_id", user.ID)
	writeSuccess(w, http.StatusOK, response)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// In a real implementation, you would invalidate the token here
	// For now, we just return success
	h.logger.Info("User logged out", "user_id", user.ID)
	
	response := map[string]interface{}{
		"message": "Logged out successfully",
	}
	writeSuccess(w, http.StatusOK, response)
}

func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get full user details
	fullUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user details", "user_id", user.ID, "error", err)
		writeError(w, errors.NewInternalError("Failed to get user information"))
		return
	}

	userInfo := UserInfo{
		ID:       fullUser.ID,
		Name:     fullUser.Name,
		Email:    fullUser.Email,
		Role:     fullUser.Role,
		TeamID:   fullUser.TeamID,
		IsActive: fullUser.Active,
	}

	writeSuccess(w, http.StatusOK, userInfo)
}