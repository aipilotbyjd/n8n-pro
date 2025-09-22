package handlers

import (
	"encoding/json"
	"net/http"

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

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

type UpdateProfileRequest struct {
	Name     *string `json:"name,omitempty" validate:"omitempty,min=2,max=100"`
	Timezone *string `json:"timezone,omitempty"`
	Language *string `json:"language,omitempty"`
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

	// Check if account is locked
	isLocked, err := h.authService.IsAccountLocked(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to check account lock status", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Authentication failed"))
		return
	}
	if isLocked {
		h.logger.Warn("Login attempt for locked account", "user_id", user.ID, "email", user.Email)
		writeError(w, errors.NewUnauthorizedError("Account is temporarily locked due to too many failed login attempts"))
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
		
		// Increment failed login attempts
		if err := h.authService.IncrementFailedLogin(r.Context(), user.ID); err != nil {
			h.logger.Error("Failed to increment failed login attempts", "user_id", user.ID, "error", err)
		}
		
		writeError(w, errors.NewUnauthorizedError("Invalid credentials"))
		return
	}

	// Get client IP for login tracking
	clientIP := getClientIP(r)

	// Update last login information
	if err := h.authService.UpdateLastLogin(r.Context(), user.ID, clientIP); err != nil {
		h.logger.Error("Failed to update last login", "user_id", user.ID, "error", err)
		// Don't fail the login for this error
	}

	// Generate tokens
	tokenPair, err := h.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		user.TeamID,
		"",        // team name - would be fetched in real implementation
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

	h.logger.Info("User logged in successfully", "user_id", user.ID, "email", user.Email, "ip", clientIP)
	writeSuccess(w, http.StatusOK, response)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		writeError(w, errors.NewValidationError("Password must be at least 8 characters long"))
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
		writeError(w, errors.InternalError("Failed to process password"))
		return
	}

	// Create user with default values
	user := &auth.User{
		ID:              common.GenerateID(),
		Name:            req.Name,
		Email:           req.Email,
		Password:        string(hashedPassword),
		Active:          true,
		TeamID:          common.GenerateID(), // Create new team for user
		Role:            "admin",             // First user in team is admin
		EmailVerified:   false,               // Email verification required
		Timezone:        "UTC",
		Language:        "en",
		Metadata:        make(map[string]interface{}),
	}

	if err := h.authService.CreateUser(r.Context(), user); err != nil {
		h.logger.Error("Failed to create user", "email", req.Email, "error", err)
		writeError(w, errors.InternalError("Failed to create user account"))
		return
	}

	// Generate email verification token
	verificationToken, err := h.authService.SetEmailVerificationToken(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to generate email verification token", "user_id", user.ID, "error", err)
		// Don't fail registration for this error
	}

	response := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
		"team_id": user.TeamID,
		"message": "User registered successfully. Please check your email for verification.",
	}

	// TODO: Remove this in production - only for development
	if verificationToken != "" {
		response["verification_token"] = verificationToken
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
		"",        // team name
		"premium", // team plan
		[]string{"workflows:read", "workflows:write", "workflows:delete", "executions:read"},
	)
	if err != nil {
		h.logger.Error("Failed to generate new tokens", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to refresh tokens"))
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
		writeError(w, errors.InternalError("Failed to get user information"))
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

// ForgotPassword initiates password reset process
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Check if user exists
	user, err := h.authService.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists or not for security
		h.logger.Info("Password reset requested for non-existent email", "email", req.Email)
		writeSuccess(w, http.StatusOK, map[string]string{
			"message": "If the email exists, a password reset link has been sent",
		})
		return
	}

	// Check if user is active
	if !user.Active {
		h.logger.Warn("Password reset requested for inactive user", "user_id", user.ID, "email", req.Email)
		writeSuccess(w, http.StatusOK, map[string]string{
			"message": "If the email exists, a password reset link has been sent",
		})
		return
	}

	// Generate password reset token
	token, err := h.authService.SetPasswordResetToken(r.Context(), req.Email)
	if err != nil {
		h.logger.Error("Failed to generate password reset token", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to initiate password reset"))
		return
	}

	// TODO: Send email with reset link
	// For now, we'll log the token (in production, this should be sent via email)
	h.logger.Info("Password reset token generated", "user_id", user.ID, "token", token)

	response := map[string]interface{}{
		"message": "Password reset link has been sent to your email",
		// TODO: Remove this in production
		"reset_token": token,
	}

	writeSuccess(w, http.StatusOK, response)
}

// ResetPassword resets user password using token
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash new password", "error", err)
		writeError(w, errors.InternalError("Failed to process new password"))
		return
	}

	// Reset password using token
	user, err := h.authService.ResetPassword(r.Context(), req.Token, string(hashedPassword))
	if err != nil {
		h.logger.Warn("Password reset failed", "token", req.Token, "error", err)
		writeError(w, errors.NewUnauthorizedError("Invalid or expired reset token"))
		return
	}

	h.logger.Info("Password reset successfully", "user_id", user.ID, "email", user.Email)

	response := map[string]interface{}{
		"message": "Password has been reset successfully",
		"user_id": user.ID,
	}

	writeSuccess(w, http.StatusOK, response)
}

// SendVerificationEmail sends email verification link
func (h *AuthHandler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get full user details
	fullUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user details", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	// Check if already verified
	if fullUser.EmailVerified {
		writeError(w, errors.NewValidationError("Email is already verified"))
		return
	}

	// Generate verification token
	token, err := h.authService.SetEmailVerificationToken(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to generate email verification token", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to generate verification token"))
		return
	}

	// TODO: Send email with verification link
	// For now, we'll log the token (in production, this should be sent via email)
	h.logger.Info("Email verification token generated", "user_id", user.ID, "token", token)

	response := map[string]interface{}{
		"message": "Verification email has been sent",
		// TODO: Remove this in production
		"verification_token": token,
	}

	writeSuccess(w, http.StatusOK, response)
}

// VerifyEmail verifies user email using token
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Verify email using token
	user, err := h.authService.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		h.logger.Warn("Email verification failed", "token", req.Token, "error", err)
		writeError(w, errors.NewUnauthorizedError("Invalid or expired verification token"))
		return
	}

	h.logger.Info("Email verified successfully", "user_id", user.ID, "email", user.Email)

	response := map[string]interface{}{
		"message": "Email has been verified successfully",
		"user_id": user.ID,
		"email":   user.Email,
	}

	writeSuccess(w, http.StatusOK, response)
}

// UpdateProfile updates user profile information
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get current user details
	fullUser, err := h.authService.GetUserByID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user details", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user information"))
		return
	}

	// Update fields if provided
	if req.Name != nil {
		fullUser.Name = *req.Name
	}
	if req.Timezone != nil {
		fullUser.Timezone = *req.Timezone
	}
	if req.Language != nil {
		fullUser.Language = *req.Language
	}

	// Update user
	if err := h.authService.UpdateUser(r.Context(), fullUser); err != nil {
		h.logger.Error("Failed to update user profile", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to update profile"))
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

	h.logger.Info("User profile updated successfully", "user_id", fullUser.ID)
	writeSuccess(w, http.StatusOK, userInfo)
}

// Helper function to get client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to remote address
	return r.RemoteAddr
}
