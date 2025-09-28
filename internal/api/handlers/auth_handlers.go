package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *auth.AuthService
	jwtService  *jwt.Service
	logger      logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *auth.AuthService, jwtService *jwt.Service, logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtService:  jwtService,
		logger:      logger,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode registration request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// Handle both "name" field and firstName/lastName fields for backward compatibility
	if req.FirstName == "" && req.LastName == "" && req.Name != "" {
		// Split name into first and last name
		parts := strings.SplitN(req.Name, " ", 2)
		req.FirstName = parts[0]
		if len(parts) > 1 {
			req.LastName = parts[1]
		}
	}

	// Set defaults if not provided
	if req.FirstName == "" {
		req.FirstName = "User"
	}
	if req.LastName == "" {
		req.LastName = ""
	}

	// Add device info from request
	req.DeviceInfo = &auth.SessionCreateRequest{
		IPAddress: getClientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
		DeviceID:  r.Header.Get("X-Device-ID"),
	}

	// Call auth service
	resp, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to register user", "error", err, "email", req.Email)
		writeError(w, err)
		return
	}

	// Write success response
	writeSuccess(w, http.StatusCreated, resp)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode login request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// Add device info from request
	req.DeviceInfo = &auth.SessionCreateRequest{
		IPAddress: getClientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
		DeviceID:  r.Header.Get("X-Device-ID"),
	}

	// Call auth service
	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to login user", "error", err, "email", req.Email)
		writeError(w, err)
		return
	}

	// Check if MFA is required
	if resp.RequiresMFA {
		writeSuccess(w, http.StatusOK, map[string]interface{}{
			"requires_mfa": true,
			"mfa_types":    resp.MFATypes,
		})
		return
	}

	// Write success response
	writeSuccess(w, http.StatusOK, resp)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session ID from header or context
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		// Try to get from context (set by auth middleware)
		if ctxSession := r.Context().Value("session_id"); ctxSession != nil {
			sessionID = ctxSession.(string)
		}
	}

	// Get user ID from context (set by auth middleware)
	userID := ""
	if ctxUser := r.Context().Value("user_id"); ctxUser != nil {
		userID = ctxUser.(string)
	}

	// Call auth service
	err := h.authService.Logout(r.Context(), sessionID)
	if err != nil {
		h.logger.Error("Failed to logout user", "error", err, "user_id", userID, "session_id", sessionID)
		// Don't return error on logout failure, just log it
	}

	// Write success response
	writeSuccess(w, http.StatusOK, map[string]string{
		"message": "Successfully logged out",
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode refresh request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.logger.Error("Invalid refresh token", "error", err)
		writeError(w, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidInput, "Invalid refresh token"))
		return
	}

	// Generate new token pair
	tokenPair, err := h.jwtService.GenerateTokenPair(
		claims.UserID,
		claims.Email,
		claims.Role,
		claims.TeamID,
		claims.TeamName,
		claims.TeamPlan,
		claims.Scopes,
	)
	if err != nil {
		h.logger.Error("Failed to generate new tokens", "error", err)
		writeError(w, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "Failed to refresh token"))
		return
	}

	// Write success response
	writeSuccess(w, http.StatusOK, tokenPair)
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Get token from query parameter
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Token is required"))
		return
	}

	// Call auth service
	err := h.authService.VerifyEmail(r.Context(), token)
	if err != nil {
		h.logger.Error("Failed to verify email", "error", err, "token", token)
		writeError(w, err)
		return
	}

	// Write success response
	writeSuccess(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully",
	})
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email" validate:"required,email"`
	}
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode forgot password request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// Call auth service (TODO: implement InitiatePasswordReset in AuthService)
	// err := h.authService.InitiatePasswordReset(r.Context(), req.Email, getClientIP(r))
	// if err != nil {
	// 	// Don't reveal if email exists or not
	// 	h.logger.Error("Failed to initiate password reset", "error", err, "email", req.Email)
	// }
	h.logger.Info("Password reset requested", "email", req.Email)

	// Always return success to prevent email enumeration
	writeSuccess(w, http.StatusOK, map[string]string{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password" validate:"required,min=8"`
	}
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode reset password request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// Call auth service
	err := h.authService.ResetPassword(r.Context(), req.Token, req.Password)
	if err != nil {
		h.logger.Error("Failed to reset password", "error", err, "ip", getClientIP(r))
		writeError(w, err)
		return
	}

	// Write success response
	writeSuccess(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// GetCurrentUser handles getting current user info
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userID := ""
	if ctxUser := r.Context().Value("user_id"); ctxUser != nil {
		userID = ctxUser.(string)
	}

	if userID == "" {
		writeError(w, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "User not authenticated"))
		return
	}

	// TODO: Implement GetUser method in AuthService
	// For now, return placeholder
	writeSuccess(w, http.StatusOK, map[string]string{
		"id":    userID,
		"message": "Get user endpoint - implementation pending",
	})
}

// UpdateCurrentUser handles updating current user info
func (h *AuthHandler) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userID := ""
	if ctxUser := r.Context().Value("user_id"); ctxUser != nil {
		userID = ctxUser.(string)
	}

	if userID == "" {
		writeError(w, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "User not authenticated"))
		return
	}

	var req map[string]interface{}
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode update request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// TODO: Implement UpdateProfile method in AuthService
	// For now, return placeholder
	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"id":      userID,
		"message": "Update user endpoint - implementation pending",
		"data":    req,
	})
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userID := ""
	if ctxUser := r.Context().Value("user_id"); ctxUser != nil {
		userID = ctxUser.(string)
	}

	if userID == "" {
		writeError(w, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "User not authenticated"))
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" validate:"required"`
		NewPassword     string `json:"new_password" validate:"required,min=8"`
	}
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode change password request", "error", err)
		writeError(w, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "Invalid request body"))
		return
	}

	// TODO: Implement ChangePassword method in AuthService
	// For now, return placeholder
	h.logger.Info("Password change requested", "user_id", userID)
	
	writeSuccess(w, http.StatusOK, map[string]string{
		"message": "Password change endpoint - implementation pending",
		"user_id": userID,
	})
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Real-IP header first
	ip := r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get the first IP in the chain
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}

	return addr
}