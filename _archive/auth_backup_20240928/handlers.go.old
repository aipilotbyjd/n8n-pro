package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
)

// Handler handles authentication HTTP requests
type Handler struct {
	service        *Service
	jwtService     *jwt.Service
	validator      *AdvancedValidator
	rateLimiter    *RateLimiter
	sessionManager *SessionManager
	logger         logger.Logger
	config         *HandlerConfig
}

// HandlerConfig contains handler configuration
type HandlerConfig struct {
	MaxLoginAttempts     int           `json:"max_login_attempts"`
	LoginAttemptWindow   time.Duration `json:"login_attempt_window"`
	SessionTimeout       time.Duration `json:"session_timeout"`
	RequireEmailVerify   bool          `json:"require_email_verify"`
	AllowPasswordReset   bool          `json:"allow_password_reset"`
	EnableDeviceTracking bool          `json:"enable_device_tracking"`
	MaxConcurrentSessions int          `json:"max_concurrent_sessions"`
	JWTConfig            *jwt.Config   `json:"jwt_config"`
}

// DefaultHandlerConfig returns default handler configuration
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		MaxLoginAttempts:     5,
		LoginAttemptWindow:   15 * time.Minute,
		SessionTimeout:       24 * time.Hour,
		RequireEmailVerify:   true,
		AllowPasswordReset:   true,
		EnableDeviceTracking: true,
		MaxConcurrentSessions: 5,
	}
}

// NewHandler creates a new authentication handler
func NewHandler(service *Service, jwtService *jwt.Service, config *HandlerConfig) *Handler {
	if config == nil {
		config = DefaultHandlerConfig()
	}

	return &Handler{
		service:        service,
		jwtService:     jwtService,
		validator:      NewAdvancedValidator(),
		rateLimiter:    NewRateLimiter(),
		sessionManager: NewSessionManager(service),
		logger:         logger.New("auth-handler"),
		config:         config,
	}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	FirstName            string `json:"first_name" validate:"required,min=1,max=100"`
	LastName             string `json:"last_name" validate:"required,min=1,max=100"`
	Email                string `json:"email" validate:"required,email"`
	Password             string `json:"password" validate:"required,min=8"`
	ConfirmPassword      string `json:"confirm_password" validate:"required,eqfield=Password"`
	OrganizationName     string `json:"organization_name,omitempty" validate:"omitempty,min=1,max=255"`
	AcceptTerms          bool   `json:"accept_terms" validate:"required,eq=true"`
	MarketingOptIn       bool   `json:"marketing_opt_in,omitempty"`
	InvitationToken      string `json:"invitation_token,omitempty"`
	CaptchaToken         string `json:"captcha_token,omitempty"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required"`
	RememberMe   bool   `json:"remember_me,omitempty"`
	CaptchaToken string `json:"captcha_token,omitempty"`
	DeviceInfo   *DeviceInfo `json:"device_info,omitempty"`
}

// DeviceInfo contains device information for tracking
type DeviceInfo struct {
	UserAgent    string `json:"user_agent,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Browser      string `json:"browser,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	Location     string `json:"location,omitempty"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	Scope        []string      `json:"scope,omitempty"`
	SessionID    string        `json:"session_id"`
	DeviceID     string        `json:"device_id,omitempty"`
}

// UserResponse represents user data in responses
type UserResponse struct {
	ID               string                 `json:"id"`
	Email            string                 `json:"email"`
	FirstName        string                 `json:"first_name"`
	LastName         string                 `json:"last_name"`
	Status           string                 `json:"status"`
	Role             string                 `json:"role"`
	EmailVerified    bool                   `json:"email_verified"`
	MFAEnabled       bool                   `json:"mfa_enabled"`
	OrganizationID   string                 `json:"organization_id"`
	Profile          map[string]interface{} `json:"profile"`
	LastLoginAt      *time.Time             `json:"last_login_at"`
	PasswordChangedAt time.Time             `json:"password_changed_at"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
}

// Register handles user registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Check rate limits
	clientIP := h.getClientIP(r)
	if !h.rateLimiter.Allow("register", clientIP) {
		h.writeError(w, errors.NewTooManyAttemptsError())
		return
	}

	// Parse request
	var req RegisterRequest
	if err := h.parseAndValidateJSON(r, &req); err != nil {
		h.writeError(w, err)
		return
	}

	// Additional validation
	if err := h.validator.ValidateRegistration(&req); err != nil {
		h.writeError(w, err)
		return
	}

	// Check if email already exists
	existingUser, err := h.service.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil && !errors.GetAppError(err).Code == errors.CodeResourceNotFound {
		h.logger.Error("Failed to check existing user", "error", err, "email", req.Email)
		h.writeError(w, errors.NewInternalError("Registration failed"))
		return
	}
	if existingUser != nil {
		h.writeError(w, errors.NewEmailExistsError(req.Email))
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		h.writeError(w, errors.NewInternalError("Registration failed"))
		return
	}

	// Create organization if provided
	var orgID string
	if req.OrganizationName != "" {
		org, err := h.createOrganization(ctx, req.OrganizationName)
		if err != nil {
			h.writeError(w, err)
			return
		}
		orgID = org.ID
	}

	// Create user
	user := &models.User{
		Email:          strings.ToLower(req.Email),
		FirstName:      strings.TrimSpace(req.FirstName),
		LastName:       strings.TrimSpace(req.LastName),
		PasswordHash:   string(hashedPassword),
		Status:         "pending",
		Role:           "member",
		OrganizationID: orgID,
		EmailVerified:  false,
		Profile: models.JSONB{
			"marketing_opt_in": req.MarketingOptIn,
			"accepted_terms":   req.AcceptTerms,
			"accepted_at":      time.Now(),
		},
	}

	if err := h.service.CreateUser(ctx, user); err != nil {
		h.logger.Error("Failed to create user", "error", err, "email", req.Email)
		h.writeError(w, errors.NewInternalError("Registration failed"))
		return
	}

	// Send email verification if required
	if h.config.RequireEmailVerify {
		token, err := h.service.SetEmailVerificationToken(ctx, user.ID)
		if err != nil {
			h.logger.Error("Failed to set email verification token", "error", err, "user_id", user.ID)
			// Don't fail registration, but log the issue
		} else {
			// TODO: Send verification email
			h.logger.Info("Email verification token generated", "user_id", user.ID, "token", token)
		}
	}

	// Create session
	sessionID, err := h.sessionManager.CreateSession(ctx, user.ID, clientIP, r.UserAgent())
	if err != nil {
		h.logger.Error("Failed to create session", "error", err, "user_id", user.ID)
		// Continue without session
	}

	// Generate tokens
	accessToken, refreshToken, err := h.generateTokens(user)
	if err != nil {
		h.logger.Error("Failed to generate tokens", "error", err, "user_id", user.ID)
		h.writeError(w, errors.NewInternalError("Registration completed but login failed"))
		return
	}

	// Audit log
	h.logSecurityEvent(ctx, "user_registered", user.ID, clientIP, map[string]interface{}{
		"email":           user.Email,
		"organization_id": user.OrganizationID,
	})

	// Response
	response := &AuthResponse{
		User:         h.userToResponse(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(h.config.JWTConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		SessionID:    sessionID,
	}

	h.writeSuccess(w, http.StatusCreated, response)
}

// Login handles user authentication
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := h.getClientIP(r)

	// Check rate limits
	if !h.rateLimiter.Allow("login", clientIP) {
		h.writeError(w, errors.NewTooManyAttemptsError())
		return
	}

	// Parse request
	var req LoginRequest
	if err := h.parseAndValidateJSON(r, &req); err != nil {
		h.writeError(w, err)
		return
	}

	// Get user
	user, err := h.service.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		if errors.GetAppError(err).Code == errors.CodeResourceNotFound {
			// Don't reveal whether user exists
			h.logSecurityEvent(ctx, "login_failed_unknown_user", "", clientIP, map[string]interface{}{
				"email": req.Email,
			})
			h.writeError(w, errors.NewInvalidLoginError())
			return
		}
		h.logger.Error("Failed to get user", "error", err, "email", req.Email)
		h.writeError(w, errors.NewInternalError("Login failed"))
		return
	}

	// Check if account is locked
	locked, err := h.service.IsAccountLocked(ctx, user.ID)
	if err != nil {
		h.logger.Error("Failed to check account lock", "error", err, "user_id", user.ID)
		h.writeError(w, errors.NewInternalError("Login failed"))
		return
	}
	if locked {
		h.logSecurityEvent(ctx, "login_failed_account_locked", user.ID, clientIP, nil)
		h.writeError(w, errors.NewAccountLockedError())
		return
	}

	// Check account status
	if user.Status == "disabled" {
		h.logSecurityEvent(ctx, "login_failed_account_disabled", user.ID, clientIP, nil)
		h.writeError(w, errors.NewAccountDisabledError())
		return
	}

	if h.config.RequireEmailVerify && !user.EmailVerified {
		h.logSecurityEvent(ctx, "login_failed_email_not_verified", user.ID, clientIP, nil)
		h.writeError(w, errors.NewAccountNotVerifiedError())
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Increment failed attempts
		if incrementErr := h.service.IncrementFailedLogin(ctx, user.ID); incrementErr != nil {
			h.logger.Error("Failed to increment failed login", "error", incrementErr, "user_id", user.ID)
		}

		h.logSecurityEvent(ctx, "login_failed_invalid_password", user.ID, clientIP, nil)
		h.writeError(w, errors.NewInvalidLoginError())
		return
	}

	// Check concurrent sessions
	if h.config.MaxConcurrentSessions > 0 {
		sessions, err := h.sessionManager.GetUserSessions(ctx, user.ID)
		if err != nil {
			h.logger.Error("Failed to get user sessions", "error", err, "user_id", user.ID)
		} else if len(sessions) >= h.config.MaxConcurrentSessions {
			// Remove oldest session
			if err := h.sessionManager.InvalidateOldestSession(ctx, user.ID); err != nil {
				h.logger.Error("Failed to invalidate oldest session", "error", err, "user_id", user.ID)
			}
		}
	}

	// Update last login
	if err := h.service.UpdateLastLogin(ctx, user.ID, clientIP); err != nil {
		h.logger.Error("Failed to update last login", "error", err, "user_id", user.ID)
		// Continue with login
	}

	// Create session
	sessionID, err := h.sessionManager.CreateSession(ctx, user.ID, clientIP, r.UserAgent())
	if err != nil {
		h.logger.Error("Failed to create session", "error", err, "user_id", user.ID)
		// Continue without session
	}

	// Generate tokens
	accessToken, refreshToken, err := h.generateTokens(user)
	if err != nil {
		h.logger.Error("Failed to generate tokens", "error", err, "user_id", user.ID)
		h.writeError(w, errors.NewInternalError("Login failed"))
		return
	}

	// Update user's last login timestamp for response
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = clientIP

	// Audit log
	h.logSecurityEvent(ctx, "user_login_success", user.ID, clientIP, map[string]interface{}{
		"session_id": sessionID,
	})

	// Response
	response := &AuthResponse{
		User:         h.userToResponse(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(h.config.JWTConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		SessionID:    sessionID,
	}

	h.writeSuccess(w, http.StatusOK, response)
}

// RefreshToken handles token refresh
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := h.getClientIP(r)

	// Rate limiting for refresh
	if !h.rateLimiter.Allow("refresh", clientIP) {
		h.writeError(w, errors.NewTooManyAttemptsError())
		return
	}

	// Parse request
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}
	if err := h.parseAndValidateJSON(r, &req); err != nil {
		h.writeError(w, err)
		return
	}

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.logSecurityEvent(ctx, "refresh_token_invalid", "", clientIP, map[string]interface{}{
			"error": err.Error(),
		})
		h.writeError(w, errors.NewUnauthorizedError("Invalid refresh token"))
		return
	}

	// Get user
	user, err := h.service.GetUserByID(ctx, claims.Subject)
	if err != nil {
		h.logger.Error("Failed to get user for refresh", "error", err, "user_id", claims.Subject)
		h.writeError(w, errors.NewUnauthorizedError("Invalid refresh token"))
		return
	}

	// Check user status
	if user.Status == "disabled" {
		h.logSecurityEvent(ctx, "refresh_failed_account_disabled", user.ID, clientIP, nil)
		h.writeError(w, errors.NewAccountDisabledError())
		return
	}

	// Generate new tokens
	accessToken, refreshToken, err := h.generateTokens(user)
	if err != nil {
		h.logger.Error("Failed to generate new tokens", "error", err, "user_id", user.ID)
		h.writeError(w, errors.NewInternalError("Token refresh failed"))
		return
	}

	// Audit log
	h.logSecurityEvent(ctx, "token_refreshed", user.ID, clientIP, nil)

	// Response
	response := &AuthResponse{
		User:         h.userToResponse(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(h.config.JWTConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
	}

	h.writeSuccess(w, http.StatusOK, response)
}

// Logout handles user logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := h.getClientIP(r)

	// Get user from context (set by auth middleware)
	user := GetUserFromContext(ctx)
	if user == nil {
		h.writeError(w, errors.NewUnauthorizedError("Authentication required"))
		return
	}

	// Parse request
	var req struct {
		SessionID    string `json:"session_id,omitempty"`
		AllSessions  bool   `json:"all_sessions,omitempty"`
	}
	if err := h.parseAndValidateJSON(r, &req); err != nil {
		// If parsing fails, continue with logout
		h.logger.Warn("Failed to parse logout request", "error", err)
	}

	// Invalidate sessions
	if req.AllSessions {
		if err := h.sessionManager.InvalidateAllSessions(ctx, user.ID); err != nil {
			h.logger.Error("Failed to invalidate all sessions", "error", err, "user_id", user.ID)
		}
	} else if req.SessionID != "" {
		if err := h.sessionManager.InvalidateSession(ctx, req.SessionID); err != nil {
			h.logger.Error("Failed to invalidate session", "error", err, "session_id", req.SessionID)
		}
	}

	// TODO: Implement token blacklisting when needed
	// h.jwtService.BlacklistToken(token)

	// Audit log
	h.logSecurityEvent(ctx, "user_logout", user.ID, clientIP, map[string]interface{}{
		"session_id":   req.SessionID,
		"all_sessions": req.AllSessions,
	})

	h.writeSuccess(w, http.StatusOK, map[string]interface{}{
		"message": "Logged out successfully",
	})
}

// Helper methods

func (h *Handler) parseAndValidateJSON(r *http.Request, v interface{}) *errors.AppError {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.NewValidationError("Invalid JSON payload")
	}

	if err := h.validator.ValidateStruct(v); err != nil {
		return errors.Wrap(err, errors.ErrorTypeValidation, errors.CodeInvalidInput, "Validation failed")
	}

	return nil
}

func (h *Handler) generateTokens(user *models.User) (string, string, error) {
	// Create claims
	claims := &jwt.Claims{
		UserID:         user.ID,
		Email:          user.Email,
		OrganizationID: user.OrganizationID,
		Role:           user.Role,
		Scopes:         []string{"read", "write"}, // TODO: Implement proper scopes
	}

	// Generate access token
	accessToken, err := h.jwtService.GenerateAccessToken(claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := h.jwtService.GenerateRefreshToken(claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (h *Handler) userToResponse(user *models.User) *UserResponse {
	return &UserResponse{
		ID:                user.ID,
		Email:             user.Email,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Status:            user.Status,
		Role:              user.Role,
		EmailVerified:     user.EmailVerified,
		MFAEnabled:        user.MFAEnabled,
		OrganizationID:    user.OrganizationID,
		Profile:           user.Profile,
		LastLoginAt:       user.LastLoginAt,
		PasswordChangedAt: user.PasswordChangedAt,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}
}

func (h *Handler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

func (h *Handler) createOrganization(ctx context.Context, name string) (*models.Organization, error) {
	// TODO: Implement organization creation
	// For now, return a mock organization
	return &models.Organization{
		BaseModel: models.BaseModel{
			ID: "mock-org-id",
		},
		Name: name,
	}, nil
}

func (h *Handler) logSecurityEvent(ctx context.Context, eventType, userID, ipAddress string, details map[string]interface{}) {
	// TODO: Implement proper audit logging
	h.logger.Info("Security event",
		"event_type", eventType,
		"user_id", userID,
		"ip_address", ipAddress,
		"details", details,
	)
}

func (h *Handler) writeSuccess(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"success": true,
		"data":    data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) writeError(w http.ResponseWriter, err *errors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus())
	
	response := map[string]interface{}{
		"success": false,
		"error": map[string]interface{}{
			"code":    err.Code,
			"message": err.Message,
			"details": err.Details,
			"context": err.Context,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	json.NewEncoder(w).Encode(response)
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *models.User {
	if user, ok := ctx.Value("user").(*models.User); ok {
		return user
	}
	return nil
}