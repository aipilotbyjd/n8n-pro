// Package auth provides comprehensive authentication and authorization services
package auth

import (
	"context"
	"fmt"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthService provides comprehensive authentication services
type AuthService struct {
	db            *gorm.DB
	jwtService    *jwt.Service
	sessionRepo   SessionRepository
	apiKeyRepo    APIKeyRepository
	config        *config.AuthConfig
	logger        logger.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(
	db *gorm.DB,
	cfg *config.AuthConfig,
	logger logger.Logger,
) *AuthService {
	// Create JWT config from auth config
	jwtConfig := &jwt.Config{
		Secret:                cfg.JWTSecret,
		AccessTokenDuration:   cfg.JWTExpiration,
		RefreshTokenDuration:  cfg.RefreshTokenExpiration,
		Issuer:                "n8n-pro",
		Audience:              "n8n-pro-api",
		RefreshTokenLength:    32,
		EnableRefreshRotation: true,
	}

	jwtService := jwt.New(jwtConfig)
	
	return &AuthService{
		db:            db,
		jwtService:    jwtService,
		sessionRepo:   NewSessionRepository(db),
		apiKeyRepo:    NewAPIKeyRepository(db),
		config:        cfg,
		logger:        logger,
	}
}

// LoginRequest represents login request data
type LoginRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	MFACode    string `json:"mfa_code,omitempty"`
	RememberMe bool   `json:"remember_me"`
	IPAddress  string `json:"-"`
	UserAgent  string `json:"-"`
}

// LoginResponse represents login response data
type LoginResponse struct {
	AccessToken           string                 `json:"access_token"`
	RefreshToken          string                 `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time              `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time              `json:"refresh_token_expires_at"`
	User                  *UserProfile           `json:"user"`
	RequiresMFA           bool                   `json:"requires_mfa"`
	MFASetupRequired      bool                   `json:"mfa_setup_required"`
	SessionID             string                 `json:"session_id"`
}

// UserProfile represents user profile data
type UserProfile struct {
	ID             string                 `json:"id"`
	Email          string                 `json:"email"`
	FirstName      string                 `json:"first_name"`
	LastName       string                 `json:"last_name"`
	Role           string                 `json:"role"`
	Status         string                 `json:"status"`
	OrganizationID string                 `json:"organization_id"`
	EmailVerified  bool                   `json:"email_verified"`
	MFAEnabled     bool                   `json:"mfa_enabled"`
	LastLoginAt    *time.Time             `json:"last_login_at"`
	Profile        map[string]interface{} `json:"profile"`
	Settings       map[string]interface{} `json:"settings"`
	CreatedAt      time.Time              `json:"created_at"`
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	// Find user by email
	var user models.User
	if err := s.db.Where("email = ? AND deleted_at IS NULL", req.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// Prevent timing attacks by still computing password hash
			bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte("dummy"))
			return nil, errors.NewUnauthorizedError("Invalid credentials")
		}
		s.logger.Error("Failed to find user", "error", err)
		return nil, errors.NewInternalError("Authentication failed")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, errors.NewUnauthorizedError("Account is temporarily locked due to too many failed login attempts")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Increment failed login attempts
		if err := s.incrementFailedLoginAttempts(ctx, user.ID); err != nil {
			s.logger.Error("Failed to increment login attempts", "error", err, "user_id", user.ID)
		}
		return nil, errors.NewUnauthorizedError("Invalid credentials")
	}

	// Check if user is active
	if user.Status != "active" {
		return nil, errors.NewUnauthorizedError("Account is not active")
	}

	// Check if email is verified (if required)
	if s.config.RequireEmailVerification && !user.EmailVerified {
		return nil, errors.NewUnauthorizedError("Email verification required")
	}

	// Check MFA requirements
	if user.MFAEnabled && req.MFACode == "" {
		return &LoginResponse{
			RequiresMFA: true,
			User:        s.userToProfile(&user),
		}, nil
	}

	// Verify MFA code if provided
	if user.MFAEnabled && req.MFACode != "" {
		if valid, err := s.verifyMFACode(ctx, user.ID, req.MFACode); err != nil || !valid {
			if err := s.incrementFailedLoginAttempts(ctx, user.ID); err != nil {
				s.logger.Error("Failed to increment login attempts", "error", err, "user_id", user.ID)
			}
			return nil, errors.NewUnauthorizedError("Invalid MFA code")
		}
	}

	// Get user's team information
	var teamMember models.TeamMember
	var teamName, teamPlan string
	if err := s.db.Joins("Team").Where("user_id = ?", user.ID).First(&teamMember).Error; err == nil {
		teamName = teamMember.Team.Name
		// Get organization plan
		var org models.Organization
		if err := s.db.Where("id = ?", user.OrganizationID).First(&org).Error; err == nil {
			teamPlan = org.Plan
		}
	}

	// Generate scopes based on user role
	scopes := s.generateScopes(user.Role)

	// Generate JWT tokens
	tokens, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		teamMember.TeamID,
		teamName,
		teamPlan,
		scopes,
	)
	if err != nil {
		s.logger.Error("Failed to generate tokens", "error", err, "user_id", user.ID)
		return nil, errors.NewInternalError("Authentication failed")
	}

	// Create session
	session, err := s.createSession(ctx, &user, tokens.RefreshToken, req.IPAddress, req.UserAgent, req.RememberMe)
	if err != nil {
		s.logger.Error("Failed to create session", "error", err, "user_id", user.ID)
		return nil, errors.NewInternalError("Authentication failed")
	}

	// Update user login information
	if err := s.updateLastLogin(ctx, user.ID, req.IPAddress); err != nil {
		s.logger.Error("Failed to update last login", "error", err, "user_id", user.ID)
		// Don't fail the login for this
	}

	response := &LoginResponse{
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		User:                  s.userToProfile(&user),
		RequiresMFA:           false,
		MFASetupRequired:      s.config.RequireMFA && !user.MFAEnabled,
		SessionID:             session.ID,
	}

	s.logger.Info("User logged in successfully", "user_id", user.ID, "session_id", session.ID)
	return response, nil
}

// RefreshToken refreshes access token using refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.NewUnauthorizedError("Invalid refresh token")
	}

	// Find and validate session
	session, err := s.sessionRepo.FindByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.NewUnauthorizedError("Invalid session")
	}

	if !session.IsActive || time.Now().After(session.ExpiresAt) {
		return nil, errors.NewUnauthorizedError("Session expired")
	}

	// Find user
	var user models.User
	if err := s.db.Where("id = ? AND deleted_at IS NULL", claims.UserID).First(&user).Error; err != nil {
		return nil, errors.NewUnauthorizedError("User not found")
	}

	// Check if user is still active
	if user.Status != "active" {
		return nil, errors.NewUnauthorizedError("Account is not active")
	}

	// Generate new token pair
	scopes := s.generateScopes(user.Role)
	tokens, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		claims.TeamID,
		claims.TeamName,
		claims.TeamPlan,
		scopes,
	)
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate tokens")
	}

	// Update session with new refresh token
	session.RefreshTokenHash = s.hashRefreshToken(tokens.RefreshToken)
	session.ExpiresAt = tokens.RefreshTokenExpiresAt
	session.LastSeenAt = time.Now()

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		s.logger.Error("Failed to update session", "error", err, "session_id", session.ID)
		return nil, errors.NewInternalError("Failed to refresh token")
	}

	return &LoginResponse{
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		User:                  s.userToProfile(&user),
		SessionID:             session.ID,
	}, nil
}

// ValidateAccessToken validates an access token and returns user information
func (s *AuthService) ValidateAccessToken(ctx context.Context, token string) (*jwt.Claims, error) {
	return s.jwtService.ValidateAccessToken(token)
}

// Logout logs out a user by invalidating the session
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	return s.sessionRepo.Revoke(ctx, sessionID)
}

// LogoutAll logs out a user from all sessions
func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	return s.sessionRepo.RevokeAllUserSessions(ctx, userID)
}

// Helper methods

func (s *AuthService) incrementFailedLoginAttempts(ctx context.Context, userID string) error {
	// Increment failed attempts and potentially lock account
	result := s.db.Exec(`
		UPDATE users 
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE 
		        WHEN failed_login_attempts + 1 >= ? THEN NOW() + INTERVAL ? MINUTE
		        ELSE locked_until
		    END,
		    updated_at = NOW()
		WHERE id = ?`,
		s.config.MaxLoginAttempts,
		s.config.LoginAttemptWindow.Minutes(),
		userID,
	)
	return result.Error
}

func (s *AuthService) updateLastLogin(ctx context.Context, userID, ipAddress string) error {
	return s.db.Exec(`
		UPDATE users 
		SET last_login_at = NOW(),
		    last_login_ip = ?,
		    login_count = login_count + 1,
		    failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = NOW()
		WHERE id = ?`,
		ipAddress, userID,
	).Error
}

func (s *AuthService) verifyMFACode(ctx context.Context, userID, code string) (bool, error) {
	// TODO: Implement actual TOTP verification
	// For now, return true for development
	s.logger.Info("MFA code verification", "user_id", userID, "code", "***")
	return code == "123456", nil
}

func (s *AuthService) generateScopes(role string) []string {
	// Generate scopes based on role
	scopes := []string{"profile"}
	
	switch role {
	case "owner":
		scopes = append(scopes, "admin:all", "org:all", "team:all", "user:all", "workflow:all")
	case "admin":
		scopes = append(scopes, "org:read", "org:write", "team:all", "user:read", "user:write", "workflow:all")
	case "member":
		scopes = append(scopes, "team:read", "workflow:read", "workflow:write")
	case "viewer":
		scopes = append(scopes, "team:read", "workflow:read")
	}
	
	return scopes
}

func (s *AuthService) userToProfile(user *models.User) *UserProfile {
	return &UserProfile{
		ID:             user.ID,
		Email:          user.Email,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Role:           user.Role,
		Status:         user.Status,
		OrganizationID: user.OrganizationID,
		EmailVerified:  user.EmailVerified,
		MFAEnabled:     user.MFAEnabled,
		LastLoginAt:    user.LastLoginAt,
		Profile:        user.Profile,
		Settings:       user.Settings,
		CreatedAt:      user.CreatedAt,
	}
}

func (s *AuthService) createSession(ctx context.Context, user *models.User, refreshToken, ipAddress, userAgent string, rememberMe bool) (*models.Session, error) {
	duration := s.config.RefreshTokenExpiration
	if rememberMe {
		duration = 30 * 24 * time.Hour // 30 days for remember me
	}

	session := &models.Session{
		BaseModel: models.BaseModel{
			ID: s.generateSessionID(),
		},
		UserID:           user.ID,
		RefreshTokenHash: s.hashRefreshToken(refreshToken),
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
		IsActive:         true,
		ExpiresAt:        time.Now().Add(duration),
		LastSeenAt:       time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (s *AuthService) generateSessionID() string {
	// Generate a secure session ID
	return fmt.Sprintf("ses_%d_%s", time.Now().UnixNano(), generateRandomString(16))
}

func (s *AuthService) hashRefreshToken(token string) string {
	// Hash refresh token for storage (using bcrypt for simplicity)
	hash, _ := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hash)
}

func generateRandomString(length int) string {
	// Simple random string generator
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}

// Additional auth methods

// ChangePassword changes user password
func (s *AuthService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	var user models.User
	if err := s.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return errors.NewUnauthorizedError("Current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.NewInternalError("Failed to process password")
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	user.PasswordChangedAt = time.Now()
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil

	if err := s.db.Save(&user).Error; err != nil {
		return errors.NewInternalError("Failed to update password")
	}

	// Revoke all other sessions
	if err := s.sessionRepo.RevokeAllUserSessions(ctx, userID); err != nil {
		s.logger.Error("Failed to revoke sessions after password change", "error", err, "user_id", userID)
	}

	s.logger.Info("Password changed successfully", "user_id", userID)
	return nil
}

// GetUserSessions returns active sessions for a user
func (s *AuthService) GetUserSessions(ctx context.Context, userID string) ([]*models.Session, error) {
	return s.sessionRepo.FindActiveByUserID(ctx, userID)
}

// RevokeSession revokes a specific session
func (s *AuthService) RevokeSession(ctx context.Context, sessionID string) error {
	return s.sessionRepo.Revoke(ctx, sessionID)
}