package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validation"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthService provides comprehensive authentication services
type AuthService struct {
	db              *gorm.DB
	jwtService      *jwt.Service
	sessionManager  *SessionManager
	rateLimiter     *RateLimiter
	validator       *validation.AuthValidator
	emailService    EmailService
	captchaService  CaptchaService
	config          *AuthConfig
	logger          logger.Logger
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	// Password policy
	BcryptCost              int           `json:"bcrypt_cost"`
	PasswordMinLength       int           `json:"password_min_length"`
	RequireEmailVerification bool         `json:"require_email_verification"`
	
	// Token settings
	EmailTokenExpiry        time.Duration `json:"email_token_expiry"`
	PasswordResetExpiry     time.Duration `json:"password_reset_expiry"`
	
	// Account settings
	MaxLoginAttempts        int           `json:"max_login_attempts"`
	LockoutDuration         time.Duration `json:"lockout_duration"`
	RequireMFA              bool          `json:"require_mfa"`
	
	// Security settings
	RequireCaptcha          bool          `json:"require_captcha"`
	LogSecurityEvents       bool          `json:"log_security_events"`
	
	// Session settings
	AllowConcurrentSessions bool          `json:"allow_concurrent_sessions"`
	SessionTimeout          time.Duration `json:"session_timeout"`
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		BcryptCost:              12,
		PasswordMinLength:       12,
		RequireEmailVerification: true,
		EmailTokenExpiry:        24 * time.Hour,
		PasswordResetExpiry:     1 * time.Hour,
		MaxLoginAttempts:        5,
		LockoutDuration:         30 * time.Minute,
		RequireMFA:              false,
		RequireCaptcha:          true,
		LogSecurityEvents:       true,
		AllowConcurrentSessions: true,
		SessionTimeout:          24 * time.Hour,
	}
}

// EmailService interface for email operations
type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
	SendMFACode(ctx context.Context, email, code string) error
	SendSecurityAlert(ctx context.Context, email, alert string) error
}

// CaptchaService interface for CAPTCHA operations
type CaptchaService interface {
	Verify(ctx context.Context, token string, action string) (float64, error)
}

// NewAuthService creates a new authentication service
func NewAuthService(
	db *gorm.DB,
	jwtService *jwt.Service,
	emailService EmailService,
	captchaService CaptchaService,
	config *AuthConfig,
) (*AuthService, error) {
	if config == nil {
		config = DefaultAuthConfig()
	}

	validator, err := validation.NewAuthValidator(db, validation.DefaultAuthValidationConfig())
	if err != nil {
		return nil, err
	}

	return &AuthService{
		db:             db,
		jwtService:     jwtService,
		sessionManager: NewSessionManager(db, DefaultSessionConfig()),
		rateLimiter:    NewRateLimiter(db, DefaultRateLimiterConfig()),
		validator:      validator,
		emailService:   emailService,
		captchaService: captchaService,
		config:         config,
		logger:         logger.New("auth-service"),
	}, nil
}

// RegisterRequest contains user registration data
type RegisterRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
	FirstName       string `json:"first_name" validate:"required,min=1,max=100"`
	LastName        string `json:"last_name" validate:"required,min=1,max=100"`
	OrganizationID  string `json:"organization_id,omitempty"`
	CaptchaToken    string `json:"captcha_token,omitempty"`
	AcceptTerms     bool   `json:"accept_terms" validate:"required"`
	DeviceInfo      *SessionCreateRequest `json:"device_info,omitempty"`
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	// Rate limiting check
	if !s.rateLimiter.Allow("register", req.Email) {
		return nil, errors.New(errors.ErrorTypeRateLimit, errors.CodeTooManyAttempts, "too many registration attempts")
	}

	// CAPTCHA verification
	if s.config.RequireCaptcha && s.captchaService != nil {
		if err := s.validator.ValidateCaptcha(req.CaptchaToken, "register"); err != nil {
			return nil, err
		}
		
		score, err := s.captchaService.Verify(ctx, req.CaptchaToken, "register")
		if err != nil || score < 0.5 {
			s.logSecurityEvent(ctx, "", "register_captcha_failed", req.Email, "")
			return nil, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "CAPTCHA verification failed")
		}
	}

	// Validate email format and uniqueness
	if err := s.validator.ValidateEmail(req.Email); err != nil {
		return nil, err
	}
	
	if err := s.validator.ValidateEmailUnique(ctx, req.Email); err != nil {
		return nil, err
	}

	// Validate password strength
	if err := s.validator.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.config.BcryptCost)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to process password")
	}

	// Begin transaction
	tx := s.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create user
	user := &models.User{
		ID:             uuid.New().String(),
		Email:          strings.ToLower(req.Email),
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		PasswordHash:   string(hashedPassword),
		OrganizationID: req.OrganizationID,
		Status:         "pending",
		Role:           "member",
		EmailVerified:  false,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		PasswordChangedAt: time.Now(),
		Profile: models.JSONB{
			"accepted_terms": req.AcceptTerms,
			"accepted_at":    time.Now(),
		},
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		if strings.Contains(err.Error(), "duplicate") {
			return nil, errors.NewEmailExistsError(req.Email)
		}
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create user")
	}

	// Add to password history
	passwordHistory := &models.PasswordHistory{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}
	
	if err := tx.Create(passwordHistory).Error; err != nil {
		tx.Rollback()
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create password history")
	}

	// Generate email verification token
	if s.config.RequireEmailVerification {
		emailToken, tokenHash, err := s.generateSecureToken()
		if err != nil {
			tx.Rollback()
			return nil, err
		}

		emailTokenRecord := &models.EmailToken{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenType: "verification",
			TokenHash: tokenHash,
			Email:     user.Email,
			IPAddress: req.DeviceInfo.IPAddress,
			UserAgent: req.DeviceInfo.UserAgent,
			ExpiresAt: time.Now().Add(s.config.EmailTokenExpiry),
			CreatedAt: time.Now(),
		}

		if err := tx.Create(emailTokenRecord).Error; err != nil {
			tx.Rollback()
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create email token")
		}

		// Send verification email asynchronously
		go func() {
			if err := s.emailService.SendVerificationEmail(context.Background(), user.Email, emailToken); err != nil {
				s.logger.Error("Failed to send verification email", "error", err, "email", user.Email)
			}
		}()
	}

	// Create session if device info provided
	var session *models.Session
	if req.DeviceInfo != nil {
		session, err = s.sessionManager.CreateSession(ctx, user.ID, req.DeviceInfo)
		if err != nil {
			// Don't fail registration if session creation fails
			s.logger.Error("Failed to create session during registration", "error", err)
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to commit registration")
	}

	// Generate JWT tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		"", // teamID
		"", // teamName
		"", // teamPlan
		[]string{"user:read", "user:write"},
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate tokens")
	}

	// Log successful registration
	s.logSecurityEvent(ctx, user.ID, "user_registered", user.Email, req.DeviceInfo.IPAddress)

	return &AuthResponse{
		User: &UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Status:    user.Status,
			Role:      user.Role,
			EmailVerified: user.EmailVerified,
		},
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int64(tokenPair.AccessTokenExpiresAt.Sub(time.Now()).Seconds()),
		TokenType:    tokenPair.TokenType,
		SessionID:    getSessionID(session),
		RequiresAction: s.getRequiredActions(user),
	}, nil
}

// LoginRequest contains login credentials
type LoginRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required"`
	CaptchaToken string `json:"captcha_token,omitempty"`
	MFACode      string `json:"mfa_code,omitempty"`
	RememberMe   bool   `json:"remember_me"`
	DeviceInfo   *SessionCreateRequest `json:"device_info,omitempty"`
}

// Login authenticates a user and creates a session
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	// Rate limiting by IP
	if req.DeviceInfo != nil && !s.rateLimiter.Allow("login", req.DeviceInfo.IPAddress) {
		return nil, errors.New(errors.ErrorTypeRateLimit, errors.CodeTooManyAttempts, "too many login attempts from this IP")
	}

	// Rate limiting by email
	if !s.rateLimiter.Allow("login", req.Email) {
		return nil, errors.New(errors.ErrorTypeRateLimit, errors.CodeTooManyAttempts, "too many login attempts for this account")
	}

	// CAPTCHA verification
	if s.config.RequireCaptcha && s.captchaService != nil {
		score, err := s.captchaService.Verify(ctx, req.CaptchaToken, "login")
		if err != nil || score < 0.5 {
			s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "failed", "captcha_failed")
			return nil, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "CAPTCHA verification failed")
		}
	}

	// Get user
	var user models.User
	err := s.db.WithContext(ctx).
		Where("LOWER(email) = LOWER(?) AND deleted_at IS NULL", req.Email).
		First(&user).Error

	if err != nil {
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "failed", "user_not_found")
		// Don't reveal if user exists
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "invalid email or password")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "blocked", "account_locked")
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeAccountLocked, "account is locked due to too many failed attempts")
	}

	// Check if account is suspended
	var enhancedUser models.EnhancedUser
	s.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", user.ID).First(&enhancedUser)
	if enhancedUser.SuspendedAt != nil {
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "blocked", "account_suspended")
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeAccountDisabled, "account is suspended")
	}

	// Check account status
	if user.Status != "active" {
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "blocked", "account_inactive")
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeAccountDisabled, "account is not active")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Increment failed attempts
		s.handleFailedLogin(ctx, &user)
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "failed", "invalid_password")
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "invalid email or password")
	}

	// Check if email verification is required
	if s.config.RequireEmailVerification && !user.EmailVerified {
		s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "blocked", "email_not_verified")
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeAccountNotVerified, "email verification required")
	}

	// Check if MFA is required
	if user.MFAEnabled {
		if req.MFACode == "" {
			// Return that MFA is required
			return &AuthResponse{
				RequiresMFA: true,
				MFATypes:    []string{"totp"},
			}, nil
		}

		// Verify MFA code
		if !s.verifyMFACode(ctx, &user, req.MFACode) {
			s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "failed", "invalid_mfa")
			return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "invalid MFA code")
		}
	}

	// Reset failed login attempts
	s.resetFailedLoginAttempts(ctx, &user)

	// Create session
	var session *models.Session
	if req.DeviceInfo != nil {
		// Set extended session duration for "remember me"
		if req.RememberMe {
			req.DeviceInfo.RememberMe = true
		}
		
		session, err = s.sessionManager.CreateSession(ctx, user.ID, req.DeviceInfo)
		if err != nil {
			s.logger.Error("Failed to create session", "error", err)
			return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to create session")
		}
	}

	// Update last login
	updates := map[string]interface{}{
		"last_login_at": time.Now(),
		"login_count":   gorm.Expr("login_count + ?", 1),
	}
	if req.DeviceInfo != nil {
		updates["last_login_ip"] = req.DeviceInfo.IPAddress
	}
	s.db.WithContext(ctx).Model(&user).Updates(updates)

	// Generate JWT tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		"", // teamID
		"", // teamName
		"", // teamPlan
		s.getUserScopes(&user),
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate tokens")
	}

	// Log successful login
	s.logLoginAttempt(ctx, req.Email, req.DeviceInfo.IPAddress, "success", "")
	s.logSecurityEvent(ctx, user.ID, "user_logged_in", user.Email, req.DeviceInfo.IPAddress)

	// Send security alert for new device
	if req.DeviceInfo != nil && !s.isKnownDevice(ctx, user.ID, req.DeviceInfo) {
		go s.sendNewDeviceAlert(ctx, &user, req.DeviceInfo)
	}

	return &AuthResponse{
		User: &UserResponse{
			ID:            user.ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Status:        user.Status,
			Role:          user.Role,
			EmailVerified: user.EmailVerified,
			MFAEnabled:    user.MFAEnabled,
		},
		AccessToken:    tokenPair.AccessToken,
		RefreshToken:   tokenPair.RefreshToken,
		ExpiresIn:      int64(tokenPair.AccessTokenExpiresAt.Sub(time.Now()).Seconds()),
		TokenType:      tokenPair.TokenType,
		SessionID:      getSessionID(session),
		RequiresAction: s.getRequiredActions(&user),
	}, nil
}

// VerifyEmail verifies a user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	tokenHash := s.hashToken(token)
	
	var emailToken models.EmailToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND token_type = 'verification' AND consumed_at IS NULL", tokenHash).
		First(&emailToken).Error

	if err != nil {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "invalid or expired verification token")
	}

	// Check expiry
	if time.Now().After(emailToken.ExpiresAt) {
		return errors.New(errors.ErrorTypeValidation, errors.CodeTokenExpired, "verification token has expired")
	}

	// Begin transaction
	tx := s.db.Begin()

	// Update user
	if err := tx.Model(&models.User{}).
		Where("id = ?", emailToken.UserID).
		Updates(map[string]interface{}{
			"email_verified": true,
			"status":         "active",
			"updated_at":     time.Now(),
		}).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to verify email")
	}

	// Mark token as consumed
	emailToken.ConsumedAt = &[]time.Time{time.Now()}[0]
	if err := tx.Save(&emailToken).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to update token")
	}

	tx.Commit()

	// Log event
	s.logSecurityEvent(ctx, emailToken.UserID, "email_verified", emailToken.Email, "")

	return nil
}

// RequestPasswordReset initiates password reset process
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	// Rate limiting
	if !s.rateLimiter.Allow("password_reset", email) {
		return errors.New(errors.ErrorTypeRateLimit, errors.CodeTooManyAttempts, "too many password reset requests")
	}

	// Get user (don't reveal if exists)
	var user models.User
	err := s.db.WithContext(ctx).
		Where("LOWER(email) = LOWER(?) AND deleted_at IS NULL", email).
		First(&user).Error

	if err != nil {
		// Pretend success to not reveal if user exists
		s.logger.Info("Password reset requested for non-existent email", "email", email)
		return nil
	}

	// Generate reset token
	resetToken, tokenHash, err := s.generateSecureToken()
	if err != nil {
		return err
	}

	// Create token record
	emailToken := &models.EmailToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenType: "password_reset",
		TokenHash: tokenHash,
		Email:     user.Email,
		IPAddress: "", // Would come from request context
		ExpiresAt: time.Now().Add(s.config.PasswordResetExpiry),
		CreatedAt: time.Now(),
	}

	if err := s.db.Create(emailToken).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create reset token")
	}

	// Send reset email
	go func() {
		if err := s.emailService.SendPasswordResetEmail(context.Background(), user.Email, resetToken); err != nil {
			s.logger.Error("Failed to send password reset email", "error", err, "email", user.Email)
		}
	}()

	// Log event
	s.logSecurityEvent(ctx, user.ID, "password_reset_requested", user.Email, "")

	return nil
}

// ResetPassword resets user password with token
func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	tokenHash := s.hashToken(token)
	
	// Get token
	var emailToken models.EmailToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND token_type = 'password_reset' AND consumed_at IS NULL", tokenHash).
		First(&emailToken).Error

	if err != nil {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "invalid or expired reset token")
	}

	// Check expiry
	if time.Now().After(emailToken.ExpiresAt) {
		return errors.New(errors.ErrorTypeValidation, errors.CodeTokenExpired, "reset token has expired")
	}

	// Get user
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", emailToken.UserID).First(&user).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "user not found")
	}

	// Validate new password
	if err := s.validator.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.config.BcryptCost)
	if err != nil {
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to hash password")
	}

	// Check password history
	if err := s.validator.ValidatePasswordHistory(ctx, user.ID, string(hashedPassword)); err != nil {
		return err
	}

	// Begin transaction
	tx := s.db.Begin()

	// Update user password
	updates := map[string]interface{}{
		"password_hash":         string(hashedPassword),
		"password_changed_at":   time.Now(),
		"failed_login_attempts": 0,
		"locked_until":          nil,
		"updated_at":            time.Now(),
	}

	if err := tx.Model(&user).Updates(updates).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to update password")
	}

	// Add to password history
	passwordHistory := &models.PasswordHistory{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	if err := tx.Create(passwordHistory).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to update password history")
	}

	// Mark token as consumed
	emailToken.ConsumedAt = &[]time.Time{time.Now()}[0]
	if err := tx.Save(&emailToken).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to consume token")
	}

	// Revoke all sessions for security
	s.sessionManager.RevokeAllSessions(ctx, user.ID)

	tx.Commit()

	// Send security alert
	go func() {
		alert := "Your password has been reset. If this wasn't you, please contact support immediately."
		s.emailService.SendSecurityAlert(context.Background(), user.Email, alert)
	}()

	// Log event
	s.logSecurityEvent(ctx, user.ID, "password_reset_completed", user.Email, "")

	return nil
}

// Logout revokes the current session
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := s.sessionManager.RevokeSession(ctx, sessionID, "user_logout"); err != nil {
		return err
	}

	// Log event
	s.logSecurityEvent(ctx, "", "user_logged_out", "", "")

	return nil
}

// LogoutAllSessions revokes all user sessions
func (s *AuthService) LogoutAllSessions(ctx context.Context, userID string, exceptCurrent string) error {
	if err := s.sessionManager.RevokeAllSessions(ctx, userID, exceptCurrent); err != nil {
		return err
	}

	// Log event
	s.logSecurityEvent(ctx, userID, "all_sessions_logged_out", "", "")

	return nil
}

// RefreshToken refreshes authentication tokens
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token with JWT service
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeTokenInvalid, "invalid refresh token")
	}

	// Check if it's actually a refresh token
	if claims.TokenType != jwt.RefreshToken {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeTokenInvalid, "not a refresh token")
	}

	// Get user
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "user not found")
	}

	// Check if user is still active
	if user.Status != "active" {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeAccountDisabled, "account is not active")
	}

	// Generate new token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Role,
		claims.TeamID,
		claims.TeamName,
		claims.TeamPlan,
		claims.Scopes,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate tokens")
	}

	return &AuthResponse{
		User: &UserResponse{
			ID:            user.ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Status:        user.Status,
			Role:          user.Role,
			EmailVerified: user.EmailVerified,
		},
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int64(tokenPair.AccessTokenExpiresAt.Sub(time.Now()).Seconds()),
		TokenType:    tokenPair.TokenType,
	}, nil
}

// Helper methods

func (s *AuthService) generateSecureToken() (token string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate token")
	}
	token = hex.EncodeToString(b)
	hash = s.hashToken(token)
	return token, hash, nil
}

func (s *AuthService) hashToken(token string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
}

func (s *AuthService) handleFailedLogin(ctx context.Context, user *models.User) {
	user.FailedLoginAttempts++
	
	updates := map[string]interface{}{
		"failed_login_attempts": user.FailedLoginAttempts,
	}

	// Lock account if max attempts reached
	if user.FailedLoginAttempts >= s.config.MaxLoginAttempts {
		lockedUntil := time.Now().Add(s.config.LockoutDuration)
		updates["locked_until"] = lockedUntil
		
		// Send security alert
		go func() {
			alert := fmt.Sprintf("Your account has been locked due to %d failed login attempts", user.FailedLoginAttempts)
			s.emailService.SendSecurityAlert(context.Background(), user.Email, alert)
		}()
		
		s.logSecurityEvent(ctx, user.ID, "account_locked", user.Email, "")
	}

	s.db.WithContext(ctx).Model(user).Updates(updates)
}

func (s *AuthService) resetFailedLoginAttempts(ctx context.Context, user *models.User) {
	s.db.WithContext(ctx).Model(user).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	})
}

func (s *AuthService) verifyMFACode(ctx context.Context, user *models.User, code string) bool {
	// TODO: Implement TOTP verification
	// This would use a library like github.com/pquerna/otp
	return false
}

func (s *AuthService) getUserScopes(user *models.User) []string {
	// Define scopes based on role
	switch user.Role {
	case "owner", "admin":
		return []string{"*"}
	case "member":
		return []string{"user:read", "user:write", "workflow:read", "workflow:write"}
	case "viewer":
		return []string{"user:read", "workflow:read"}
	default:
		return []string{"user:read"}
	}
}

func (s *AuthService) getRequiredActions(user *models.User) []string {
	actions := []string{}
	
	if !user.EmailVerified && s.config.RequireEmailVerification {
		actions = append(actions, "verify_email")
	}
	
	if s.config.RequireMFA && !user.MFAEnabled {
		actions = append(actions, "setup_mfa")
	}
	
	// Check if password needs to be changed
	passwordAge := time.Since(user.PasswordChangedAt)
	if passwordAge > 90*24*time.Hour {
		actions = append(actions, "change_password")
	}
	
	return actions
}

func (s *AuthService) isKnownDevice(ctx context.Context, userID string, device *SessionCreateRequest) bool {
	var count int64
	s.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("user_id = ? AND device_id = ?", userID, device.DeviceID).
		Count(&count)
	
	return count > 0
}

func (s *AuthService) sendNewDeviceAlert(ctx context.Context, user *models.User, device *SessionCreateRequest) {
	alert := fmt.Sprintf("New login from %s (%s) at IP %s", device.DeviceName, device.UserAgent, device.IPAddress)
	s.emailService.SendSecurityAlert(ctx, user.Email, alert)
}

func (s *AuthService) logSecurityEvent(ctx context.Context, userID string, eventType string, email string, ipAddress string) {
	if !s.config.LogSecurityEvents {
		return
	}

	event := &models.SecurityEvent{
		ID:            uuid.New().String(),
		EventType:     eventType,
		EventCategory: "auth",
		Severity:      "info",
		Description:   fmt.Sprintf("Authentication event: %s", eventType),
		IPAddress:     ipAddress,
		CreatedAt:     time.Now(),
	}

	if userID != "" {
		event.UserID = &userID
	}

	if email != "" {
		event.Details = models.JSONB{"email": email}
	}

	// Log asynchronously
	go func() {
		if err := s.db.Create(event).Error; err != nil {
			s.logger.Error("Failed to log security event", "error", err, "event_type", eventType)
		}
	}()
}

func (s *AuthService) logLoginAttempt(ctx context.Context, email string, ipAddress string, status string, failureReason string) {
	attempt := &models.LoginAttempt{
		ID:            uuid.New().String(),
		Email:         email,
		IPAddress:     ipAddress,
		AttemptType:   "password",
		Status:        status,
		FailureReason: failureReason,
		CreatedAt:     time.Now(),
	}

	// Get user ID if exists
	var user models.User
	if s.db.Where("LOWER(email) = LOWER(?)", email).First(&user).Error == nil {
		attempt.UserID = &user.ID
	}

	// Log asynchronously
	go func() {
		if err := s.db.Create(attempt).Error; err != nil {
			s.logger.Error("Failed to log login attempt", "error", err)
		}
	}()
}

func getSessionID(session *models.Session) string {
	if session != nil {
		return session.ID
	}
	return ""
}

// Response types

// AuthResponse contains authentication response data
type AuthResponse struct {
	User           *UserResponse `json:"user,omitempty"`
	AccessToken    string        `json:"access_token,omitempty"`
	RefreshToken   string        `json:"refresh_token,omitempty"`
	ExpiresIn      int64         `json:"expires_in,omitempty"`
	TokenType      string        `json:"token_type,omitempty"`
	SessionID      string        `json:"session_id,omitempty"`
	RequiresMFA    bool          `json:"requires_mfa,omitempty"`
	MFATypes       []string      `json:"mfa_types,omitempty"`
	RequiresAction []string      `json:"requires_action,omitempty"`
}

// UserResponse contains user data for responses
type UserResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	Status        string    `json:"status"`
	Role          string    `json:"role"`
	EmailVerified bool      `json:"email_verified"`
	MFAEnabled    bool      `json:"mfa_enabled"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}