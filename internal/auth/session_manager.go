package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/mssola/user_agent"
	"gorm.io/gorm"
)

// SessionManager handles user session lifecycle
type SessionManager struct {
	db     *gorm.DB
	config *SessionConfig
	logger logger.Logger
}

// SessionConfig contains session configuration
type SessionConfig struct {
	SessionDuration       time.Duration `json:"session_duration"`
	RefreshTokenDuration  time.Duration `json:"refresh_token_duration"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`
	AllowMultipleDevices  bool          `json:"allow_multiple_devices"`
	TrustDeviceDuration   time.Duration `json:"trust_device_duration"`
	InactivityTimeout     time.Duration `json:"inactivity_timeout"`
	ExtendOnActivity      bool          `json:"extend_on_activity"`
	RequireMFAForNewDevice bool         `json:"require_mfa_for_new_device"`
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		SessionDuration:       24 * time.Hour,
		RefreshTokenDuration:  7 * 24 * time.Hour,
		MaxConcurrentSessions: 5,
		AllowMultipleDevices:  true,
		TrustDeviceDuration:   30 * 24 * time.Hour,
		InactivityTimeout:     2 * time.Hour,
		ExtendOnActivity:      true,
		RequireMFAForNewDevice: false,
	}
}

// NewSessionManager creates a new session manager
func NewSessionManager(db *gorm.DB, config *SessionConfig) *SessionManager {
	if config == nil {
		config = DefaultSessionConfig()
	}

	return &SessionManager{
		db:     db,
		config: config,
		logger: logger.New("session-manager"),
	}
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(ctx context.Context, userID string, req *SessionCreateRequest) (*models.Session, error) {
	// Validate user exists and is active
	var user models.User
	if err := sm.db.WithContext(ctx).Where("id = ? AND status = 'active' AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "user not found or inactive")
		}
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to validate user")
	}

	// Check concurrent session limit
	if err := sm.enforceSessionLimits(ctx, userID); err != nil {
		return nil, err
	}

	// Parse user agent
	ua := user_agent.New(req.UserAgent)
	browserName, browserVersion := ua.Browser()

	// Generate tokens
	refreshToken, refreshTokenHash, err := sm.generateToken()
	if err != nil {
		return nil, err
	}

	accessToken, accessTokenHash, err := sm.generateToken()
	if err != nil {
		return nil, err
	}

	// Create session
	session := &models.Session{
		UserID:           userID,
		RefreshTokenHash: refreshTokenHash,
		AccessTokenHash:  accessTokenHash,
		DeviceID:         req.DeviceID,
		DeviceName:       req.DeviceName,
		DeviceType:       sm.detectDeviceType(ua),
		Browser:          browserName,
		BrowserVersion:   browserVersion,
		OS:               ua.OS(),
		OSVersion:        "", // UA library doesn't provide OS version
		IPAddress:        req.IPAddress,
		IPLocation:       req.IPLocation,
		CountryCode:      req.CountryCode,
		City:             req.City,
		UserAgent:        req.UserAgent,
		IsActive:         true,
		IsTrusted:        false,
		MFAVerified:      false,
		ExpiresAt:        time.Now().Add(sm.config.SessionDuration),
		LastActivityAt:   time.Now(),
		CreatedAt:        time.Now(),
	}

	// Check if device is trusted
	if req.DeviceID != "" {
		trusted, err := sm.isDeviceTrusted(ctx, userID, req.DeviceID)
		if err != nil {
			sm.logger.Error("Failed to check device trust", "error", err)
		}
		session.IsTrusted = trusted
	}

	// Save session
	if err := sm.db.WithContext(ctx).Create(session).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create session")
	}

	// Store tokens in response (not hashes)
	session.RefreshTokenHash = refreshToken
	session.AccessTokenHash = accessToken

	// Log session creation
	sm.logSecurityEvent(ctx, userID, "session_created", session.ID, req.IPAddress)

	return session, nil
}

// SessionCreateRequest contains session creation parameters
type SessionCreateRequest struct {
	DeviceID     string `json:"device_id"`
	DeviceName   string `json:"device_name"`
	UserAgent    string `json:"user_agent"`
	IPAddress    string `json:"ip_address"`
	IPLocation   string `json:"ip_location"`
	CountryCode  string `json:"country_code"`
	City         string `json:"city"`
	TrustDevice  bool   `json:"trust_device"`
	RememberMe   bool   `json:"remember_me"`
}

// ValidateSession validates an existing session
func (sm *SessionManager) ValidateSession(ctx context.Context, sessionID string, tokenHash string) (*models.Session, error) {
	var session models.Session
	
	err := sm.db.WithContext(ctx).
		Where("id = ? AND is_active = true AND expires_at > ?", sessionID, time.Now()).
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeTokenInvalid, "session not found or expired")
		}
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to retrieve session")
	}

	// Validate token hash
	if session.RefreshTokenHash != tokenHash && session.AccessTokenHash != tokenHash {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeTokenInvalid, "invalid session token")
	}

	// Check inactivity timeout
	if sm.config.InactivityTimeout > 0 {
		if time.Since(session.LastActivityAt) > sm.config.InactivityTimeout {
			// Mark session as inactive
			sm.db.WithContext(ctx).Model(&session).Update("is_active", false)
			return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeTokenExpired, "session expired due to inactivity")
		}
	}

	// Update last activity
	if sm.config.ExtendOnActivity {
		updates := map[string]interface{}{
			"last_activity_at": time.Now(),
		}
		
		// Extend session if configured
		newExpiry := time.Now().Add(sm.config.SessionDuration)
		if newExpiry.After(session.ExpiresAt) {
			updates["expires_at"] = newExpiry
		}

		sm.db.WithContext(ctx).Model(&session).Updates(updates)
	}

	return &session, nil
}

// RefreshSession refreshes session tokens
func (sm *SessionManager) RefreshSession(ctx context.Context, sessionID string, oldRefreshToken string) (*models.Session, error) {
	// Hash the old token to compare
	oldTokenHash := sm.hashToken(oldRefreshToken)
	
	// Validate existing session
	session, err := sm.ValidateSession(ctx, sessionID, oldTokenHash)
	if err != nil {
		return nil, err
	}

	// Generate new tokens
	newRefreshToken, newRefreshTokenHash, err := sm.generateToken()
	if err != nil {
		return nil, err
	}

	newAccessToken, newAccessTokenHash, err := sm.generateToken()
	if err != nil {
		return nil, err
	}

	// Update session with new tokens
	updates := map[string]interface{}{
		"refresh_token_hash": newRefreshTokenHash,
		"access_token_hash":  newAccessTokenHash,
		"last_activity_at":   time.Now(),
		"expires_at":         time.Now().Add(sm.config.SessionDuration),
	}

	if err := sm.db.WithContext(ctx).Model(session).Updates(updates).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to refresh session")
	}

	// Return session with actual tokens (not hashes)
	session.RefreshTokenHash = newRefreshToken
	session.AccessTokenHash = newAccessToken

	// Log token refresh
	sm.logSecurityEvent(ctx, session.UserID, "session_refreshed", session.ID, session.IPAddress)

	return session, nil
}

// RevokeSession revokes a specific session
func (sm *SessionManager) RevokeSession(ctx context.Context, sessionID string, reason string) error {
	updates := map[string]interface{}{
		"is_active":      false,
		"revoked_at":     time.Now(),
		"revoked_reason": reason,
	}

	result := sm.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("id = ?", sessionID).
		Updates(updates)

	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to revoke session")
	}

	if result.RowsAffected == 0 {
		return errors.New(errors.ErrorTypeNotFound, errors.CodeResourceNotFound, "session not found")
	}

	return nil
}

// RevokeAllSessions revokes all sessions for a user
func (sm *SessionManager) RevokeAllSessions(ctx context.Context, userID string, exceptSessionID ...string) error {
	query := sm.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("user_id = ? AND is_active = true", userID)

	if len(exceptSessionID) > 0 && exceptSessionID[0] != "" {
		query = query.Where("id != ?", exceptSessionID[0])
	}

	updates := map[string]interface{}{
		"is_active":      false,
		"revoked_at":     time.Now(),
		"revoked_reason": "bulk_revocation",
	}

	if err := query.Updates(updates).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to revoke sessions")
	}

	// Log security event
	sm.logSecurityEvent(ctx, userID, "all_sessions_revoked", "", "")

	return nil
}

// GetActiveSessions retrieves all active sessions for a user
func (sm *SessionManager) GetActiveSessions(ctx context.Context, userID string) ([]*models.Session, error) {
	var sessions []*models.Session
	
	err := sm.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true AND expires_at > ?", userID, time.Now()).
		Order("last_activity_at DESC").
		Find(&sessions).Error

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to retrieve sessions")
	}

	// Don't return token hashes
	for _, session := range sessions {
		session.RefreshTokenHash = ""
		session.AccessTokenHash = ""
	}

	return sessions, nil
}

// TrustDevice marks a device as trusted
func (sm *SessionManager) TrustDevice(ctx context.Context, userID string, deviceID string, deviceName string) error {
	if deviceID == "" {
		deviceID = sm.generateDeviceID()
	}

	trustToken, trustTokenHash, err := sm.generateToken()
	if err != nil {
		return err
	}

	trustedDevice := &models.TrustedDevice{
		UserID:            userID,
		DeviceFingerprint: deviceID,
		DeviceName:        deviceName,
		TrustTokenHash:    trustTokenHash,
		IsActive:          true,
		LastUsedAt:        time.Now(),
		ExpiresAt:         time.Now().Add(sm.config.TrustDeviceDuration),
		CreatedAt:         time.Now(),
	}

	if err := sm.db.WithContext(ctx).Create(trustedDevice).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to trust device")
	}

	// Log security event
	sm.logSecurityEvent(ctx, userID, "device_trusted", deviceID, "")

	// Return the actual trust token (caller needs to store it)
	_ = trustToken

	return nil
}

// Helper functions

func (sm *SessionManager) enforceSessionLimits(ctx context.Context, userID string) error {
	if sm.config.MaxConcurrentSessions <= 0 {
		return nil // No limit
	}

	var count int64
	err := sm.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("user_id = ? AND is_active = true AND expires_at > ?", userID, time.Now()).
		Count(&count).Error

	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to count sessions")
	}

	if int(count) >= sm.config.MaxConcurrentSessions {
		// Revoke oldest session
		var oldestSession models.Session
		err := sm.db.WithContext(ctx).
			Where("user_id = ? AND is_active = true", userID).
			Order("last_activity_at ASC").
			First(&oldestSession).Error

		if err == nil {
			sm.RevokeSession(ctx, oldestSession.ID, "max_sessions_exceeded")
		}
	}

	return nil
}

func (sm *SessionManager) generateToken() (token string, hash string, err error) {
	// Generate random token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate token")
	}
	
	token = hex.EncodeToString(b)
	hash = sm.hashToken(token)
	
	return token, hash, nil
}

func (sm *SessionManager) hashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (sm *SessionManager) generateDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (sm *SessionManager) detectDeviceType(ua *user_agent.UserAgent) string {
	if ua.Mobile() {
		return "mobile"
	}
	if ua.Bot() {
		return "bot"
	}
	// Could add tablet detection logic here
	return "desktop"
}

func (sm *SessionManager) isDeviceTrusted(ctx context.Context, userID string, deviceID string) (bool, error) {
	var count int64
	err := sm.db.WithContext(ctx).
		Model(&models.TrustedDevice{}).
		Where("user_id = ? AND device_fingerprint = ? AND is_active = true AND expires_at > ?", 
			userID, deviceID, time.Now()).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (sm *SessionManager) logSecurityEvent(ctx context.Context, userID string, eventType string, sessionID string, ipAddress string) {
	event := &models.SecurityEvent{
		UserID:        &userID,
		EventType:     eventType,
		EventCategory: "auth",
		Severity:      "info",
		Description:   fmt.Sprintf("Session event: %s", eventType),
		IPAddress:     ipAddress,
		SessionID:     sessionID,
		CreatedAt:     time.Now(),
	}

	if strings.Contains(eventType, "revoked") || strings.Contains(eventType, "failed") {
		event.Severity = "warning"
	}

	// Log asynchronously to not block the main flow
	go func() {
		if err := sm.db.Create(event).Error; err != nil {
			sm.logger.Error("Failed to log security event", "error", err, "event_type", eventType)
		}
	}()
}