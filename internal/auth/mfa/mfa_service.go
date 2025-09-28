package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service provides MFA operations
type Service struct {
	db       *gorm.DB
	config   *Config
	logger   logger.Logger
}

// Config contains MFA configuration
type Config struct {
	Issuer           string        `json:"issuer"`
	Algorithm        string        `json:"algorithm"` // SHA1, SHA256, SHA512
	Digits           int           `json:"digits"`    // 6 or 8
	Period           uint          `json:"period"`    // seconds (usually 30)
	Skew             uint          `json:"skew"`      // allow N periods before/after
	BackupCodeCount  int           `json:"backup_code_count"`
	BackupCodeLength int           `json:"backup_code_length"`
	QRCodeSize       int           `json:"qr_code_size"`
	EnforceBackups   bool          `json:"enforce_backups"`
	AllowMultiple    bool          `json:"allow_multiple_devices"`
}

// DefaultConfig returns default MFA configuration
func DefaultConfig() *Config {
	return &Config{
		Issuer:           "n8n Pro",
		Algorithm:        "SHA256",
		Digits:           6,
		Period:           30,
		Skew:             1, // Accept codes 30 seconds before/after
		BackupCodeCount:  10,
		BackupCodeLength: 8,
		QRCodeSize:       256,
		EnforceBackups:   true,
		AllowMultiple:    false,
	}
}

// NewService creates a new MFA service
func NewService(db *gorm.DB, config *Config) *Service {
	if config == nil {
		config = DefaultConfig()
	}

	return &Service{
		db:     db,
		config: config,
		logger: logger.New("mfa-service"),
	}
}

// MFASetupResponse contains MFA setup information
type MFASetupResponse struct {
	Secret       string   `json:"secret"`
	QRCode       string   `json:"qr_code"`       // Base64 encoded PNG
	ManualEntry  string   `json:"manual_entry"`  // For manual entry
	BackupCodes  []string `json:"backup_codes"`
	RecoveryCode string   `json:"recovery_code"` // Single-use recovery code
}

// MFADevice represents a registered MFA device
type MFADevice struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"` // totp, sms, email
	IsDefault    bool      `json:"is_default"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (s *Service) GenerateTOTPSecret(ctx context.Context, userID string, email string) (*MFASetupResponse, error) {
	// Check if user already has MFA enabled (unless multiple devices allowed)
	if !s.config.AllowMultiple {
		var user models.User
		if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get user")
		}

		if user.MFAEnabled {
			return nil, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "MFA is already enabled for this account")
		}
	}

	// Generate secret
	secret := s.generateSecret()
	
	// Create TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.Issuer,
		AccountName: email,
		Period:      s.config.Period,
		Digits:      otp.DigitsSix,
		Algorithm:   s.getAlgorithm(),
		Secret:      []byte(secret),
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate TOTP key")
	}

	// Generate QR code
	qrCode, err := s.generateQRCode(key)
	if err != nil {
		return nil, err
	}

	// Generate backup codes
	backupCodes, hashedCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, err
	}

	// Generate recovery code (single-use master recovery)
	recoveryCode := s.generateRecoveryCode()

	// Store temporarily in a pending state (not yet verified)
	// This would typically be stored in a temporary table or cache
	// until the user verifies with a code
	
	response := &MFASetupResponse{
		Secret:       key.Secret(),
		QRCode:       qrCode,
		ManualEntry:  key.Secret(),
		BackupCodes:  backupCodes,
		RecoveryCode: recoveryCode,
	}

	// Store hashed backup codes (would be done after verification in production)
	for _, hashedCode := range hashedCodes {
		backupCode := &models.MFABackupCode{
			ID:       uuid.New().String(),
			UserID:   userID,
			CodeHash: hashedCode,
			CreatedAt: time.Now(),
		}
		// These would be saved after user verifies the setup
		_ = backupCode
	}

	s.logger.Info("Generated TOTP secret for user", "user_id", userID)

	return response, nil
}

// EnableTOTP enables TOTP for a user after verification
func (s *Service) EnableTOTP(ctx context.Context, userID string, secret string, verificationCode string) error {
	// Verify the code first
	valid := totp.Validate(verificationCode, secret)
	if !valid {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "invalid verification code")
	}

	// Begin transaction
	tx := s.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update user
	updates := map[string]interface{}{
		"mfa_enabled": true,
		"mfa_secret":  secret,
		"updated_at":  time.Now(),
	}

	if err := tx.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to enable MFA")
	}

	// TODO: Save backup codes that were generated during setup

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to commit MFA enablement")
	}

	// Log security event
	s.logSecurityEvent(ctx, userID, "mfa_enabled", "TOTP MFA has been enabled")

	return nil
}

// VerifyTOTP verifies a TOTP code
func (s *Service) VerifyTOTP(ctx context.Context, userID string, code string) (bool, error) {
	// Get user's secret
	var user models.User
	if err := s.db.WithContext(ctx).Select("id, mfa_secret, mfa_enabled").Where("id = ?", userID).First(&user).Error; err != nil {
		return false, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get user")
	}

	if !user.MFAEnabled {
		return false, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "MFA is not enabled for this account")
	}

	if user.MFASecret == "" {
		return false, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "MFA secret not found")
	}

	// Validate TOTP code
	valid := totp.Validate(code, user.MFASecret)
	
	if valid {
		s.logger.Info("TOTP verification successful", "user_id", userID)
		
		// Update last MFA verification time
		s.db.Model(&models.Session{}).
			Where("user_id = ? AND is_active = true", userID).
			Update("mfa_verified", true)
	} else {
		s.logger.Warn("TOTP verification failed", "user_id", userID)
		s.logSecurityEvent(ctx, userID, "mfa_failed", "Failed TOTP verification attempt")
	}

	return valid, nil
}

// VerifyBackupCode verifies and consumes a backup code
func (s *Service) VerifyBackupCode(ctx context.Context, userID string, code string) (bool, error) {
	// Normalize code (remove spaces, dashes)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ToUpper(code)

	// Get unused backup codes for user
	var backupCodes []models.MFABackupCode
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND used_at IS NULL", userID).
		Find(&backupCodes).Error; err != nil {
		return false, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get backup codes")
	}

	// Check each code
	for _, backupCode := range backupCodes {
		if err := bcrypt.CompareHashAndPassword([]byte(backupCode.CodeHash), []byte(code)); err == nil {
			// Code matches - mark as used
			now := time.Now()
			backupCode.UsedAt = &now
			
			if err := s.db.Save(&backupCode).Error; err != nil {
				return false, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to update backup code")
			}

			s.logger.Info("Backup code used successfully", "user_id", userID)
			s.logSecurityEvent(ctx, userID, "backup_code_used", "MFA backup code was used")
			
			// Check remaining codes and warn if low
			var remainingCount int64
			s.db.Model(&models.MFABackupCode{}).
				Where("user_id = ? AND used_at IS NULL", userID).
				Count(&remainingCount)
			
			if remainingCount < 3 {
				s.logSecurityEvent(ctx, userID, "backup_codes_low", 
					fmt.Sprintf("Only %d backup codes remaining", remainingCount))
			}

			return true, nil
		}
	}

	s.logger.Warn("Invalid backup code attempted", "user_id", userID)
	s.logSecurityEvent(ctx, userID, "backup_code_failed", "Failed backup code verification attempt")

	return false, nil
}

// DisableMFA disables MFA for a user
func (s *Service) DisableMFA(ctx context.Context, userID string, password string) error {
	// Verify user's password first
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get user")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "invalid password")
	}

	// Begin transaction
	tx := s.db.Begin()

	// Disable MFA
	updates := map[string]interface{}{
		"mfa_enabled": false,
		"mfa_secret":  "",
		"updated_at":  time.Now(),
	}

	if err := tx.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to disable MFA")
	}

	// Delete backup codes
	if err := tx.Where("user_id = ?", userID).Delete(&models.MFABackupCode{}).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to delete backup codes")
	}

	// Update all active sessions to mark MFA as not verified
	tx.Model(&models.Session{}).
		Where("user_id = ? AND is_active = true", userID).
		Update("mfa_verified", false)

	tx.Commit()

	s.logger.Info("MFA disabled for user", "user_id", userID)
	s.logSecurityEvent(ctx, userID, "mfa_disabled", "MFA has been disabled")

	return nil
}

// RegenerateBackupCodes generates new backup codes
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID string, password string) ([]string, error) {
	// Verify password
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get user")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials, "invalid password")
	}

	if !user.MFAEnabled {
		return nil, errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "MFA is not enabled")
	}

	// Generate new codes
	codes, hashedCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, err
	}

	// Begin transaction
	tx := s.db.Begin()

	// Delete old backup codes
	if err := tx.Where("user_id = ?", userID).Delete(&models.MFABackupCode{}).Error; err != nil {
		tx.Rollback()
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to delete old backup codes")
	}

	// Save new backup codes
	for _, hashedCode := range hashedCodes {
		backupCode := &models.MFABackupCode{
			ID:        uuid.New().String(),
			UserID:    userID,
			CodeHash:  hashedCode,
			CreatedAt: time.Now(),
		}
		if err := tx.Create(backupCode).Error; err != nil {
			tx.Rollback()
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to create backup code")
		}
	}

	tx.Commit()

	s.logger.Info("Regenerated backup codes for user", "user_id", userID, "count", len(codes))
	s.logSecurityEvent(ctx, userID, "backup_codes_regenerated", "MFA backup codes were regenerated")

	return codes, nil
}

// GetMFAStatus returns the MFA status for a user
func (s *Service) GetMFAStatus(ctx context.Context, userID string) (*MFAStatus, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to get user")
	}

	// Count remaining backup codes
	var backupCodeCount int64
	s.db.Model(&models.MFABackupCode{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Count(&backupCodeCount)

	status := &MFAStatus{
		Enabled:              user.MFAEnabled,
		Type:                 "totp",
		BackupCodesRemaining: int(backupCodeCount),
		LastVerified:         nil, // Would come from session
	}

	// Get last MFA verification from session
	var session models.Session
	if err := s.db.Where("user_id = ? AND mfa_verified = true", userID).
		Order("last_activity_at DESC").
		First(&session).Error; err == nil {
		status.LastVerified = &session.LastActivityAt
	}

	return status, nil
}

// MFAStatus represents the current MFA status
type MFAStatus struct {
	Enabled              bool       `json:"enabled"`
	Type                 string     `json:"type"`
	BackupCodesRemaining int        `json:"backup_codes_remaining"`
	LastVerified         *time.Time `json:"last_verified,omitempty"`
	Devices              []MFADevice `json:"devices,omitempty"`
}

// Helper methods

func (s *Service) generateSecret() string {
	// Generate random bytes
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(err)
	}
	
	// Encode to base32
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
}

func (s *Service) generateQRCode(key *otp.Key) (string, error) {
	// Generate QR code image
	img, err := key.Image(s.config.QRCodeSize, s.config.QRCodeSize)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to generate QR code")
	}

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to encode QR code")
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	
	return "data:image/png;base64," + encoded, nil
}

func (s *Service) generateBackupCodes() ([]string, []string, error) {
	codes := make([]string, s.config.BackupCodeCount)
	hashedCodes := make([]string, s.config.BackupCodeCount)

	for i := 0; i < s.config.BackupCodeCount; i++ {
		// Generate random code
		code := s.generateRandomCode(s.config.BackupCodeLength)
		codes[i] = s.formatBackupCode(code)

		// Hash the code for storage
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to hash backup code")
		}
		hashedCodes[i] = string(hashed)
	}

	return codes, hashedCodes, nil
}

func (s *Service) generateRandomCode(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // Base32 alphabet
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func (s *Service) formatBackupCode(code string) string {
	// Format as XXXX-XXXX for readability
	if len(code) == 8 {
		return code[:4] + "-" + code[4:]
	}
	return code
}

func (s *Service) generateRecoveryCode() string {
	// Generate a longer, more secure recovery code
	code := s.generateRandomCode(16)
	// Format as XXXX-XXXX-XXXX-XXXX
	return fmt.Sprintf("%s-%s-%s-%s", code[:4], code[4:8], code[8:12], code[12:])
}

func (s *Service) getAlgorithm() otp.Algorithm {
	switch s.config.Algorithm {
	case "SHA256":
		return otp.AlgorithmSHA256
	case "SHA512":
		return otp.AlgorithmSHA512
	default:
		return otp.AlgorithmSHA1
	}
}

func (s *Service) logSecurityEvent(ctx context.Context, userID string, eventType string, description string) {
	event := &models.SecurityEvent{
		ID:            uuid.New().String(),
		UserID:        &userID,
		EventType:     eventType,
		EventCategory: "mfa",
		Severity:      "info",
		Description:   description,
		CreatedAt:     time.Now(),
	}

	if strings.Contains(eventType, "failed") {
		event.Severity = "warning"
	}
	if strings.Contains(eventType, "disabled") {
		event.Severity = "warning"
	}

	// Log asynchronously
	go func() {
		if err := s.db.Create(event).Error; err != nil {
			s.logger.Error("Failed to log security event", "error", err, "event_type", eventType)
		}
	}()
}

// Add missing import
import "math/big"