package validation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"n8n-pro/pkg/errors"
	
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

// AuthValidator provides authentication-specific validation
type AuthValidator struct {
	validator *validator.Validate
	db        *gorm.DB
	config    *AuthValidationConfig
}

// AuthValidationConfig contains validation configuration
type AuthValidationConfig struct {
	// Password requirements
	PasswordMinLength      int      `json:"password_min_length"`
	PasswordMaxLength      int      `json:"password_max_length"`
	PasswordRequireUpper   bool     `json:"password_require_upper"`
	PasswordRequireLower   bool     `json:"password_require_lower"`
	PasswordRequireNumber  bool     `json:"password_require_number"`
	PasswordRequireSpecial bool     `json:"password_require_special"`
	PasswordMinStrength    int      `json:"password_min_strength"` // 0-4 scale
	PasswordBannedWords    []string `json:"password_banned_words"`
	
	// Email validation
	EmailDomainWhitelist []string `json:"email_domain_whitelist"`
	EmailDomainBlacklist []string `json:"email_domain_blacklist"`
	
	// Username requirements
	UsernameMinLength int      `json:"username_min_length"`
	UsernameMaxLength int      `json:"username_max_length"`
	UsernamePattern   string   `json:"username_pattern"`
	ReservedUsernames []string `json:"reserved_usernames"`
	
	// Security
	MaxPasswordAge         int  `json:"max_password_age_days"`
	PreventPasswordReuse   int  `json:"prevent_password_reuse_count"`
	RequireCaptcha         bool `json:"require_captcha"`
	CaptchaScoreThreshold  float64 `json:"captcha_score_threshold"`
}

// DefaultAuthValidationConfig returns default validation configuration
func DefaultAuthValidationConfig() *AuthValidationConfig {
	return &AuthValidationConfig{
		PasswordMinLength:      12,
		PasswordMaxLength:      128,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireNumber:  true,
		PasswordRequireSpecial: true,
		PasswordMinStrength:    3,
		PasswordBannedWords: []string{
			"password", "123456", "qwerty", "admin", "letmein",
			"welcome", "monkey", "dragon", "master", "abc123",
		},
		EmailDomainBlacklist: []string{
			"tempmail.com", "throwaway.email", "guerrillamail.com",
		},
		UsernameMinLength: 3,
		UsernameMaxLength: 30,
		UsernamePattern:   "^[a-zA-Z0-9_-]+$",
		ReservedUsernames: []string{
			"admin", "root", "administrator", "system", "api",
			"support", "info", "noreply", "postmaster", "webmaster",
		},
		MaxPasswordAge:        90,
		PreventPasswordReuse:  5,
		RequireCaptcha:        true,
		CaptchaScoreThreshold: 0.5,
	}
}

// NewAuthValidator creates a new authentication validator
func NewAuthValidator(db *gorm.DB, config *AuthValidationConfig) (*AuthValidator, error) {
	if config == nil {
		config = DefaultAuthValidationConfig()
	}

	v := validator.New()
	av := &AuthValidator{
		validator: v,
		db:        db,
		config:    config,
	}

	// Register custom validators
	if err := av.registerCustomValidators(); err != nil {
		return nil, err
	}

	return av, nil
}

// registerCustomValidators registers all custom validation functions
func (av *AuthValidator) registerCustomValidators() error {
	validators := map[string]validator.Func{
		"password":       av.validatePassword,
		"email_unique":   av.validateEmailUnique,
		"username":       av.validateUsername,
		"phone":          av.validatePhone,
		"safe_input":     av.validateSafeInput,
		"no_sql_injection": av.validateNoSQLInjection,
	}

	for tag, fn := range validators {
		if err := av.validator.RegisterValidation(tag, fn); err != nil {
			return fmt.Errorf("failed to register validator %s: %w", tag, err)
		}
	}

	return nil
}

// ValidatePassword performs comprehensive password validation
func (av *AuthValidator) ValidatePassword(password string) error {
	var validationErrors []string

	// Length check
	if len(password) < av.config.PasswordMinLength {
		validationErrors = append(validationErrors, 
			fmt.Sprintf("password must be at least %d characters", av.config.PasswordMinLength))
	}
	if len(password) > av.config.PasswordMaxLength {
		validationErrors = append(validationErrors, 
			fmt.Sprintf("password must not exceed %d characters", av.config.PasswordMaxLength))
	}

	// Character requirements
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if av.config.PasswordRequireUpper && !hasUpper {
		validationErrors = append(validationErrors, "password must contain at least one uppercase letter")
	}
	if av.config.PasswordRequireLower && !hasLower {
		validationErrors = append(validationErrors, "password must contain at least one lowercase letter")
	}
	if av.config.PasswordRequireNumber && !hasNumber {
		validationErrors = append(validationErrors, "password must contain at least one number")
	}
	if av.config.PasswordRequireSpecial && !hasSpecial {
		validationErrors = append(validationErrors, "password must contain at least one special character")
	}

	// Check for banned words
	passwordLower := strings.ToLower(password)
	for _, banned := range av.config.PasswordBannedWords {
		if strings.Contains(passwordLower, strings.ToLower(banned)) {
			validationErrors = append(validationErrors, "password contains commonly used words")
			break
		}
	}

	// Check password strength
	strength := av.calculatePasswordStrength(password)
	if strength < av.config.PasswordMinStrength {
		validationErrors = append(validationErrors, 
			fmt.Sprintf("password strength is too weak (minimum: %d/4)", av.config.PasswordMinStrength))
	}

	if len(validationErrors) > 0 {
		return errors.NewValidationError(strings.Join(validationErrors, "; "))
	}

	return nil
}

// calculatePasswordStrength calculates password strength on a 0-4 scale
func (av *AuthValidator) calculatePasswordStrength(password string) int {
	strength := 0
	
	// Length contribution
	if len(password) >= 8 {
		strength++
	}
	if len(password) >= 12 {
		strength++
	}

	// Character diversity
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	charTypes := 0
	if hasUpper {
		charTypes++
	}
	if hasLower {
		charTypes++
	}
	if hasNumber {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	if charTypes >= 3 {
		strength++
	}
	if charTypes == 4 {
		strength++
	}

	// Cap at 4
	if strength > 4 {
		strength = 4
	}

	return strength
}

// ValidatePasswordHistory checks if password has been used before
func (av *AuthValidator) ValidatePasswordHistory(ctx context.Context, userID string, passwordHash string) error {
	if av.config.PreventPasswordReuse <= 0 {
		return nil
	}

	var count int64
	subQuery := av.db.WithContext(ctx).
		Table("password_history").
		Select("password_hash").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(av.config.PreventPasswordReuse)

	err := av.db.WithContext(ctx).
		Table("(?) as recent_passwords", subQuery).
		Where("password_hash = ?", passwordHash).
		Count(&count).Error

	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to check password history")
	}

	if count > 0 {
		return errors.NewValidationError(
			fmt.Sprintf("password has been used in the last %d passwords", av.config.PreventPasswordReuse))
	}

	return nil
}

// ValidateEmail performs email validation
func (av *AuthValidator) ValidateEmail(email string) error {
	// Basic email format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.NewValidationError("invalid email format")
	}

	// Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.NewValidationError("invalid email format")
	}
	domain := strings.ToLower(parts[1])

	// Check whitelist (if configured)
	if len(av.config.EmailDomainWhitelist) > 0 {
		allowed := false
		for _, allowedDomain := range av.config.EmailDomainWhitelist {
			if domain == strings.ToLower(allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.NewValidationError("email domain not allowed")
		}
	}

	// Check blacklist
	for _, blockedDomain := range av.config.EmailDomainBlacklist {
		if domain == strings.ToLower(blockedDomain) {
			return errors.NewValidationError("temporary email addresses are not allowed")
		}
	}

	return nil
}

// ValidateEmailUnique checks if email is unique in the database
func (av *AuthValidator) ValidateEmailUnique(ctx context.Context, email string, excludeUserID ...string) error {
	var count int64
	query := av.db.WithContext(ctx).
		Table("users").
		Where("LOWER(email) = LOWER(?) AND deleted_at IS NULL", email)

	if len(excludeUserID) > 0 && excludeUserID[0] != "" {
		query = query.Where("id != ?", excludeUserID[0])
	}

	if err := query.Count(&count).Error; err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery, "failed to check email uniqueness")
	}

	if count > 0 {
		return errors.NewEmailExistsError(email)
	}

	return nil
}

// ValidateUsername validates username format and uniqueness
func (av *AuthValidator) ValidateUsername(username string) error {
	// Length check
	if len(username) < av.config.UsernameMinLength {
		return errors.NewValidationError(
			fmt.Sprintf("username must be at least %d characters", av.config.UsernameMinLength))
	}
	if len(username) > av.config.UsernameMaxLength {
		return errors.NewValidationError(
			fmt.Sprintf("username must not exceed %d characters", av.config.UsernameMaxLength))
	}

	// Pattern check
	if av.config.UsernamePattern != "" {
		regex := regexp.MustCompile(av.config.UsernamePattern)
		if !regex.MatchString(username) {
			return errors.NewValidationError("username contains invalid characters")
		}
	}

	// Reserved username check
	usernameLower := strings.ToLower(username)
	for _, reserved := range av.config.ReservedUsernames {
		if usernameLower == strings.ToLower(reserved) {
			return errors.NewValidationError("username is reserved")
		}
	}

	return nil
}

// ValidatePhoneNumber validates phone number format
func (av *AuthValidator) ValidatePhoneNumber(phone string) error {
	// Remove common separators
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) || r == '+' {
			return r
		}
		return -1
	}, phone)

	// Basic international format check
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	if !phoneRegex.MatchString(cleaned) {
		return errors.NewValidationError("invalid phone number format")
	}

	return nil
}

// ValidateCaptcha validates CAPTCHA token
func (av *AuthValidator) ValidateCaptcha(token string, action string) error {
	if !av.config.RequireCaptcha {
		return nil
	}

	if token == "" {
		return errors.NewValidationError("CAPTCHA verification required")
	}

	// This would integrate with actual CAPTCHA service (reCAPTCHA, hCaptcha, etc.)
	// For now, just validate token format
	if len(token) < 20 {
		return errors.NewValidationError("invalid CAPTCHA token")
	}

	return nil
}

// ValidateSecurityAnswer validates security answer format
func (av *AuthValidator) ValidateSecurityAnswer(answer string) error {
	answer = strings.TrimSpace(answer)
	
	if len(answer) < 2 {
		return errors.NewValidationError("security answer is too short")
	}
	if len(answer) > 100 {
		return errors.NewValidationError("security answer is too long")
	}

	// Check for potential injection attempts
	if containsSQLInjectionPatterns(answer) {
		return errors.NewValidationError("security answer contains invalid characters")
	}

	return nil
}

// Helper validator functions for struct tags
func (av *AuthValidator) validatePassword(fl validator.FieldLevel) bool {
	return av.ValidatePassword(fl.Field().String()) == nil
}

func (av *AuthValidator) validateEmailUnique(fl validator.FieldLevel) bool {
	// This would need context and user ID in actual implementation
	return true
}

func (av *AuthValidator) validateUsername(fl validator.FieldLevel) bool {
	return av.ValidateUsername(fl.Field().String()) == nil
}

func (av *AuthValidator) validatePhone(fl validator.FieldLevel) bool {
	return av.ValidatePhoneNumber(fl.Field().String()) == nil
}

func (av *AuthValidator) validateSafeInput(fl validator.FieldLevel) bool {
	return !containsXSSPatterns(fl.Field().String())
}

func (av *AuthValidator) validateNoSQLInjection(fl validator.FieldLevel) bool {
	return !containsSQLInjectionPatterns(fl.Field().String())
}

// Security helper functions
func containsXSSPatterns(input string) bool {
	xssPatterns := []string{
		"<script", "javascript:", "onerror=", "onload=", "onclick=",
		"<iframe", "<embed", "<object", "document.", "window.",
	}
	
	inputLower := strings.ToLower(input)
	for _, pattern := range xssPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

func containsSQLInjectionPatterns(input string) bool {
	sqlPatterns := []string{
		"' or ", "' and ", "--", "/*", "*/", "xp_", "sp_",
		"exec ", "execute ", "select ", "insert ", "update ",
		"delete ", "drop ", "create ", "alter ", "union ",
	}
	
	inputLower := strings.ToLower(input)
	for _, pattern := range sqlPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

// ValidationError represents multiple validation errors
type ValidationError struct {
	Fields map[string][]string `json:"fields"`
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	var messages []string
	for field, errors := range ve.Fields {
		for _, err := range errors {
			messages = append(messages, fmt.Sprintf("%s: %s", field, err))
		}
	}
	return strings.Join(messages, "; ")
}

// ValidateStruct validates a struct using registered validators
func (av *AuthValidator) ValidateStruct(s interface{}) error {
	if err := av.validator.Struct(s); err != nil {
		validationErr := &ValidationError{
			Fields: make(map[string][]string),
		}

		for _, err := range err.(validator.ValidationErrors) {
			field := err.Field()
			tag := err.Tag()
			
			// Create human-readable error message
			message := av.getValidationMessage(field, tag, err.Param())
			validationErr.Fields[field] = append(validationErr.Fields[field], message)
		}

		return validationErr
	}
	return nil
}

// getValidationMessage returns a human-readable validation message
func (av *AuthValidator) getValidationMessage(field, tag, param string) string {
	messages := map[string]string{
		"required":  "is required",
		"email":     "must be a valid email address",
		"min":       fmt.Sprintf("must be at least %s characters", param),
		"max":       fmt.Sprintf("must not exceed %s characters", param),
		"password":  "does not meet password requirements",
		"username":  "contains invalid characters or is reserved",
		"phone":     "must be a valid phone number",
		"safe_input": "contains potentially unsafe content",
	}

	if msg, exists := messages[tag]; exists {
		return msg
	}
	return fmt.Sprintf("failed %s validation", tag)
}