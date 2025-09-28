package auth

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"n8n-pro/pkg/errors"

	"github.com/go-playground/validator/v10"
)

// AdvancedValidator provides advanced validation capabilities
type AdvancedValidator struct {
	validator              *validator.Validate
	passwordValidator      *PasswordValidator
	emailValidator         *EmailValidator
	inputSanitizer         *InputSanitizer
	profanityChecker       *ProfanityChecker
	disposableEmailChecker *DisposableEmailChecker
}

// NewAdvancedValidator creates a new advanced validator
func NewAdvancedValidator() *AdvancedValidator {
	v := validator.New()
	
	// Register custom validators
	v.RegisterValidation("password", validatePassword)
	v.RegisterValidation("email_advanced", validateEmailAdvanced)
	v.RegisterValidation("username", validateUsername)
	v.RegisterValidation("phone", validatePhoneNumber)
	v.RegisterValidation("no_sql_injection", validateNoSQLInjection)
	v.RegisterValidation("no_xss", validateNoXSS)
	v.RegisterValidation("safe_text", validateSafeText)
	v.RegisterValidation("url_safe", validateURLSafe)
	
	return &AdvancedValidator{
		validator:              v,
		passwordValidator:      NewPasswordValidator(),
		emailValidator:         NewEmailValidator(),
		inputSanitizer:         NewInputSanitizer(),
		profanityChecker:       NewProfanityChecker(),
		disposableEmailChecker: NewDisposableEmailChecker(),
	}
}

// ValidateStruct validates a struct
func (av *AdvancedValidator) ValidateStruct(s interface{}) error {
	if err := av.validator.Struct(s); err != nil {
		return av.formatValidationErrors(err)
	}
	return nil
}

// ValidateRegistration performs comprehensive registration validation
func (av *AdvancedValidator) ValidateRegistration(req *RegisterRequest) error {
	// Basic struct validation
	if err := av.ValidateStruct(req); err != nil {
		return err
	}

	// Sanitize inputs
	req.FirstName = av.inputSanitizer.SanitizeName(req.FirstName)
	req.LastName = av.inputSanitizer.SanitizeName(req.LastName)
	req.Email = av.inputSanitizer.SanitizeEmail(req.Email)

	// Advanced email validation
	if err := av.emailValidator.ValidateComprehensive(req.Email); err != nil {
		return err
	}

	// Check for disposable email
	if av.disposableEmailChecker.IsDisposable(req.Email) {
		return errors.NewValidationError("Disposable email addresses are not allowed")
	}

	// Advanced password validation
	if err := av.passwordValidator.ValidateComprehensive(req.Password, req.Email, req.FirstName, req.LastName); err != nil {
		return err
	}

	// Check for profanity in names
	if av.profanityChecker.ContainsProfanity(req.FirstName) || av.profanityChecker.ContainsProfanity(req.LastName) {
		return errors.NewValidationError("Name contains inappropriate content")
	}

	// Validate organization name if provided
	// TODO: Add OrganizationName field to RegisterRequest when needed
	// if req.OrganizationName != "" {
	// 	req.OrganizationName = av.inputSanitizer.SanitizeName(req.OrganizationName)
	// 	if av.profanityChecker.ContainsProfanity(req.OrganizationName) {
	// 		return errors.NewValidationError("Organization name contains inappropriate content")
	// 	}
	// }

	return nil
}

// formatValidationErrors formats validation errors to be user-friendly
func (av *AdvancedValidator) formatValidationErrors(err error) error {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var messages []string
		for _, e := range validationErrors {
			messages = append(messages, av.formatFieldError(e))
		}
		return errors.NewValidationError(strings.Join(messages, "; "))
	}
	return errors.NewValidationError("Validation failed")
}

func (av *AdvancedValidator) formatFieldError(e validator.FieldError) string {
	field := e.Field()
	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", field, e.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters", field, e.Param())
	case "eqfield":
		return fmt.Sprintf("%s must match %s", field, e.Param())
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// PasswordValidator provides comprehensive password validation
type PasswordValidator struct {
	minLength          int
	requireUppercase   bool
	requireLowercase   bool
	requireNumber      bool
	requireSpecial     bool
	maxConsecutive     int
	bannedPasswords    map[string]bool
	commonPatterns     []*regexp.Regexp
	breachChecker      *BreachChecker
}

// NewPasswordValidator creates a new password validator
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		minLength:        12, // Higher than default for production
		requireUppercase: true,
		requireLowercase: true,
		requireNumber:    true,
		requireSpecial:   true,
		maxConsecutive:   3,
		bannedPasswords: map[string]bool{
			"password":    true,
			"123456":      true,
			"password123": true,
			"admin":       true,
			"letmein":     true,
			"qwerty":      true,
			"monkey":      true,
			"dragon":      true,
			"master":      true,
			"sunshine":    true,
		},
		commonPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^[0-9]+$`),           // All numbers
			regexp.MustCompile(`^[a-z]+[0-9]+$`),     // Letters followed by numbers
			regexp.MustCompile(`^[0-9]+[a-z]+$`),     // Numbers followed by letters
			regexp.MustCompile(`(.)\1{3,}`),          // Same character repeated 4+ times
			regexp.MustCompile(`(012|123|234|345|456|567|678|789|890)`), // Sequential numbers
			regexp.MustCompile(`(abc|bcd|cde|def|efg|fgh)`),             // Sequential letters
		},
		breachChecker: NewBreachChecker(),
	}
}

// ValidateComprehensive performs comprehensive password validation
func (pv *PasswordValidator) ValidateComprehensive(password, email, firstName, lastName string) error {
	// Length check
	if len(password) < pv.minLength {
		return errors.NewPasswordTooShortError(pv.minLength)
	}

	// Character requirements
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	var consecutive int
	var lastChar rune

	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		}
		if unicode.IsLower(char) {
			hasLower = true
		}
		if unicode.IsDigit(char) {
			hasNumber = true
		}
		if isSpecialChar(char) {
			hasSpecial = true
		}

		// Check consecutive characters
		if char == lastChar {
			consecutive++
			if consecutive >= pv.maxConsecutive {
				return errors.NewValidationError(fmt.Sprintf("Password cannot contain more than %d consecutive identical characters", pv.maxConsecutive))
			}
		} else {
			consecutive = 0
			lastChar = char
		}
	}

	var missing []string
	if pv.requireUppercase && !hasUpper {
		missing = append(missing, "at least one uppercase letter")
	}
	if pv.requireLowercase && !hasLower {
		missing = append(missing, "at least one lowercase letter")
	}
	if pv.requireNumber && !hasNumber {
		missing = append(missing, "at least one number")
	}
	if pv.requireSpecial && !hasSpecial {
		missing = append(missing, "at least one special character (!@#$%^&*)")
	}

	if len(missing) > 0 {
		return errors.NewPasswordTooWeakError(missing)
	}

	// Check against banned passwords
	if pv.bannedPasswords[strings.ToLower(password)] {
		return errors.New(errors.ErrorTypeValidation, errors.CodePasswordCommon, "This password is too common")
	}

	// Check common patterns
	for _, pattern := range pv.commonPatterns {
		if pattern.MatchString(password) {
			return errors.New(errors.ErrorTypeValidation, errors.CodePasswordTooWeak, "Password follows a predictable pattern")
		}
	}

	// Check if password contains personal information
	lowerPassword := strings.ToLower(password)
	if email != "" && strings.Contains(lowerPassword, strings.Split(email, "@")[0]) {
		return errors.NewValidationError("Password cannot contain your email address")
	}
	if firstName != "" && len(firstName) > 2 && strings.Contains(lowerPassword, strings.ToLower(firstName)) {
		return errors.NewValidationError("Password cannot contain your first name")
	}
	if lastName != "" && len(lastName) > 2 && strings.Contains(lowerPassword, strings.ToLower(lastName)) {
		return errors.NewValidationError("Password cannot contain your last name")
	}

	// Check against known breaches (simulated)
	if pv.breachChecker.IsBreached(password) {
		return errors.NewValidationError("This password has been found in data breaches. Please choose a different password")
	}

	// Calculate entropy
	entropy := pv.calculateEntropy(password)
	if entropy < 50 { // Minimum 50 bits of entropy
		return errors.New(errors.ErrorTypeValidation, errors.CodePasswordTooWeak, "Password is not complex enough")
	}

	return nil
}

func (pv *PasswordValidator) calculateEntropy(password string) float64 {
	// Simplified entropy calculation
	charSetSize := 0
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
	
	for _, char := range password {
		if unicode.IsLower(char) && !hasLower {
			charSetSize += 26
			hasLower = true
		}
		if unicode.IsUpper(char) && !hasUpper {
			charSetSize += 26
			hasUpper = true
		}
		if unicode.IsDigit(char) && !hasDigit {
			charSetSize += 10
			hasDigit = true
		}
		if isSpecialChar(char) && !hasSpecial {
			charSetSize += 32
			hasSpecial = true
		}
	}
	
	if charSetSize == 0 {
		return 0
	}
	
	// Entropy = log2(charSetSize) * length
	return float64(len(password)) * (float64(charSetSize) / 10) // Simplified calculation
}

// EmailValidator provides comprehensive email validation
type EmailValidator struct {
	domainWhitelist []string
	domainBlacklist []string
	mxChecker       *MXChecker
}

// NewEmailValidator creates a new email validator
func NewEmailValidator() *EmailValidator {
	return &EmailValidator{
		domainWhitelist: []string{}, // Add trusted domains if needed
		domainBlacklist: []string{
			"mailinator.com",
			"guerrillamail.com",
			"10minutemail.com",
			"tempmail.com",
		},
		mxChecker: NewMXChecker(),
	}
}

// ValidateComprehensive performs comprehensive email validation
func (ev *EmailValidator) ValidateComprehensive(email string) error {
	// Parse email
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return errors.NewInvalidEmailError(email)
	}

	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return errors.NewInvalidEmailError(email)
	}

	local, domain := parts[0], parts[1]

	// Validate local part
	if len(local) < 1 || len(local) > 64 {
		return errors.NewValidationError("Email local part must be between 1 and 64 characters")
	}

	// Check for invalid characters in local part
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return errors.NewValidationError("Email local part has invalid format")
	}

	// Validate domain
	if len(domain) < 3 || len(domain) > 255 {
		return errors.NewValidationError("Email domain must be between 3 and 255 characters")
	}

	// Check domain against blacklist
	for _, blocked := range ev.domainBlacklist {
		if strings.EqualFold(domain, blocked) {
			return errors.NewValidationError("Email domain is not allowed")
		}
	}

	// Check if domain has valid MX records (optional, can be slow)
	// Commented out for performance, enable if needed
	// if !ev.mxChecker.HasMXRecord(domain) {
	//     return errors.NewValidationError("Email domain does not accept email")
	// }

	return nil
}

// InputSanitizer provides input sanitization
type InputSanitizer struct {
	htmlPolicy *regexp.Regexp
	sqlPolicy  *regexp.Regexp
}

// NewInputSanitizer creates a new input sanitizer
func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{
		htmlPolicy: regexp.MustCompile(`<[^>]*>`),
		sqlPolicy:  regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)`),
	}
}

// SanitizeName sanitizes a name input
func (is *InputSanitizer) SanitizeName(name string) string {
	// Remove HTML tags
	name = is.htmlPolicy.ReplaceAllString(name, "")
	// Trim whitespace
	name = strings.TrimSpace(name)
	// Remove control characters
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	return name
}

// SanitizeEmail sanitizes an email input
func (is *InputSanitizer) SanitizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ProfanityChecker checks for inappropriate content
type ProfanityChecker struct {
	bannedWords map[string]bool
	patterns    []*regexp.Regexp
}

// NewProfanityChecker creates a new profanity checker
func NewProfanityChecker() *ProfanityChecker {
	return &ProfanityChecker{
		bannedWords: map[string]bool{
			// Add inappropriate words to filter
			// This is a minimal list for demonstration
			"admin":  true,
			"root":   true,
			"system": true,
		},
		patterns: []*regexp.Regexp{
			// Add regex patterns for variations
		},
	}
}

// ContainsProfanity checks if text contains profanity
func (pc *ProfanityChecker) ContainsProfanity(text string) bool {
	lower := strings.ToLower(text)
	
	// Check exact matches
	words := strings.Fields(lower)
	for _, word := range words {
		if pc.bannedWords[word] {
			return true
		}
	}
	
	// Check patterns
	for _, pattern := range pc.patterns {
		if pattern.MatchString(lower) {
			return true
		}
	}
	
	return false
}

// DisposableEmailChecker checks for disposable email addresses
type DisposableEmailChecker struct {
	domains map[string]bool
}

// NewDisposableEmailChecker creates a new disposable email checker
func NewDisposableEmailChecker() *DisposableEmailChecker {
	return &DisposableEmailChecker{
		domains: map[string]bool{
			"mailinator.com":     true,
			"guerrillamail.com":  true,
			"10minutemail.com":   true,
			"tempmail.com":       true,
			"throwaway.email":    true,
			"temporarymail.net":  true,
			"disposablemail.com": true,
			"yopmail.com":        true,
			"trashmail.com":      true,
			"fakeinbox.com":      true,
		},
	}
}

// IsDisposable checks if an email is from a disposable provider
func (dec *DisposableEmailChecker) IsDisposable(email string) bool {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return false
	}
	return dec.domains[parts[1]]
}

// BreachChecker checks passwords against known breaches
type BreachChecker struct {
	// In production, this would connect to an API like HaveIBeenPwned
	knownBreached map[string]bool
}

// NewBreachChecker creates a new breach checker
func NewBreachChecker() *BreachChecker {
	return &BreachChecker{
		knownBreached: map[string]bool{
			// Sample breached passwords (in production, use API)
			"password123": true,
			"qwerty123":   true,
			"123456789":   true,
		},
	}
}

// IsBreached checks if a password has been breached
func (bc *BreachChecker) IsBreached(password string) bool {
	// In production, hash the password and check against HaveIBeenPwned API
	return bc.knownBreached[password]
}

// MXChecker checks for MX records
type MXChecker struct {
	// Cache MX check results
	cache map[string]bool
}

// NewMXChecker creates a new MX checker
func NewMXChecker() *MXChecker {
	return &MXChecker{
		cache: make(map[string]bool),
	}
}

// HasMXRecord checks if a domain has MX records
func (mx *MXChecker) HasMXRecord(domain string) bool {
	// In production, perform actual MX lookup
	// For now, return true to avoid blocking
	return true
}

// Helper functions

func isSpecialChar(r rune) bool {
	return strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", r)
}

// Custom validation functions for validator tags

func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	return len(password) >= 8 // Basic check, comprehensive validation done separately
}

func validateEmailAdvanced(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
	return match
}

func validatePhoneNumber(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	match, _ := regexp.MatchString(`^[+]?[0-9]{10,15}$`, phone)
	return match
}

func validateNoSQLInjection(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	sqlPattern := regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|script|javascript|onclick|onload)`)
	return !sqlPattern.MatchString(value)
}

func validateNoXSS(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	xssPattern := regexp.MustCompile(`<[^>]*>|javascript:|on\w+=`)
	return !xssPattern.MatchString(value)
}

func validateSafeText(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	// Allow only safe characters
	match, _ := regexp.MatchString(`^[a-zA-Z0-9\s.,!?@#$%^&*()\-_+=\[\]{}|;:'"\` + "`" + `]+$`, value)
	return match
}

func validateURLSafe(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	// Basic URL validation
	match, _ := regexp.MatchString(`^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`, value)
	return match
}