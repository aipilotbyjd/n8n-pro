package auth

import (
	"regexp"
	"strings"
	"unicode"

	"n8n-pro/pkg/errors"
)

// PasswordRequirements defines password validation rules
type PasswordRequirements struct {
	MinLength    int
	RequireUpper bool
	RequireLower bool
	RequireDigit bool
	RequireSpecial bool
	ForbiddenPasswords []string
}

// DefaultPasswordRequirements returns the default password requirements
func DefaultPasswordRequirements() PasswordRequirements {
	return PasswordRequirements{
		MinLength:    8,
		RequireUpper: true,
		RequireLower: true,
		RequireDigit: true,
		RequireSpecial: false, // Set to false for better UX initially
		ForbiddenPasswords: []string{
			"password", "123456", "123456789", "12345678", "12345",
			"1234567", "password123", "admin", "qwerty", "abc123",
			"letmein", "welcome", "monkey", "dragon", "password1",
		},
	}
}

// ValidatePassword validates a password against requirements and returns detailed errors
func ValidatePassword(password string, requirements PasswordRequirements) error {
	var missingRequirements []string

	// Check minimum length
	if len(password) < requirements.MinLength {
		return errors.NewPasswordTooShortError(requirements.MinLength)
	}

	// Check for uppercase letter
	if requirements.RequireUpper && !hasUppercase(password) {
		missingRequirements = append(missingRequirements, "at least one uppercase letter (A-Z)")
	}

	// Check for lowercase letter
	if requirements.RequireLower && !hasLowercase(password) {
		missingRequirements = append(missingRequirements, "at least one lowercase letter (a-z)")
	}

	// Check for digit
	if requirements.RequireDigit && !hasDigit(password) {
		missingRequirements = append(missingRequirements, "at least one number (0-9)")
	}

	// Check for special character
	if requirements.RequireSpecial && !hasSpecialChar(password) {
		missingRequirements = append(missingRequirements, "at least one special character (!@#$%^&*)")
	}

	// Check for common/forbidden passwords
	if isForbiddenPassword(password, requirements.ForbiddenPasswords) {
		return errors.New(errors.ErrorTypeValidation, errors.CodePasswordCommon, "This password is too common and not secure").
			WithDetails("Please choose a more unique password")
	}

	// If there are missing requirements, return detailed error
	if len(missingRequirements) > 0 {
		return errors.NewPasswordTooWeakError(missingRequirements)
	}

	return nil
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return errors.NewValidationError("Email address is required")
	}

	// Basic format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.NewInvalidEmailError(email)
	}

	// Check for common issues
	email = strings.TrimSpace(strings.ToLower(email))
	
	// Check for consecutive dots
	if strings.Contains(email, "..") {
		return errors.NewInvalidEmailError(email).WithDetails("Email cannot contain consecutive dots")
	}

	// Check for leading/trailing dots in local part
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.NewInvalidEmailError(email)
	}

	localPart := parts[0]
	domainPart := parts[1]

	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return errors.NewInvalidEmailError(email).WithDetails("Email local part cannot start or end with a dot")
	}

	// Check domain part
	if strings.HasPrefix(domainPart, ".") || strings.HasSuffix(domainPart, ".") || 
	   strings.HasPrefix(domainPart, "-") || strings.HasSuffix(domainPart, "-") {
		return errors.NewInvalidEmailError(email).WithDetails("Invalid domain format")
	}

	return nil
}

// ValidateRegistrationData validates all registration data
func ValidateRegistrationData(name, email, password string) error {
	// Validate name
	if strings.TrimSpace(name) == "" {
		return errors.NewValidationError("Full name is required")
	}

	if len(strings.TrimSpace(name)) < 2 {
		return errors.NewValidationError("Full name must be at least 2 characters long")
	}

	if len(name) > 100 {
		return errors.NewValidationError("Full name cannot exceed 100 characters")
	}

	// Validate email
	if err := ValidateEmail(email); err != nil {
		return err
	}

	// Validate password
	requirements := DefaultPasswordRequirements()
	if err := ValidatePassword(password, requirements); err != nil {
		return err
	}

	return nil
}

// Helper functions

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecialChar(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range s {
		if strings.ContainsRune(specialChars, r) {
			return true
		}
	}
	return false
}

func isForbiddenPassword(password string, forbidden []string) bool {
	lower := strings.ToLower(password)
	for _, fp := range forbidden {
		if lower == strings.ToLower(fp) {
			return true
		}
	}
	return false
}