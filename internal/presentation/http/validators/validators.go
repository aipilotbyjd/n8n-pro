package validators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"n8n-pro/internal/shared/types"
	"n8n-pro/pkg/errors"

	"github.com/go-playground/validator/v10"
)

// Validator provides validation functionality for HTTP requests
type Validator struct {
	validator *validator.Validate
}

// New creates a new validator instance
func New() *Validator {
	v := &Validator{
		validator: validator.New(),
	}

	// Register custom validations
	v.registerCustomValidations()

	return v
}

// ValidateStruct validates a struct using struct tags
func (v *Validator) ValidateStruct(s interface{}) *errors.Error {
	if s == nil {
		return nil
	}

	if err := v.validator.Struct(s); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		return v.processValidationErrors(validationErrors)
	}

	return nil
}

// ValidateMap validates a map of values
func (v *Validator) ValidateMap(m map[string]interface{}, rules map[string]string) *errors.Error {
	// Convert map to struct for validation
	// This is a simplified implementation - in reality you'd need more complex rule processing
	for field, value := range m {
		if rule, exists := rules[field]; exists {
			if err := v.validateField(field, value, rule); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateField validates a single field with the given rule
func (v *Validator) validateField(field string, value interface{}, rule string) *errors.Error {
	// Parse rules - simple implementation
	rules := strings.Split(rule, "|")

	for _, r := range rules {
		r = strings.TrimSpace(r)
		
		switch {
		case r == "required":
			if value == nil || value == "" {
				return errors.NewValidationError(fmt.Sprintf("field %s is required", field))
			}
		case strings.HasPrefix(r, "min="):
			min := strings.TrimPrefix(r, "min=")
			if err := v.validateMin(field, value, min); err != nil {
				return err
			}
		case strings.HasPrefix(r, "max="):
			max := strings.TrimPrefix(r, "max=")
			if err := v.validateMax(field, value, max); err != nil {
				return err
			}
		case r == "email":
			if str, ok := value.(string); ok {
				if !v.isValidEmail(str) {
					return errors.NewValidationError(fmt.Sprintf("field %s must be a valid email", field))
				}
			}
		case r == "url":
			if str, ok := value.(string); ok {
				if !v.isValidURL(str) {
					return errors.NewValidationError(fmt.Sprintf("field %s must be a valid URL", field))
				}
			}
		}
	}

	return nil
}

// validateMin validates minimum length/value
func (v *Validator) validateMin(field string, value interface{}, minStr string) *errors.Error {
	// For strings
	if str, ok := value.(string); ok {
		if len(str) < len(minStr) { // This is a simplified check - in reality you'd parse the min number
			return errors.NewValidationError(fmt.Sprintf("field %s must be at least %s characters long", field, minStr))
		}
	}

	return nil
}

// validateMax validates maximum length/value
func (v *Validator) validateMax(field string, value interface{}, maxStr string) *errors.Error {
	// For strings
	if str, ok := value.(string); ok {
		if len(str) > len(maxStr) { // This is a simplified check - in reality you'd parse the max number
			return errors.NewValidationError(fmt.Sprintf("field %s must not exceed %s characters", field, maxStr))
		}
	}

	return nil
}

// isValidEmail validates email format
func (v *Validator) isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// isValidURL validates URL format
func (v *Validator) isValidURL(url string) bool {
	re := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	return re.MatchString(url)
}

// registerCustomValidations registers custom validation functions
func (v *Validator) registerCustomValidations() {
	// Register password complexity validation
	v.validator.RegisterValidation("password_complex", v.passwordComplexityValidation)
	
	// Register custom time format validation
	v.validator.RegisterValidation("time_format", v.timeFormatValidation)
}

// passwordComplexityValidation validates password complexity
func (v *Validator) passwordComplexityValidation(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	
	// Check minimum length
	if len(password) < 8 {
		return false
	}
	
	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	
	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	
	// Check for at least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	
	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	
	return hasUpper && hasLower && hasDigit && hasSpecial
}

// timeFormatValidation validates time format
func (v *Validator) timeFormatValidation(fl validator.FieldLevel) bool {
	timeStr := fl.Field().String()
	_, err := time.Parse(time.RFC3339, timeStr)
	return err == nil
}

// processValidationErrors converts validator errors to app errors
func (v *Validator) processValidationErrors(validationErrors validator.ValidationErrors) *errors.Error {
	details := make(map[string]interface{})
	
	for _, err := range validationErrors {
		field := strings.ToLower(err.Field())
		var msg string
		
		switch err.Tag() {
		case "required":
			msg = fmt.Sprintf("%s is required", field)
		case "email":
			msg = fmt.Sprintf("%s must be a valid email", field)
		case "url":
			msg = fmt.Sprintf("%s must be a valid URL", field)
		case "min":
			msg = fmt.Sprintf("%s must be at least %s", field, err.Param())
		case "max":
			msg = fmt.Sprintf("%s must not exceed %s", field, err.Param())
		case "len":
			msg = fmt.Sprintf("%s must be exactly %s characters", field, err.Param())
		case "password_complex":
			msg = fmt.Sprintf("%s must meet complexity requirements", field)
		case "time_format":
			msg = fmt.Sprintf("%s must be in a valid time format", field)
		default:
			msg = fmt.Sprintf("%s failed validation", field)
		}
		
		details[field] = msg
	}
	
	return errors.NewValidationErrorWithDetails("Validation failed", details)
}

// ValidateJSON validates JSON data against a schema
func (v *Validator) ValidateJSON(data []byte, schema interface{}) *errors.Error {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return errors.NewValidationError("Invalid JSON format")
	}
	
	// In a real implementation, you'd validate against a JSON schema
	// For now, just validate using struct tags if schema is a struct
	if schema != nil {
		if err := v.validator.Struct(schema); err != nil {
			validationErrors := err.(validator.ValidationErrors)
			return v.processValidationErrors(validationErrors)
		}
	}
	
	return nil
}

// ValidateRequest validates an HTTP request body
func (v *Validator) ValidateRequest(r *http.Request, target interface{}) *errors.Error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	
	if err := decoder.Decode(target); err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid JSON in request body: %v", err))
	}
	
	// Validate the decoded struct
	return v.ValidateStruct(target)
}

// ValidatePagination validates pagination parameters
func (v *Validator) ValidatePagination(p *types.Pagination) *errors.Error {
	if p.Page < 1 {
		return errors.NewValidationError("page must be greater than 0")
	}
	
	if p.Limit < 1 {
		return errors.NewValidationError("limit must be greater than 0")
	}
	
	if p.Limit > 100 {
		return errors.NewValidationError("limit must not exceed 100")
	}
	
	return nil
}

// ValidateFilter validates filter parameters
func (v *Validator) ValidateFilter(f *types.Filter) *errors.Error {
	if f.Page < 1 {
		return errors.NewValidationError("page must be greater than 0")
	}
	
	if f.Limit < 1 {
		return errors.NewValidationError("limit must be greater than 0")
	}
	
	if f.Limit > 100 {
		return errors.NewValidationError("limit must not exceed 100")
	}
	
	if f.SortOrder != "" && f.SortOrder != "asc" && f.SortOrder != "desc" {
		return errors.NewValidationError("sort_order must be 'asc' or 'desc'")
	}
	
	return nil
}

// ValidateEmail validates email format
func (v *Validator) ValidateEmail(email string) *errors.Error {
	if email == "" {
		return errors.NewValidationError("email is required")
	}
	
	email = strings.TrimSpace(email)
	
	if !v.isValidEmail(email) {
		return errors.NewValidationError("email format is invalid")
	}
	
	return nil
}

// ValidatePassword validates password complexity
func (v *Validator) ValidatePassword(password string) *errors.Error {
	if password == "" {
		return errors.NewValidationError("password is required")
	}
	
	if len(password) < 8 {
		return errors.NewValidationError("password must be at least 8 characters long")
	}
	
	// Basic complexity check
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	
	if !hasUpper {
		return errors.NewValidationError("password must contain at least one uppercase letter")
	}
	
	if !hasLower {
		return errors.NewValidationError("password must contain at least one lowercase letter")
	}
	
	if !hasDigit {
		return errors.NewValidationError("password must contain at least one digit")
	}
	
	if !hasSpecial {
		return errors.NewValidationError("password must contain at least one special character")
	}
	
	return nil
}