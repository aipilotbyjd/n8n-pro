package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-playground/validator/v10"
)

// ValidationMiddleware provides comprehensive input validation
type ValidationMiddleware struct {
	validator *validator.Validate
	logger    logger.Logger
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(logger logger.Logger) *ValidationMiddleware {
	validate := validator.New()
	
	// Register custom validators
	validate.RegisterValidation("password", validatePassword)
	validate.RegisterValidation("slug", validateSlug)
	validate.RegisterValidation("phone", validatePhone)
	validate.RegisterValidation("timezone", validateTimezone)
	validate.RegisterValidation("language", validateLanguage)
	validate.RegisterValidation("safe_html", validateSafeHTML)
	validate.RegisterValidation("no_script", validateNoScript)

	return &ValidationMiddleware{
		validator: validate,
		logger:    logger,
	}
}

// ValidateJSON validates JSON request bodies
func (v *ValidationMiddleware) ValidateJSON() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
				contentType := r.Header.Get("Content-Type")
				if strings.HasPrefix(contentType, "application/json") {
					// Validate JSON structure without parsing into struct
					if err := validateJSONSyntax(r); err != nil {
						v.logger.Warn("Invalid JSON in request", "path", r.URL.Path, "error", err.Error())
						writeValidationError(w, errors.NewValidationError("Invalid JSON format: "+err.Error()))
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SanitizeInput sanitizes input data to prevent XSS and injection attacks
func (v *ValidationMiddleware) SanitizeInput() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sanitize URL parameters
			query := r.URL.Query()
			for key, values := range query {
				for i, value := range values {
					query[key][i] = sanitizeString(value)
				}
			}
			r.URL.RawQuery = query.Encode()

			// Sanitize form data
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
				contentType := r.Header.Get("Content-Type")
				if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
					if err := r.ParseForm(); err == nil {
						for key, values := range r.PostForm {
							for i, value := range values {
								r.PostForm[key][i] = sanitizeString(value)
							}
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateStruct validates a struct using the validator
func (v *ValidationMiddleware) ValidateStruct(data interface{}) error {
	if err := v.validator.Struct(data); err != nil {
		var validationErrors []ValidationError
		
		if errs, ok := err.(validator.ValidationErrors); ok {
			for _, e := range errs {
				validationErrors = append(validationErrors, ValidationError{
					Field:   getJSONFieldName(data, e.Field()),
					Tag:     e.Tag(),
					Value:   fmt.Sprintf("%v", e.Value()),
					Message: getValidationMessage(e),
				})
			}
		}
		
		return &ValidationErrorResponse{
			Message: "Validation failed",
			Errors:  validationErrors,
		}
	}
	return nil
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

// ValidationErrorResponse represents validation error response
type ValidationErrorResponse struct {
	Message string            `json:"message"`
	Errors  []ValidationError `json:"errors"`
}

func (v ValidationErrorResponse) Error() string {
	return v.Message
}

// ValidateQueryParams validates query parameters
func (v *ValidationMiddleware) ValidateQueryParams(params map[string]interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			var validationErrors []ValidationError

			for paramName, rules := range params {
				value := query.Get(paramName)
				if value != "" {
					if err := v.validateQueryParam(paramName, value, rules); err != nil {
						validationErrors = append(validationErrors, ValidationError{
							Field:   paramName,
							Value:   value,
							Message: err.Error(),
						})
					}
				}
			}

			if len(validationErrors) > 0 {
				response := &ValidationErrorResponse{
					Message: "Query parameter validation failed",
					Errors:  validationErrors,
				}
				writeValidationError(w, response)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// EnforceContentLength validates content length limits
func (v *ValidationMiddleware) EnforceContentLength(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				v.logger.Warn("Content length exceeded", 
					"content_length", r.ContentLength, 
					"max_size", maxSize, 
					"path", r.URL.Path)
				writeValidationError(w, errors.NewValidationError("Request body too large"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateHeaders validates required headers
func (v *ValidationMiddleware) ValidateHeaders(requiredHeaders []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, header := range requiredHeaders {
				if r.Header.Get(header) == "" {
					v.logger.Warn("Missing required header", "header", header, "path", r.URL.Path)
					writeValidationError(w, errors.NewValidationError("Missing required header: "+header))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Custom validators

// validatePassword validates password strength
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}
	
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	// Require at least 3 of the 4 character types
	count := 0
	if hasUpper { count++ }
	if hasLower { count++ }
	if hasDigit { count++ }
	if hasSpecial { count++ }
	
	return count >= 3
}

// validateSlug validates URL-friendly slugs
func validateSlug(fl validator.FieldLevel) bool {
	slug := fl.Field().String()
	matched, _ := regexp.MatchString(`^[a-z0-9]+(?:-[a-z0-9]+)*$`, slug)
	return matched
}

// validatePhone validates phone numbers (basic validation)
func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	// Remove all non-digit characters
	digits := regexp.MustCompile(`\D`).ReplaceAllString(phone, "")
	// Check if it has 10-15 digits
	return len(digits) >= 10 && len(digits) <= 15
}

// validateTimezone validates timezone strings
func validateTimezone(fl validator.FieldLevel) bool {
	timezone := fl.Field().String()
	validTimezones := []string{
		"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
		"Europe/London", "Europe/Berlin", "Europe/Paris", "Asia/Tokyo", "Asia/Shanghai",
		"Australia/Sydney", "Pacific/Auckland",
	}
	
	for _, valid := range validTimezones {
		if timezone == valid {
			return true
		}
	}
	return false
}

// validateLanguage validates language codes
func validateLanguage(fl validator.FieldLevel) bool {
	lang := fl.Field().String()
	validLanguages := []string{
		"en", "es", "fr", "de", "it", "pt", "ru", "ja", "ko", "zh", "ar", "hi",
	}
	
	for _, valid := range validLanguages {
		if lang == valid {
			return true
		}
	}
	return false
}

// validateSafeHTML validates that HTML is safe (no script tags, etc.)
func validateSafeHTML(fl validator.FieldLevel) bool {
	html := strings.ToLower(fl.Field().String())
	dangerousTags := []string{
		"<script", "</script>", "<iframe", "</iframe>", "<object", "</object>",
		"<embed", "</embed>", "<form", "</form>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
	}
	
	for _, tag := range dangerousTags {
		if strings.Contains(html, tag) {
			return false
		}
	}
	return true
}

// validateNoScript ensures no script content is present
func validateNoScript(fl validator.FieldLevel) bool {
	content := strings.ToLower(fl.Field().String())
	scriptPatterns := []string{
		"<script", "javascript:", "vbscript:", "onload", "onerror", "onclick",
		"onmouseover", "onmouseout", "onfocus", "onblur", "onchange", "onsubmit",
	}
	
	for _, pattern := range scriptPatterns {
		if strings.Contains(content, pattern) {
			return false
		}
	}
	return true
}

// Helper functions

// validateJSONSyntax validates JSON syntax without full parsing
func validateJSONSyntax(r *http.Request) error {
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage
	return decoder.Decode(&raw)
}

// sanitizeString removes potentially dangerous characters
func sanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove control characters except tab, newline, and carriage return
	var result strings.Builder
	for _, char := range input {
		if char >= 32 || char == '\t' || char == '\n' || char == '\r' {
			result.WriteRune(char)
		}
	}
	
	return strings.TrimSpace(result.String())
}

// getJSONFieldName gets the JSON field name from struct field name
func getJSONFieldName(data interface{}, fieldName string) string {
	dataType := reflect.TypeOf(data)
	if dataType.Kind() == reflect.Ptr {
		dataType = dataType.Elem()
	}
	
	field, found := dataType.FieldByName(fieldName)
	if !found {
		return fieldName
	}
	
	jsonTag := field.Tag.Get("json")
	if jsonTag == "" {
		return fieldName
	}
	
	// Handle comma-separated json tags
	parts := strings.Split(jsonTag, ",")
	if parts[0] == "-" {
		return fieldName
	}
	if parts[0] != "" {
		return parts[0]
	}
	
	return fieldName
}

// getValidationMessage returns a user-friendly validation message
func getValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return fmt.Sprintf("Minimum length is %s characters", err.Param())
	case "max":
		return fmt.Sprintf("Maximum length is %s characters", err.Param())
	case "len":
		return fmt.Sprintf("Length must be exactly %s characters", err.Param())
	case "password":
		return "Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters"
	case "slug":
		return "Invalid slug format. Use lowercase letters, numbers, and hyphens only"
	case "phone":
		return "Invalid phone number format"
	case "timezone":
		return "Invalid timezone"
	case "language":
		return "Invalid language code"
	case "safe_html":
		return "HTML content contains unsafe elements"
	case "no_script":
		return "Script content is not allowed"
	case "oneof":
		return fmt.Sprintf("Value must be one of: %s", err.Param())
	case "url":
		return "Invalid URL format"
	case "uri":
		return "Invalid URI format"
	case "alpha":
		return "Only alphabetic characters are allowed"
	case "alphanum":
		return "Only alphanumeric characters are allowed"
	case "numeric":
		return "Only numeric characters are allowed"
	case "hexadecimal":
		return "Invalid hexadecimal format"
	case "hexcolor":
		return "Invalid hex color format"
	case "rgb":
		return "Invalid RGB color format"
	case "rgba":
		return "Invalid RGBA color format"
	case "uuid":
		return "Invalid UUID format"
	case "uuid3":
		return "Invalid UUID v3 format"
	case "uuid4":
		return "Invalid UUID v4 format"
	case "uuid5":
		return "Invalid UUID v5 format"
	case "ascii":
		return "Only ASCII characters are allowed"
	case "printascii":
		return "Only printable ASCII characters are allowed"
	case "multibyte":
		return "Multibyte characters are required"
	case "datauri":
		return "Invalid data URI format"
	case "latitude":
		return "Invalid latitude"
	case "longitude":
		return "Invalid longitude"
	default:
		return fmt.Sprintf("Validation failed for '%s'", err.Tag())
	}
}

// validateQueryParam validates individual query parameters
func (v *ValidationMiddleware) validateQueryParam(name, value string, rules interface{}) error {
	rulesMap, ok := rules.(map[string]interface{})
	if !ok {
		return nil
	}

	// Check type
	if expectedType, exists := rulesMap["type"]; exists {
		if err := validateParamType(value, expectedType.(string)); err != nil {
			return err
		}
	}

	// Check min/max for numbers
	if min, exists := rulesMap["min"]; exists {
		if num, err := strconv.Atoi(value); err == nil {
			if num < min.(int) {
				return fmt.Errorf("minimum value is %d", min.(int))
			}
		}
	}

	if max, exists := rulesMap["max"]; exists {
		if num, err := strconv.Atoi(value); err == nil {
			if num > max.(int) {
				return fmt.Errorf("maximum value is %d", max.(int))
			}
		}
	}

	// Check allowed values
	if allowed, exists := rulesMap["oneof"]; exists {
		allowedValues := allowed.([]string)
		found := false
		for _, allowedValue := range allowedValues {
			if value == allowedValue {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("must be one of: %s", strings.Join(allowedValues, ", "))
		}
	}

	return nil
}

// validateParamType validates parameter type
func validateParamType(value, expectedType string) error {
	switch expectedType {
	case "int":
		if _, err := strconv.Atoi(value); err != nil {
			return fmt.Errorf("must be an integer")
		}
	case "float":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return fmt.Errorf("must be a number")
		}
	case "bool":
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("must be true or false")
		}
	case "email":
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(value) {
			return fmt.Errorf("invalid email format")
		}
	case "uuid":
		uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		if !uuidRegex.MatchString(strings.ToLower(value)) {
			return fmt.Errorf("invalid UUID format")
		}
	}
	return nil
}

// writeValidationError writes a validation error response
func writeValidationError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	
	if validationErr, ok := err.(*ValidationErrorResponse); ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validationErr)
	} else if apiError, ok := err.(*errors.APIError); ok {
		w.WriteHeader(apiError.HTTPStatus())
		w.Write([]byte(`{"error": "` + apiError.Message + `", "code": "` + string(apiError.Code) + `"}`))
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "` + err.Error() + `", "code": "VALIDATION_ERROR"}`))
	}
}

// Common validation configurations

// PaginationQueryParams defines validation rules for pagination parameters
var PaginationQueryParams = map[string]interface{}{
	"page": map[string]interface{}{
		"type": "int",
		"min":  1,
		"max":  10000,
	},
	"limit": map[string]interface{}{
		"type":   "int",
		"min":    1,
		"max":    100,
		"oneof":  []string{"10", "20", "50", "100"},
	},
}

// SearchQueryParams defines validation rules for search parameters
var SearchQueryParams = map[string]interface{}{
	"search": map[string]interface{}{
		"type": "string",
	},
	"sort": map[string]interface{}{
		"oneof": []string{"name", "created_at", "updated_at", "email"},
	},
	"order": map[string]interface{}{
		"oneof": []string{"asc", "desc"},
	},
}