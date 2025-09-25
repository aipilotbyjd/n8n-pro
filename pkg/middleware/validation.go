package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"

	"github.com/gorilla/mux"
)

// ValidationConfig contains configuration for validation middleware
type ValidationConfig struct {
	MaxRequestSize      int64         `json:"max_request_size"`      // Maximum request body size in bytes
	RequestTimeout      time.Duration `json:"request_timeout"`       // Request processing timeout
	EnableSQLInjection  bool          `json:"enable_sql_injection"`  // Enable SQL injection detection
	EnableXSSProtection bool          `json:"enable_xss_protection"` // Enable XSS protection
	EnablePathTraversal bool          `json:"enable_path_traversal"` // Enable path traversal protection
	MaxFieldLength      int           `json:"max_field_length"`      // Maximum field length
	AllowedFileTypes    []string      `json:"allowed_file_types"`    // Allowed file extensions
	BlockedPatterns     []string      `json:"blocked_patterns"`      // Blocked regex patterns
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		MaxRequestSize:      10 * 1024 * 1024, // 10MB
		RequestTimeout:      30 * time.Second,
		EnableSQLInjection:  true,
		EnableXSSProtection: true,
		EnablePathTraversal: true,
		MaxFieldLength:      10000,
		AllowedFileTypes:    []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt"},
		BlockedPatterns: []string{
			`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`,
			`(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=)`,
			`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)`,
		},
	}
}

// ValidationMiddleware provides comprehensive request validation
type ValidationMiddleware struct {
	config    *ValidationConfig
	validator *validator.Validator
	logger    logger.Logger

	// Compiled regex patterns for performance
	sqlInjectionPatterns []*regexp.Regexp
	xssPatterns         []*regexp.Regexp
	pathTraversalPatterns []*regexp.Regexp
	blockedPatterns     []*regexp.Regexp

	// Common validation patterns
	emailPattern    *regexp.Regexp
	urlPattern      *regexp.Regexp
	phonePattern    *regexp.Regexp
	ipPattern       *regexp.Regexp
	uuidPattern     *regexp.Regexp
	alphanumPattern *regexp.Regexp
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(config *ValidationConfig, validator *validator.Validator, logger logger.Logger) (*ValidationMiddleware, error) {
	if config == nil {
		config = DefaultValidationConfig()
	}

	vm := &ValidationMiddleware{
		config:    config,
		validator: validator,
		logger:    logger,
	}

	// Compile patterns for better performance
	if err := vm.compilePatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile validation patterns: %w", err)
	}

	return vm, nil
}

// compilePatterns compiles all regex patterns used for validation
func (vm *ValidationMiddleware) compilePatterns() error {
	// SQL Injection patterns
	if vm.config.EnableSQLInjection {
		sqlPatterns := []string{
			`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`,
			`(?i)(drop\s+table|create\s+table|alter\s+table|truncate\s+table)`,
			`(?i)(grant\s+|revoke\s+|exec\s*\(|execute\s*\(|sp_|xp_)`,
			`(?i)(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)`,
			`(?i)(concat\s*\(|substring\s*\(|ascii\s*\(|char\s*\(|length\s*\()`,
		}
		for _, pattern := range sqlPatterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile SQL injection pattern: %w", err)
			}
			vm.sqlInjectionPatterns = append(vm.sqlInjectionPatterns, compiled)
		}
	}

	// XSS patterns
	if vm.config.EnableXSSProtection {
		xssPatterns := []string{
			`(?i)(<script[^>]*>.*?</script>|<script[^>]*/>)`,
			`(?i)(javascript:|vbscript:|data:text/html)`,
			`(?i)(onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=)`,
			`(?i)(<iframe|<object|<embed|<link|<meta)`,
			`(?i)(expression\s*\(|url\s*\(|@import)`,
		}
		for _, pattern := range xssPatterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile XSS pattern: %w", err)
			}
			vm.xssPatterns = append(vm.xssPatterns, compiled)
		}
	}

	// Path traversal patterns
	if vm.config.EnablePathTraversal {
		pathPatterns := []string{
			`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)`,
			`(?i)(%c0%af|%c1%9c|%%2e|%%2f)`,
			`(?i)(file:\/\/|ftp:\/\/|\\\\\w+\\)`,
		}
		for _, pattern := range pathPatterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile path traversal pattern: %w", err)
			}
			vm.pathTraversalPatterns = append(vm.pathTraversalPatterns, compiled)
		}
	}

	// Custom blocked patterns
	for _, pattern := range vm.config.BlockedPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile blocked pattern: %w", err)
		}
		vm.blockedPatterns = append(vm.blockedPatterns, compiled)
	}

	// Common validation patterns
	var err error
	vm.emailPattern, err = regexp.Compile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if err != nil {
		return err
	}

	vm.urlPattern, err = regexp.Compile(`^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$`)
	if err != nil {
		return err
	}

	vm.phonePattern, err = regexp.Compile(`^\+?[1-9]\d{1,14}$`)
	if err != nil {
		return err
	}

	vm.ipPattern, err = regexp.Compile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	if err != nil {
		return err
	}

	vm.uuidPattern, err = regexp.Compile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if err != nil {
		return err
	}

	vm.alphanumPattern, err = regexp.Compile(`^[a-zA-Z0-9_-]+$`)
	if err != nil {
		return err
	}

	return nil
}

// ValidateRequest validates the entire HTTP request
func (vm *ValidationMiddleware) ValidateRequest() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set timeout context
			ctx, cancel := context.WithTimeout(r.Context(), vm.config.RequestTimeout)
			defer cancel()
			r = r.WithContext(ctx)

			// Check request size
			if r.ContentLength > vm.config.MaxRequestSize {
				vm.writeValidationError(w, "Request size exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
				return
			}

			// Validate URL path
			if err := vm.validatePath(r.URL.Path); err != nil {
				vm.logger.Warn("Invalid request path", "path", r.URL.Path, "error", err)
				vm.writeValidationError(w, "Invalid request path", http.StatusBadRequest)
				return
			}

			// Validate query parameters
			if err := vm.validateQueryParams(r.URL.Query()); err != nil {
				vm.logger.Warn("Invalid query parameters", "error", err)
				vm.writeValidationError(w, "Invalid query parameters", http.StatusBadRequest)
				return
			}

			// Validate headers
			if err := vm.validateHeaders(r.Header); err != nil {
				vm.logger.Warn("Invalid headers", "error", err)
				vm.writeValidationError(w, "Invalid headers", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateJSON validates JSON request bodies against struct definitions
func (vm *ValidationMiddleware) ValidateJSON(target interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate JSON for POST, PUT, PATCH methods
			if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
				next.ServeHTTP(w, r)
				return
			}

			// Check content type
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				vm.writeValidationError(w, "Content-Type must be application/json", http.StatusBadRequest)
				return
			}

			// Limit request body size
			r.Body = http.MaxBytesReader(w, r.Body, vm.config.MaxRequestSize)

			// Parse JSON
			targetType := reflect.TypeOf(target)
			if targetType.Kind() == reflect.Ptr {
				targetType = targetType.Elem()
			}
			targetValue := reflect.New(targetType)
			targetInterface := targetValue.Interface()

			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields() // Strict JSON parsing

			if err := decoder.Decode(targetInterface); err != nil {
				vm.logger.Warn("JSON decode error", "error", err)
				vm.writeValidationError(w, "Invalid JSON format", http.StatusBadRequest)
				return
			}

			// Validate against security patterns
			if err := vm.validateJSONSecurity(targetInterface); err != nil {
				vm.logger.Warn("JSON security validation failed", "error", err)
				vm.writeValidationError(w, "Invalid input detected", http.StatusBadRequest)
				return
			}

			// Struct validation using validator
			if err := vm.validator.Struct(targetInterface); err != nil {
				vm.logger.Warn("Struct validation failed", "error", err)
				vm.writeValidationError(w, fmt.Sprintf("Validation failed: %s", err.Error()), http.StatusBadRequest)
				return
			}

			// Store validated data in context
			ctx := context.WithValue(r.Context(), "validated_json", targetInterface)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// ValidatePathParams validates URL path parameters
func (vm *ValidationMiddleware) ValidatePathParams(validations map[string]ValidationRule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)

			for paramName, rule := range validations {
				paramValue, exists := vars[paramName]
				if !exists && rule.Required {
					vm.writeValidationError(w, fmt.Sprintf("Required path parameter '%s' is missing", paramName), http.StatusBadRequest)
					return
				}

				if exists {
					if err := vm.validateParam(paramName, paramValue, rule); err != nil {
						vm.logger.Warn("Path parameter validation failed", "param", paramName, "value", paramValue, "error", err)
						vm.writeValidationError(w, fmt.Sprintf("Invalid path parameter '%s': %s", paramName, err.Error()), http.StatusBadRequest)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidationRule defines validation rules for parameters
type ValidationRule struct {
	Required    bool
	Type        string // "string", "int", "uuid", "email", "url", "alphanumeric"
	MinLength   int
	MaxLength   int
	MinValue    int64
	MaxValue    int64
	Pattern     string // Custom regex pattern
	AllowedValues []string
}

// validatePath validates the URL path for security issues
func (vm *ValidationMiddleware) validatePath(path string) error {
	// Check for path traversal
	for _, pattern := range vm.pathTraversalPatterns {
		if pattern.MatchString(path) {
			return fmt.Errorf("path traversal detected")
		}
	}

	// Check blocked patterns
	for _, pattern := range vm.blockedPatterns {
		if pattern.MatchString(path) {
			return fmt.Errorf("blocked pattern detected in path")
		}
	}

	return nil
}

// validateQueryParams validates query parameters
func (vm *ValidationMiddleware) validateQueryParams(params map[string][]string) error {
	for key, values := range params {
		// Validate parameter name
		if err := vm.validateString(key, 100); err != nil {
			return fmt.Errorf("invalid parameter name '%s': %w", key, err)
		}

		// Validate parameter values
		for _, value := range values {
			if err := vm.validateString(value, vm.config.MaxFieldLength); err != nil {
				return fmt.Errorf("invalid parameter value for '%s': %w", key, err)
			}
		}
	}

	return nil
}

// validateHeaders validates HTTP headers
func (vm *ValidationMiddleware) validateHeaders(headers http.Header) error {
	for key, values := range headers {
		// Skip standard headers
		if vm.isStandardHeader(key) {
			continue
		}

		// Validate custom header values
		for _, value := range values {
			if err := vm.validateString(value, 2000); err != nil {
				return fmt.Errorf("invalid header value for '%s': %w", key, err)
			}
		}
	}

	return nil
}

// validateJSONSecurity validates JSON data for security issues
func (vm *ValidationMiddleware) validateJSONSecurity(data interface{}) error {
	return vm.validateJSONValue(reflect.ValueOf(data))
}

// validateJSONValue recursively validates JSON values
func (vm *ValidationMiddleware) validateJSONValue(value reflect.Value) error {
	switch value.Kind() {
	case reflect.String:
		return vm.validateString(value.String(), vm.config.MaxFieldLength)
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if err := vm.validateJSONValue(value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			// Validate map key
			if err := vm.validateJSONValue(key); err != nil {
				return err
			}
			// Validate map value
			if err := vm.validateJSONValue(value.MapIndex(key)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if err := vm.validateJSONValue(value.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Ptr, reflect.Interface:
		if !value.IsNil() {
			return vm.validateJSONValue(value.Elem())
		}
	}

	return nil
}

// validateString validates string values for security issues
func (vm *ValidationMiddleware) validateString(input string, maxLength int) error {
	// Check length
	if len(input) > maxLength {
		return fmt.Errorf("string exceeds maximum length of %d", maxLength)
	}

	// Check for control characters (except tab, newline, carriage return)
	for _, r := range input {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return fmt.Errorf("control characters not allowed")
		}
	}

	// Check for SQL injection
	if vm.config.EnableSQLInjection {
		for _, pattern := range vm.sqlInjectionPatterns {
			if pattern.MatchString(input) {
				return fmt.Errorf("potential SQL injection detected")
			}
		}
	}

	// Check for XSS
	if vm.config.EnableXSSProtection {
		for _, pattern := range vm.xssPatterns {
			if pattern.MatchString(input) {
				return fmt.Errorf("potential XSS attack detected")
			}
		}
	}

	// Check for path traversal
	if vm.config.EnablePathTraversal {
		for _, pattern := range vm.pathTraversalPatterns {
			if pattern.MatchString(input) {
				return fmt.Errorf("path traversal detected")
			}
		}
	}

	// Check blocked patterns
	for _, pattern := range vm.blockedPatterns {
		if pattern.MatchString(input) {
			return fmt.Errorf("blocked pattern detected")
		}
	}

	return nil
}

// validateParam validates a single parameter value against validation rules
func (vm *ValidationMiddleware) validateParam(name, value string, rule ValidationRule) error {
	// Required check
	if rule.Required && value == "" {
		return fmt.Errorf("required parameter is empty")
	}

	if value == "" {
		return nil // Optional parameter
	}

	// Type validation
	switch rule.Type {
	case "string":
		return vm.validateStringType(value, rule)
	case "int":
		return vm.validateIntType(value, rule)
	case "uuid":
		if !vm.uuidPattern.MatchString(value) {
			return fmt.Errorf("invalid UUID format")
		}
	case "email":
		if !vm.emailPattern.MatchString(value) {
			return fmt.Errorf("invalid email format")
		}
	case "url":
		if !vm.urlPattern.MatchString(value) {
			return fmt.Errorf("invalid URL format")
		}
	case "alphanumeric":
		if !vm.alphanumPattern.MatchString(value) {
			return fmt.Errorf("only alphanumeric characters, hyphens, and underscores allowed")
		}
	case "phone":
		if !vm.phonePattern.MatchString(value) {
			return fmt.Errorf("invalid phone number format")
		}
	case "ip":
		if !vm.ipPattern.MatchString(value) {
			return fmt.Errorf("invalid IP address format")
		}
	}

	// Custom pattern validation
	if rule.Pattern != "" {
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid validation pattern")
		}
		if !pattern.MatchString(value) {
			return fmt.Errorf("value does not match required pattern")
		}
	}

	// Allowed values validation
	if len(rule.AllowedValues) > 0 {
		allowed := false
		for _, allowedValue := range rule.AllowedValues {
			if value == allowedValue {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("value not in allowed list")
		}
	}

	// Basic security validation
	return vm.validateString(value, vm.config.MaxFieldLength)
}

// validateStringType validates string type parameters
func (vm *ValidationMiddleware) validateStringType(value string, rule ValidationRule) error {
	if rule.MinLength > 0 && len(value) < rule.MinLength {
		return fmt.Errorf("minimum length is %d", rule.MinLength)
	}

	maxLength := rule.MaxLength
	if maxLength == 0 {
		maxLength = vm.config.MaxFieldLength
	}

	if len(value) > maxLength {
		return fmt.Errorf("maximum length is %d", maxLength)
	}

	return vm.validateString(value, maxLength)
}

// validateIntType validates integer type parameters
func (vm *ValidationMiddleware) validateIntType(value string, rule ValidationRule) error {
	intValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer format")
	}

	if rule.MinValue != 0 && intValue < rule.MinValue {
		return fmt.Errorf("minimum value is %d", rule.MinValue)
	}

	if rule.MaxValue != 0 && intValue > rule.MaxValue {
		return fmt.Errorf("maximum value is %d", rule.MaxValue)
	}

	return nil
}

// isStandardHeader checks if a header is a standard HTTP header
func (vm *ValidationMiddleware) isStandardHeader(headerName string) bool {
	standardHeaders := map[string]bool{
		"accept":              true,
		"accept-encoding":     true,
		"accept-language":     true,
		"authorization":       true,
		"cache-control":       true,
		"connection":          true,
		"content-encoding":    true,
		"content-length":      true,
		"content-type":        true,
		"cookie":              true,
		"date":                true,
		"host":                true,
		"if-modified-since":   true,
		"if-none-match":       true,
		"origin":              true,
		"referer":             true,
		"user-agent":          true,
		"x-forwarded-for":     true,
		"x-forwarded-proto":   true,
		"x-real-ip":           true,
		"x-requested-with":    true,
	}

	return standardHeaders[strings.ToLower(headerName)]
}

// writeValidationError writes a standardized validation error response
func (vm *ValidationMiddleware) writeValidationError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":     message,
		"code":      statusCode,
		"timestamp": time.Now().UTC(),
		"type":      "validation_error",
	}

	json.NewEncoder(w).Encode(response)
}

// SanitizeInput provides input sanitization utilities
type SanitizeInput struct{}

// SanitizeHTML removes or encodes HTML tags from input
func (si *SanitizeInput) SanitizeHTML(input string) string {
	// Remove HTML tags
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	sanitized := htmlTagPattern.ReplaceAllString(input, "")

	// Encode HTML entities
	sanitized = strings.ReplaceAll(sanitized, "&", "&amp;")
	sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, "\"", "&quot;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#x27;")

	return sanitized
}

// SanitizeSQL removes SQL injection attempts
func (si *SanitizeInput) SanitizeSQL(input string) string {
	// Remove common SQL injection patterns
	sqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`),
		regexp.MustCompile(`(?i)(drop\s+table|create\s+table|alter\s+table|truncate\s+table)`),
		regexp.MustCompile(`(?i)(grant\s+|revoke\s+|exec\s*\(|execute\s*\(|sp_|xp_)`),
		regexp.MustCompile(`(?i)(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)`),
	}

	sanitized := input
	for _, pattern := range sqlPatterns {
		sanitized = pattern.ReplaceAllString(sanitized, "")
	}

	return strings.TrimSpace(sanitized)
}

// SanitizeFileName sanitizes file names for safe storage
func (si *SanitizeInput) SanitizeFileName(filename string) string {
	// Remove path separators and dangerous characters
	dangerousChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	sanitized := dangerousChars.ReplaceAllString(filename, "")

	// Remove leading/trailing dots and spaces
	sanitized = strings.Trim(sanitized, ". ")

	// Limit length
	if len(sanitized) > 255 {
		sanitized = sanitized[:255]
	}

	// Ensure we have a valid filename
	if sanitized == "" {
		sanitized = "unnamed_file"
	}

	return sanitized
}

// GetValidatedJSON retrieves validated JSON from request context
func GetValidatedJSON(r *http.Request) interface{} {
	if validated := r.Context().Value("validated_json"); validated != nil {
		return validated
	}
	return nil
}