package validator

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	validate *validator.Validate
	once     sync.Once
)

// Validator provides validation functionality
type Validator struct {
	validate *validator.Validate
}

// New creates a new validator instance
func New() *Validator {
	Initialize()
	return &Validator{
		validate: validate,
	}
}

// Struct validates a struct using the validator instance
func (v *Validator) Struct(s interface{}) error {
	return v.validate.Struct(s)
}

// Initialize initializes the global validator instance
func Initialize() {
	once.Do(func() {
		validate = validator.New()
		
		// Register custom tag name function to use json tags
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})
		
		// Register custom validators
		registerCustomValidators()
	})
}

// Validate validates a struct
func Validate(s interface{}) error {
	if validate == nil {
		Initialize()
	}
	
	err := validate.Struct(s)
	if err == nil {
		return nil
	}
	
	// Convert validation errors to user-friendly format
	var validationErrors []string
	for _, err := range err.(validator.ValidationErrors) {
		validationErrors = append(validationErrors, formatValidationError(err))
	}
	
	return fmt.Errorf("validation failed: %s", strings.Join(validationErrors, ", "))
}

// ValidateVar validates a single variable
func ValidateVar(field interface{}, tag string) error {
	if validate == nil {
		Initialize()
	}
	
	return validate.Var(field, tag)
}

// formatValidationError formats a validation error into a human-readable message
func formatValidationError(err validator.FieldError) string {
	field := err.Field()
	
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", field, err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters", field, err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters", field, err.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, err.Param())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", field)
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "json":
		return fmt.Sprintf("%s must be valid JSON", field)
	case "alphanum":
		return fmt.Sprintf("%s must contain only alphanumeric characters", field)
	case "alpha":
		return fmt.Sprintf("%s must contain only alphabetic characters", field)
	case "numeric":
		return fmt.Sprintf("%s must contain only numeric characters", field)
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, err.Param())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", field, err.Param())
	case "lt":
		return fmt.Sprintf("%s must be less than %s", field, err.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", field, err.Param())
	default:
		return fmt.Sprintf("%s failed validation (%s)", field, err.Tag())
	}
}

// registerCustomValidators registers custom validation rules
func registerCustomValidators() {
	// Register workflow_name validator
	validate.RegisterValidation("workflow_name", validateWorkflowName)
	
	// Register node_type validator
	validate.RegisterValidation("node_type", validateNodeType)
	
	// Register cron validator
	validate.RegisterValidation("cron", validateCron)
}

// validateWorkflowName validates workflow names
func validateWorkflowName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	
	// Workflow name should be 1-100 characters, alphanumeric with spaces, hyphens, underscores
	if len(name) < 1 || len(name) > 100 {
		return false
	}
	
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == ' ' || char == '-' || char == '_') {
			return false
		}
	}
	
	return true
}

// validateNodeType validates node type identifiers
func validateNodeType(fl validator.FieldLevel) bool {
	nodeType := fl.Field().String()
	
	// Node type should follow n8n convention: n8n-nodes-base.nodeName
	if !strings.HasPrefix(nodeType, "n8n-nodes-") {
		return false
	}
	
	// Should have at least one dot separator
	parts := strings.Split(nodeType, ".")
	if len(parts) < 2 {
		return false
	}
	
	// Node name should be valid
	nodeName := parts[len(parts)-1]
	if len(nodeName) < 1 || len(nodeName) > 50 {
		return false
	}
	
	return true
}

// validateCron validates cron expressions
func validateCron(fl validator.FieldLevel) bool {
	cronExpr := fl.Field().String()
	
	// Basic cron validation - should have 5 or 6 fields
	fields := strings.Fields(cronExpr)
	if len(fields) != 5 && len(fields) != 6 {
		return false
	}
	
	// TODO: Add more sophisticated cron validation if needed
	return true
}

// ValidateWorkflow validates a workflow structure
type WorkflowValidationConfig struct {
	MaxNodes       int
	MaxConnections int
	RequiredFields []string
}

// ValidateWorkflowStructure validates a workflow's structure beyond basic field validation
func ValidateWorkflowStructure(workflow interface{}, config *WorkflowValidationConfig) error {
	// This would implement workflow-specific validation logic
	// For now, just use basic struct validation
	return Validate(workflow)
}