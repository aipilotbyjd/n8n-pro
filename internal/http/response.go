package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"n8n-pro/internal/domain/common/errors"
)

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// APIError represents an API error response
type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Trace   string                 `json:"trace,omitempty"`
}

// Meta contains metadata for paginated responses
type Meta struct {
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// ValidationError represents field validation errors
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// WriteJSON writes a JSON response with the given status code and data
func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	response := APIResponse{
		Success:   statusCode >= 200 && statusCode < 300,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, statusCode, response)
}

// WriteError writes an error response
func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	apiError := &APIError{
		Code:    code,
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, statusCode, response)
}

// WriteErrorWithDetails writes an error response with additional details
func WriteErrorWithDetails(w http.ResponseWriter, statusCode int, code, message string, details map[string]interface{}) {
	apiError := &APIError{
		Code:    code,
		Message: message,
		Details: details,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, statusCode, response)
}

// WriteValidationErrors writes validation error response
func WriteValidationErrors(w http.ResponseWriter, validationErrors []ValidationError) {
	apiError := &APIError{
		Code:    "VALIDATION_ERROR",
		Message: "Request validation failed",
		Details: map[string]interface{}{
			"validation_errors": validationErrors,
		},
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, http.StatusBadRequest, response)
}

// WritePaginatedJSON writes a paginated JSON response
func WritePaginatedJSON(w http.ResponseWriter, statusCode int, data interface{}, meta *Meta) {
	response := APIResponse{
		Success:   statusCode >= 200 && statusCode < 300,
		Data:      data,
		Meta:      meta,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSONResponse(w, statusCode, response)
}

// WriteDomainError converts domain errors to HTTP responses
func WriteDomainError(w http.ResponseWriter, err error) {
	if domainErr, ok := err.(*errors.DomainError); ok {
		statusCode := domainErrorToHTTPStatus(domainErr.Type)
		
		apiError := &APIError{
			Code:    domainErr.Code,
			Message: domainErr.Message,
			Details: domainErr.Context,
		}

		response := APIResponse{
			Success:   false,
			Error:     apiError,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		writeJSONResponse(w, statusCode, response)
		return
	}

	// Fallback for unknown errors
	WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred")
}

// WriteNotFound writes a 404 not found response
func WriteNotFound(w http.ResponseWriter, resource string) {
	WriteError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("%s not found", resource))
}

// WriteUnauthorized writes a 401 unauthorized response
func WriteUnauthorized(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Authentication required"
	}
	WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", message)
}

// WriteForbidden writes a 403 forbidden response
func WriteForbidden(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Access forbidden"
	}
	WriteError(w, http.StatusForbidden, "FORBIDDEN", message)
}

// WriteConflict writes a 409 conflict response
func WriteConflict(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Resource conflict"
	}
	WriteError(w, http.StatusConflict, "CONFLICT", message)
}

// WriteBadRequest writes a 400 bad request response
func WriteBadRequest(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Bad request"
	}
	WriteError(w, http.StatusBadRequest, "BAD_REQUEST", message)
}

// WriteInternalError writes a 500 internal server error response
func WriteInternalError(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Internal server error"
	}
	WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", message)
}

// WriteTooManyRequests writes a 429 too many requests response
func WriteTooManyRequests(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Too many requests"
	}
	WriteError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", message)
}

// WriteCreated writes a 201 created response
func WriteCreated(w http.ResponseWriter, data interface{}) {
	WriteJSON(w, http.StatusCreated, data)
}

// WriteNoContent writes a 204 no content response
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Helper functions

// writeJSONResponse is the low-level JSON response writer
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	
	if err := encoder.Encode(data); err != nil {
		// If we can't encode the response, write a simple error
		// This is a last resort and should rarely happen
		http.Error(w, `{"success":false,"error":{"code":"ENCODING_ERROR","message":"Failed to encode response"}}`, 
			http.StatusInternalServerError)
	}
}

// domainErrorToHTTPStatus maps domain error types to HTTP status codes
func domainErrorToHTTPStatus(errorType string) int {
	switch errorType {
	case "NOT_FOUND":
		return http.StatusNotFound
	case "VALIDATION_ERROR":
		return http.StatusBadRequest
	case "BUSINESS_RULE_VIOLATION":
		return http.StatusBadRequest
	case "CONFLICT":
		return http.StatusConflict
	case "UNAUTHORIZED":
		return http.StatusUnauthorized
	case "FORBIDDEN":
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// CreateValidationError creates a validation error struct
func CreateValidationError(field, message, code string) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	}
}

// CreateMeta creates a pagination metadata struct
func CreateMeta(page, perPage, total int) *Meta {
	totalPages := (total + perPage - 1) / perPage // Ceiling division
	
	return &Meta{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}
}

// ErrorHandler is a centralized error handler for the application
type ErrorHandler struct {
	logger interface{} // Will be replaced with proper logger interface
	debug  bool
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger interface{}, debug bool) *ErrorHandler {
	return &ErrorHandler{
		logger: logger,
		debug:  debug,
	}
}

// HandleError handles different types of errors and writes appropriate responses
func (eh *ErrorHandler) HandleError(w http.ResponseWriter, r *http.Request, err error) {
	// Log the error (simplified for now)
	fmt.Printf("Error handling request %s %s: %v\n", r.Method, r.URL.Path, err)

	// Handle different error types
	if domainErr, ok := err.(*errors.DomainError); ok {
		WriteDomainError(w, domainErr)
		return
	}

	// Handle validation errors
	if validationErrs, ok := err.(*errors.ValidationErrors); ok {
		var apiValidationErrors []ValidationError
		for _, validationErr := range *validationErrs {
			apiValidationErrors = append(apiValidationErrors, ValidationError{
				Field:   validationErr.Field,
				Message: validationErr.Message,
				Code:    "VALIDATION_ERROR",
			})
		}
		WriteValidationErrors(w, apiValidationErrors)
		return
	}

	// Default to internal server error
	message := "An unexpected error occurred"
	if eh.debug {
		message = err.Error()
	}
	
	WriteInternalError(w, message)
}

// ResponseInterceptor can be used to modify responses before they're sent
type ResponseInterceptor struct {
	http.ResponseWriter
	statusCode int
	body       []byte
}

// NewResponseInterceptor creates a new response interceptor
func NewResponseInterceptor(w http.ResponseWriter) *ResponseInterceptor {
	return &ResponseInterceptor{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader captures the status code
func (ri *ResponseInterceptor) WriteHeader(statusCode int) {
	ri.statusCode = statusCode
	ri.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the response body
func (ri *ResponseInterceptor) Write(body []byte) (int, error) {
	ri.body = append(ri.body, body...)
	return ri.ResponseWriter.Write(body)
}

// GetStatusCode returns the captured status code
func (ri *ResponseInterceptor) GetStatusCode() int {
	return ri.statusCode
}

// GetBody returns the captured body
func (ri *ResponseInterceptor) GetBody() []byte {
	return ri.body
}