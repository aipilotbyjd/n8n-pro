package handlers

import (
	"encoding/json"
	"net/http"

	"n8n-pro/internal/shared"
	"n8n-pro/pkg/errors"
)

func writeError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	var code string
	var message string
	var details string
	var context map[string]interface{}

	if appErr := errors.GetAppError(err); appErr != nil {
		statusCode = appErr.HTTPStatus()
		code = string(appErr.Code)
		message = appErr.Message
		details = appErr.Details
		context = appErr.Context
	} else {
		statusCode = http.StatusInternalServerError
		code = "internal_error"
		message = "Internal server error"
	}

	w.WriteHeader(statusCode)
	response := common.NewEnhancedErrorResponse(code, message, details, context)
	json.NewEncoder(w).Encode(response)
}

func writeSuccess(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := common.NewSuccessResponse(data)
	json.NewEncoder(w).Encode(response)
}
