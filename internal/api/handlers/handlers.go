package handlers

import (
	"encoding/json"
	"net/http"

	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
)

func writeError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	var message string

	if appErr := errors.GetAppError(err); appErr != nil {
		statusCode = appErr.HTTPStatus()
		message = appErr.Message
	} else {
		statusCode = http.StatusInternalServerError
		message = "Internal server error"
	}

	w.WriteHeader(statusCode)
	response := common.NewErrorResponse("error", message, "")
	json.NewEncoder(w).Encode(response)
}

func writeSuccess(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := common.NewSuccessResponse(data)
	json.NewEncoder(w).Encode(response)
}
