package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"n8n-pro/internal/presentation/http/middleware"
	"n8n-pro/internal/credentials"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
)

type CredentialHandler struct {
	credentialManager *credentials.Manager
	logger            logger.Logger
}

func NewCredentialHandler(credentialManager *credentials.Manager, logger logger.Logger) *CredentialHandler {
	return &CredentialHandler{
		credentialManager: credentialManager,
		logger:            logger,
	}
}

// CreateCredential creates a new credential
func (h *CredentialHandler) CreateCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req credentials.CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Create credential
	credential, err := h.credentialManager.Create(r.Context(), user.ID, user.TeamID, &req)
	if err != nil {
		h.logger.Error("Failed to create credential", "user_id", user.ID, "error", err)
		writeError(w, err)
		return
	}

	h.logger.Info("Credential created successfully", 
		"credential_id", credential.ID, 
		"user_id", user.ID,
		"name", credential.Name,
		"type", credential.Type,
	)

	writeSuccess(w, http.StatusCreated, credential)
}

// GetCredential retrieves a specific credential
func (h *CredentialHandler) GetCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		writeError(w, errors.NewValidationError("Credential ID is required"))
		return
	}

	// Get credential
	credential, err := h.credentialManager.GetByID(r.Context(), user.ID, user.TeamID, credentialID)
	if err != nil {
		h.logger.Error("Failed to get credential", 
			"credential_id", credentialID, 
			"user_id", user.ID, 
			"error", err,
		)
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusOK, credential)
}

// ListCredentials retrieves credentials with filtering
func (h *CredentialHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Parse query parameters
	filter := &credentials.CredentialFilter{
		OwnerID: user.ID,
		TeamID:  user.TeamID,
		Limit:   50, // Default limit
		Offset:  0,
	}

	// Parse optional parameters
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 100 {
			filter.Limit = l
		}
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	if credType := r.URL.Query().Get("type"); credType != "" {
		filter.Type = credentials.CredentialType(credType)
	}

	if sharingLevel := r.URL.Query().Get("sharing_level"); sharingLevel != "" {
		filter.SharingLevel = credentials.SharingLevel(sharingLevel)
	}

	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			filter.IsActive = &active
		}
	}

	// Get credentials
	creds, total, err := h.credentialManager.List(r.Context(), user.ID, user.TeamID, filter)
	if err != nil {
		h.logger.Error("Failed to list credentials", "user_id", user.ID, "error", err)
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"credentials": creds,
		"total":       total,
		"limit":       filter.Limit,
		"offset":      filter.Offset,
	}

	writeSuccess(w, http.StatusOK, response)
}

// UpdateCredential updates an existing credential
func (h *CredentialHandler) UpdateCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		writeError(w, errors.NewValidationError("Credential ID is required"))
		return
	}

	var req credentials.UpdateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Update credential
	credential, err := h.credentialManager.Update(r.Context(), user.ID, user.TeamID, credentialID, &req)
	if err != nil {
		h.logger.Error("Failed to update credential", 
			"credential_id", credentialID, 
			"user_id", user.ID, 
			"error", err,
		)
		writeError(w, err)
		return
	}

	h.logger.Info("Credential updated successfully", 
		"credential_id", credentialID, 
		"user_id", user.ID,
		"name", credential.Name,
	)

	writeSuccess(w, http.StatusOK, credential)
}

// DeleteCredential deletes a credential
func (h *CredentialHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		writeError(w, errors.NewValidationError("Credential ID is required"))
		return
	}

	// Delete credential
	err := h.credentialManager.Delete(r.Context(), user.ID, user.TeamID, credentialID)
	if err != nil {
		h.logger.Error("Failed to delete credential", 
			"credential_id", credentialID, 
			"user_id", user.ID, 
			"error", err,
		)
		writeError(w, err)
		return
	}

	h.logger.Info("Credential deleted successfully", 
		"credential_id", credentialID, 
		"user_id", user.ID,
	)

	response := map[string]interface{}{
		"message": "Credential deleted successfully",
	}

	writeSuccess(w, http.StatusOK, response)
}

// TestCredential tests a credential connection
func (h *CredentialHandler) TestCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		writeError(w, errors.NewValidationError("Credential ID is required"))
		return
	}

	// Test credential
	result, err := h.credentialManager.TestCredential(r.Context(), credentialID, user.ID, user.TeamID)
	if err != nil {
		h.logger.Error("Failed to test credential", 
			"credential_id", credentialID, 
			"user_id", user.ID, 
			"error", err,
		)
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"success": result.Success,
		"message": result.Message,
		"details": result.Details,
	}

	writeSuccess(w, http.StatusOK, response)
}

// GetDecryptedCredential returns decrypted credential data (for internal use)
func (h *CredentialHandler) GetDecryptedCredential(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		writeError(w, errors.NewValidationError("Credential ID is required"))
		return
	}

	// Get decrypted credential data
	credData, err := h.credentialManager.GetDecryptedData(r.Context(), credentialID, user.ID, user.TeamID)
	if err != nil {
		h.logger.Error("Failed to get decrypted credential", 
			"credential_id", credentialID, 
			"user_id", user.ID, 
			"error", err,
		)
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusOK, credData)
}

// GetCredentialTypes returns supported credential types
func (h *CredentialHandler) GetCredentialTypes(w http.ResponseWriter, r *http.Request) {
	types := []map[string]interface{}{
		{
			"type":        "api_key",
			"name":        "API Key",
			"description": "Simple API key authentication",
			"fields": []map[string]interface{}{
				{"name": "api_key", "type": "string", "required": true, "sensitive": true},
				{"name": "header", "type": "string", "required": false, "default": "X-API-Key"},
			},
		},
		{
			"type":        "basic_auth",
			"name":        "Basic Authentication",
			"description": "Username and password authentication",
			"fields": []map[string]interface{}{
				{"name": "username", "type": "string", "required": true},
				{"name": "password", "type": "string", "required": true, "sensitive": true},
			},
		},
		{
			"type":        "oauth2",
			"name":        "OAuth 2.0",
			"description": "OAuth 2.0 authentication",
			"fields": []map[string]interface{}{
				{"name": "client_id", "type": "string", "required": true},
				{"name": "client_secret", "type": "string", "required": true, "sensitive": true},
				{"name": "auth_url", "type": "string", "required": true},
				{"name": "token_url", "type": "string", "required": true},
				{"name": "redirect_uri", "type": "string", "required": false},
				{"name": "scope", "type": "string", "required": false},
			},
		},
		{
			"type":        "database",
			"name":        "Database Connection",
			"description": "Database connection credentials",
			"fields": []map[string]interface{}{
				{"name": "host", "type": "string", "required": true},
				{"name": "port", "type": "number", "required": true, "default": 5432},
				{"name": "username", "type": "string", "required": true},
				{"name": "password", "type": "string", "required": true, "sensitive": true},
				{"name": "database", "type": "string", "required": true},
				{"name": "ssl", "type": "boolean", "required": false, "default": false},
			},
		},
		{
			"type":        "smtp",
			"name":        "SMTP Server",
			"description": "Email server credentials",
			"fields": []map[string]interface{}{
				{"name": "smtp_host", "type": "string", "required": true},
				{"name": "smtp_port", "type": "number", "required": true, "default": 587},
				{"name": "username", "type": "string", "required": true},
				{"name": "password", "type": "string", "required": true, "sensitive": true},
				{"name": "use_tls", "type": "boolean", "required": false, "default": true},
			},
		},
		{
			"type":        "aws",
			"name":        "Amazon Web Services",
			"description": "AWS access credentials",
			"fields": []map[string]interface{}{
				{"name": "access_key_id", "type": "string", "required": true},
				{"name": "secret_access_key", "type": "string", "required": true, "sensitive": true},
				{"name": "region", "type": "string", "required": true, "default": "us-east-1"},
			},
		},
		{
			"type":        "gcp",
			"name":        "Google Cloud Platform",
			"description": "GCP service account credentials",
			"fields": []map[string]interface{}{
				{"name": "project_id", "type": "string", "required": true},
				{"name": "service_account", "type": "text", "required": true, "sensitive": true},
			},
		},
		{
			"type":        "azure",
			"name":        "Microsoft Azure",
			"description": "Azure service principal credentials",
			"fields": []map[string]interface{}{
				{"name": "client_id", "type": "string", "required": true},
				{"name": "client_secret", "type": "string", "required": true, "sensitive": true},
				{"name": "tenant_id", "type": "string", "required": true},
			},
		},
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"types": types,
	})
}

// GetCredentialStats returns credential usage statistics
func (h *CredentialHandler) GetCredentialStats(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get usage statistics
	stats, err := h.credentialManager.GetUsageStats(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get credential stats", "user_id", user.ID, "error", err)
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusOK, stats)
}