package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/webhooks"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// WebhooksHandler handles webhook-related HTTP requests
type WebhooksHandler struct {
	service *webhooks.Service
	logger  logger.Logger
}

// NewWebhooksHandler creates a new webhooks handler
func NewWebhooksHandler(service *webhooks.Service, logger logger.Logger) *WebhooksHandler {
	return &WebhooksHandler{
		service: service,
		logger:  logger,
	}
}

// CreateWebhookRequest represents the request to create a webhook
type CreateWebhookRequest struct {
	WorkflowID  string                 `json:"workflow_id" validate:"required,uuid"`
	NodeID      string                 `json:"node_id" validate:"required"`
	Path        string                 `json:"path" validate:"required,min=1,max=200"`
	Method      string                 `json:"method" validate:"required,oneof=GET POST PUT PATCH DELETE"`
	Enabled     bool                   `json:"enabled"`
	SecretToken string                 `json:"secret_token,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// UpdateWebhookRequest represents the request to update a webhook
type UpdateWebhookRequest struct {
	Path        *string                `json:"path,omitempty" validate:"omitempty,min=1,max=200"`
	Method      *string                `json:"method,omitempty" validate:"omitempty,oneof=GET POST PUT PATCH DELETE"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	SecretToken *string                `json:"secret_token,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// WebhookResponse represents a webhook in API responses
type WebhookResponse struct {
	ID            string                 `json:"id"`
	WorkflowID    string                 `json:"workflow_id"`
	NodeID        string                 `json:"node_id"`
	TeamID        string                 `json:"team_id"`
	Path          string                 `json:"path"`
	Method        string                 `json:"method"`
	Enabled       bool                   `json:"enabled"`
	Headers       map[string]string      `json:"headers"`
	Settings      map[string]interface{} `json:"settings"`
	URL           string                 `json:"url"`
	LastTriggered *string                `json:"last_triggered,omitempty"`
	TriggerCount  int64                  `json:"trigger_count"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
}

// WebhookExecutionResponse represents a webhook execution in API responses
type WebhookExecutionResponse struct {
	ID          string            `json:"id"`
	WebhookID   string            `json:"webhook_id"`
	WorkflowID  string            `json:"workflow_id"`
	ExecutionID *string           `json:"execution_id,omitempty"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Query       map[string]string `json:"query"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	Status      string            `json:"status"`
	Response    string            `json:"response"`
	Error       string            `json:"error,omitempty"`
	Duration    int64             `json:"duration"`
	CreatedAt   string            `json:"created_at"`
}

// CreateWebhook creates a new webhook
func (h *WebhooksHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in create webhook request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Create webhook
	webhook := &webhooks.Webhook{
		ID:          uuid.New().String(),
		WorkflowID:  req.WorkflowID,
		NodeID:      req.NodeID,
		TeamID:      userCtx.TeamID,
		Path:        req.Path,
		Method:      req.Method,
		Enabled:     req.Enabled,
		SecretToken: req.SecretToken,
		Headers:     req.Headers,
		Settings:    req.Settings,
		CreatedBy:   userCtx.ID,
	}

	if webhook.Headers == nil {
		webhook.Headers = make(map[string]string)
	}
	if webhook.Settings == nil {
		webhook.Settings = make(map[string]interface{})
	}

	err := h.service.CreateWebhook(r.Context(), webhook)
	if err != nil {
		h.logger.Error("Failed to create webhook", "error", err, "user_id", userCtx.ID)
		writeError(w, err)
		return
	}

	response := h.webhookToResponse(webhook)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhook": response,
	})

	h.logger.Info("Webhook created successfully", "webhook_id", webhook.ID, "user_id", userCtx.ID)
}

// ListWebhooks lists webhooks for a workflow
func (h *WebhooksHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	workflowID := r.URL.Query().Get("workflow_id")
	if workflowID == "" {
		writeError(w, errors.NewValidationError("workflow_id parameter is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	webhooks, err := h.service.ListWebhooks(r.Context(), workflowID)
	if err != nil {
		h.logger.Error("Failed to list webhooks", "error", err, "workflow_id", workflowID)
		writeError(w, err)
		return
	}

	responses := make([]WebhookResponse, len(webhooks))
	for i, webhook := range webhooks {
		responses[i] = h.webhookToResponse(webhook)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhooks": responses,
		"count":    len(responses),
	})
}

// GetWebhook retrieves a specific webhook by ID
func (h *WebhooksHandler) GetWebhook(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "id")
	if webhookID == "" {
		writeError(w, errors.NewValidationError("Webhook ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	webhook, err := h.service.GetWebhookByID(r.Context(), webhookID)
	if err != nil {
		h.logger.Error("Failed to get webhook", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	response := h.webhookToResponse(webhook)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhook": response,
	})
}

// UpdateWebhook updates a webhook
func (h *WebhooksHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "id")
	if webhookID == "" {
		writeError(w, errors.NewValidationError("Webhook ID is required"))
		return
	}

	var req UpdateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in update webhook request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get existing webhook
	webhook, err := h.service.GetWebhookByID(r.Context(), webhookID)
	if err != nil {
		h.logger.Error("Failed to get webhook for update", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	// Update fields
	if req.Path != nil {
		webhook.Path = *req.Path
	}
	if req.Method != nil {
		webhook.Method = *req.Method
	}
	if req.Enabled != nil {
		webhook.Enabled = *req.Enabled
	}
	if req.SecretToken != nil {
		webhook.SecretToken = *req.SecretToken
	}
	if req.Headers != nil {
		webhook.Headers = req.Headers
	}
	if req.Settings != nil {
		webhook.Settings = req.Settings
	}

	err = h.service.UpdateWebhook(r.Context(), webhook)
	if err != nil {
		h.logger.Error("Failed to update webhook", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	response := h.webhookToResponse(webhook)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhook": response,
	})

	h.logger.Info("Webhook updated successfully", "webhook_id", webhookID, "user_id", userCtx.ID)
}

// DeleteWebhook deletes a webhook
func (h *WebhooksHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "id")
	if webhookID == "" {
		writeError(w, errors.NewValidationError("Webhook ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	err := h.service.DeleteWebhook(r.Context(), webhookID)
	if err != nil {
		h.logger.Error("Failed to delete webhook", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.logger.Info("Webhook deleted successfully", "webhook_id", webhookID, "user_id", userCtx.ID)
}

// GetWebhookExecutions retrieves executions for a webhook
func (h *WebhooksHandler) GetWebhookExecutions(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "id")
	if webhookID == "" {
		writeError(w, errors.NewValidationError("Webhook ID is required"))
		return
	}

	// Parse pagination parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	
	limit := 50 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}
	
	offset := 0 // default
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	executions, err := h.service.ListExecutions(r.Context(), webhookID, limit, offset)
	if err != nil {
		h.logger.Error("Failed to get webhook executions", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	responses := make([]WebhookExecutionResponse, len(executions))
	for i, execution := range executions {
		responses[i] = h.executionToResponse(execution)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"executions": responses,
		"count":      len(responses),
		"limit":      limit,
		"offset":     offset,
	})
}

// TestWebhook tests a webhook endpoint
func (h *WebhooksHandler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "id")
	if webhookID == "" {
		writeError(w, errors.NewValidationError("Webhook ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get webhook details
	webhook, err := h.service.GetWebhookByID(r.Context(), webhookID)
	if err != nil {
		h.logger.Error("Failed to get webhook for test", "error", err, "webhook_id", webhookID)
		writeError(w, err)
		return
	}

	// Create test data
	testData := map[string]interface{}{
		"test":      true,
		"timestamp": time.Now().Unix(),
		"message":   "This is a test webhook payload",
		"user_id":   userCtx.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"webhook_id":  webhook.ID,
		"url":         h.buildWebhookURL(webhook),
		"method":      webhook.Method,
		"test_data":   testData,
		"status":      "test_ready",
		"message":     "You can now send a test request to this webhook",
	})

	h.logger.Info("Webhook test prepared", "webhook_id", webhookID, "user_id", userCtx.ID)
}

// Helper methods

func (h *WebhooksHandler) webhookToResponse(webhook *webhooks.Webhook) WebhookResponse {
	response := WebhookResponse{
		ID:           webhook.ID,
		WorkflowID:   webhook.WorkflowID,
		NodeID:       webhook.NodeID,
		TeamID:       webhook.TeamID,
		Path:         webhook.Path,
		Method:       webhook.Method,
		Enabled:      webhook.Enabled,
		Headers:      webhook.Headers,
		Settings:     webhook.Settings,
		URL:          h.buildWebhookURL(webhook),
		TriggerCount: webhook.TriggerCount,
		CreatedAt:    webhook.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    webhook.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if webhook.LastTriggered != nil {
		lastTriggered := webhook.LastTriggered.Format("2006-01-02T15:04:05Z07:00")
		response.LastTriggered = &lastTriggered
	}

	return response
}

func (h *WebhooksHandler) executionToResponse(execution *webhooks.WebhookExecution) WebhookExecutionResponse {
	response := WebhookExecutionResponse{
		ID:          execution.ID,
		WebhookID:   execution.WebhookID,
		WorkflowID:  execution.WorkflowID,
		ExecutionID: execution.ExecutionID,
		Method:      execution.Method,
		Path:        execution.Path,
		Headers:     execution.Headers,
		Body:        execution.Body,
		Query:       execution.Query,
		IPAddress:   execution.IPAddress,
		UserAgent:   execution.UserAgent,
		Status:      execution.Status,
		Response:    execution.Response,
		Error:       execution.Error,
		Duration:    execution.Duration,
		CreatedAt:   execution.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	return response
}

func (h *WebhooksHandler) buildWebhookURL(webhook *webhooks.Webhook) string {
	// This should be configurable based on your domain
	baseURL := "http://localhost:8081" // webhook service port
	return fmt.Sprintf("%s/webhook/%s", baseURL, webhook.WorkflowID)
}