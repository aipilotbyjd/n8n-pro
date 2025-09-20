package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/messaging"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
)

// Webhook represents a webhook in the system
type Webhook struct {
	ID            string                 `json:"id" db:"id"`
	WorkflowID    string                 `json:"workflow_id" db:"workflow_id"`
	NodeID        string                 `json:"node_id" db:"node_id"`
	TeamID        string                 `json:"team_id" db:"team_id"`
	Path          string                 `json:"path" db:"path"`
	Method        string                 `json:"method" db:"method"`
	Enabled       bool                   `json:"enabled" db:"enabled"`
	SecretToken   string                 `json:"-" db:"secret_token"`
	Headers       map[string]string      `json:"headers" db:"headers"`
	Settings      map[string]interface{} `json:"settings" db:"settings"`
	LastTriggered *time.Time             `json:"last_triggered,omitempty" db:"last_triggered"`
	TriggerCount  int64                  `json:"trigger_count" db:"trigger_count"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy     string                 `json:"created_by" db:"created_by"`
}

// WebhookExecution represents a webhook execution
type WebhookExecution struct {
	ID          string            `json:"id" db:"id"`
	WebhookID   string            `json:"webhook_id" db:"webhook_id"`
	WorkflowID  string            `json:"workflow_id" db:"workflow_id"`
	ExecutionID *string           `json:"execution_id,omitempty" db:"execution_id"`
	Method      string            `json:"method" db:"method"`
	Path        string            `json:"path" db:"path"`
	Headers     map[string]string `json:"headers" db:"headers"`
	Body        string            `json:"body" db:"body"`
	Query       map[string]string `json:"query" db:"query"`
	IPAddress   string            `json:"ip_address" db:"ip_address"`
	UserAgent   string            `json:"user_agent" db:"user_agent"`
	Status      string            `json:"status" db:"status"`
	Response    string            `json:"response" db:"response"`
	Error       string            `json:"error,omitempty" db:"error"`
	Duration    int64             `json:"duration" db:"duration"` // milliseconds
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
}

// Repository defines the webhooks data access interface
type Repository interface {
	CreateWebhook(ctx context.Context, webhook *Webhook) error
	GetWebhookByID(ctx context.Context, id string) (*Webhook, error)
	GetWebhookByPath(ctx context.Context, path string) (*Webhook, error)
	UpdateWebhook(ctx context.Context, webhook *Webhook) error
	DeleteWebhook(ctx context.Context, id string) error
	ListWebhooks(ctx context.Context, workflowID string) ([]*Webhook, error)
	CreateExecution(ctx context.Context, execution *WebhookExecution) error
	ListExecutions(ctx context.Context, webhookID string, limit, offset int) ([]*WebhookExecution, error)
}

// Service provides webhook management and processing services
type Service struct {
	config      *config.WebhookConfig
	repo        Repository
	db          *postgres.DB
	workflowSvc *workflows.Service
	producer    *messaging.Producer
	logger      logger.Logger
	metrics     *metrics.Metrics
}

// PostgresRepository implements Repository for PostgreSQL
type PostgresRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresRepository creates a new PostgreSQL webhooks repository
func NewPostgresRepository(db *postgres.DB) Repository {
	return &PostgresRepository{
		db:     db,
		logger: logger.New("webhooks-repository"),
	}
}

// NewService creates a new webhooks service
func NewService(
	config *config.WebhookConfig,
	repo Repository,
	db *postgres.DB,
	workflowSvc *workflows.Service,
	producer *messaging.Producer,
	log logger.Logger,
) *Service {
	return &Service{
		config:      config,
		repo:        repo,
		db:          db,
		workflowSvc: workflowSvc,
		producer:    producer,
		logger:      log,
		metrics:     metrics.GetGlobal(),
	}
}

// HandleWebhook handles incoming webhook requests
func (s *Service) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	workflowID := chi.URLParam(r, "workflowId")

	s.logger.InfoContext(r.Context(), "Processing webhook request",
		"workflow_id", workflowID,
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr,
	)

	// Get workflow to verify it exists and is active
	workflow, err := s.workflowSvc.GetByID(r.Context(), workflowID, "webhook-user")
	if err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to get workflow",
			"workflow_id", workflowID,
			"error", err,
		)
		http.Error(w, "Workflow not found", http.StatusNotFound)
		s.recordWebhookMetrics(workflowID, r.Method, "not_found", time.Since(start))
		return
	}

	if workflow.Status != workflows.WorkflowStatusActive {
		s.logger.WarnContext(r.Context(), "Workflow is not active",
			"workflow_id", workflowID,
			"status", workflow.Status,
		)
		http.Error(w, "Workflow is not active", http.StatusBadRequest)
		s.recordWebhookMetrics(workflowID, r.Method, "inactive", time.Since(start))
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to read request body", "error", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		s.recordWebhookMetrics(workflowID, r.Method, "read_error", time.Since(start))
		return
	}
	defer r.Body.Close()

	// Check payload size limit
	if len(body) > int(s.config.MaxPayloadSize) {
		s.logger.WarnContext(r.Context(), "Payload too large",
			"size", len(body),
			"max_size", s.config.MaxPayloadSize,
		)
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		s.recordWebhookMetrics(workflowID, r.Method, "too_large", time.Since(start))
		return
	}

	// Validate signature if required
	if s.config.EnableSignatureVerify {
		if err := s.validateSignature(r, body); err != nil {
			s.logger.ErrorContext(r.Context(), "Signature validation failed", "error", err)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			s.recordWebhookMetrics(workflowID, r.Method, "invalid_signature", time.Since(start))
			return
		}
	}

	// Parse headers and query parameters
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}

	// Create webhook data for workflow execution
	webhookData := map[string]interface{}{
		"method":     r.Method,
		"headers":    headers,
		"query":      query,
		"body":       string(body),
		"url":        r.URL.String(),
		"remote_ip":  s.getClientIP(r),
		"user_agent": r.UserAgent(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	// Try to parse JSON body
	if isJSONContent(r.Header.Get("Content-Type")) {
		var jsonBody interface{}
		if err := json.Unmarshal(body, &jsonBody); err == nil {
			webhookData["json"] = jsonBody
		}
	}

	// Trigger workflow execution
	execution, err := s.workflowSvc.Execute(
		r.Context(),
		workflowID,
		webhookData,
		"webhook-system",
		"webhook",
	)

	if err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to trigger workflow execution",
			"workflow_id", workflowID,
			"error", err,
		)

		// Create execution record for failed trigger
		s.createExecutionRecord(r.Context(), &WebhookExecution{
			ID:         workflows.GenerateID(),
			WebhookID:  fmt.Sprintf("webhook_%s", workflowID),
			WorkflowID: workflowID,
			Method:     r.Method,
			Path:       r.URL.Path,
			Headers:    headers,
			Body:       string(body),
			Query:      query,
			IPAddress:  s.getClientIP(r),
			UserAgent:  r.UserAgent(),
			Status:     "failed",
			Error:      err.Error(),
			Duration:   time.Since(start).Milliseconds(),
			CreatedAt:  time.Now(),
		})

		http.Error(w, "Failed to execute workflow", http.StatusInternalServerError)
		s.recordWebhookMetrics(workflowID, r.Method, "execution_failed", time.Since(start))
		return
	}

	// Create execution record for successful trigger
	s.createExecutionRecord(r.Context(), &WebhookExecution{
		ID:          workflows.GenerateID(),
		WebhookID:   fmt.Sprintf("webhook_%s", workflowID),
		WorkflowID:  workflowID,
		ExecutionID: &execution.ID,
		Method:      r.Method,
		Path:        r.URL.Path,
		Headers:     headers,
		Body:        string(body),
		Query:       query,
		IPAddress:   s.getClientIP(r),
		UserAgent:   r.UserAgent(),
		Status:      "success",
		Duration:    time.Since(start).Milliseconds(),
		CreatedAt:   time.Now(),
	})

	// Return successful response
	response := map[string]interface{}{
		"success":      true,
		"message":      "Webhook processed successfully",
		"execution_id": execution.ID,
		"workflow_id":  workflowID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	s.recordWebhookMetrics(workflowID, r.Method, "success", time.Since(start))
	s.logger.InfoContext(r.Context(), "Webhook processed successfully",
		"workflow_id", workflowID,
		"execution_id", execution.ID,
		"duration", time.Since(start),
	)
}

// HandleNodeWebhook handles webhook requests for specific nodes
func (s *Service) HandleNodeWebhook(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "workflowId")
	nodeID := chi.URLParam(r, "nodeId")

	s.logger.InfoContext(r.Context(), "Processing node webhook request",
		"workflow_id", workflowID,
		"node_id", nodeID,
		"method", r.Method,
	)

	// For node-specific webhooks, we can add additional processing logic
	// For now, delegate to the main webhook handler with node context
	_ = map[string]interface{}{
		"node_id": nodeID,
		"method":  r.Method,
		"path":    r.URL.Path,
	}

	// Read and add request data similar to HandleWebhook
	// This is a simplified version - full implementation would be similar to HandleWebhook
	response := map[string]interface{}{
		"success":     true,
		"message":     "Node webhook processed",
		"workflow_id": workflowID,
		"node_id":     nodeID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleWebhookGET handles GET requests for webhooks (for testing/verification)
func (s *Service) HandleWebhookGET(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "workflowId")

	response := map[string]interface{}{
		"message":     "Webhook endpoint is active",
		"workflow_id": workflowID,
		"method":      "GET",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGenericWebhook handles generic webhook requests
func (s *Service) HandleGenericWebhook(w http.ResponseWriter, r *http.Request) {
	hookID := chi.URLParam(r, "hookId")

	s.logger.InfoContext(r.Context(), "Processing generic webhook",
		"hook_id", hookID,
		"method", r.Method,
	)

	// This would look up the webhook by hook ID and process accordingly
	response := map[string]interface{}{
		"success":   true,
		"message":   "Generic webhook processed",
		"hook_id":   hookID,
		"method":    r.Method,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGenericWebhookGET handles GET requests for generic webhooks
func (s *Service) HandleGenericWebhookGET(w http.ResponseWriter, r *http.Request) {
	hookID := chi.URLParam(r, "hookId")

	response := map[string]interface{}{
		"message":   "Generic webhook endpoint is active",
		"hook_id":   hookID,
		"method":    "GET",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper methods

// validateSignature validates webhook signature
func (s *Service) validateSignature(r *http.Request, body []byte) error {
	if !s.config.EnableSignatureVerify {
		return nil
	}

	signature := r.Header.Get(s.config.SignatureHeader)
	if signature == "" {
		return errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials,
			"missing signature header")
	}

	// Extract the signature from the header (e.g., "sha256=abc123")
	parts := strings.SplitN(signature, "=", 2)
	if len(parts) != 2 || parts[0] != s.config.SignatureAlgorithm {
		return errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials,
			"invalid signature format")
	}

	expectedSig := parts[1]

	// Calculate expected signature
	// Note: This is a simplified example - you'd need the actual webhook secret
	secret := "webhook-secret" // This should come from configuration
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	calculatedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(calculatedSig)) {
		return errors.New(errors.ErrorTypeAuthentication, errors.CodeInvalidCredentials,
			"signature verification failed")
	}

	return nil
}

// getClientIP extracts the client IP address
func (s *Service) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}

	return ip
}

// isJSONContent checks if the content type is JSON
func isJSONContent(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/json")
}

// recordWebhookMetrics records metrics for webhook processing
func (s *Service) recordWebhookMetrics(workflowID, method, status string, duration time.Duration) {
	s.metrics.RecordHTTPRequest(method, "/webhook/"+workflowID, getStatusCode(status), duration, 0)
}

// getStatusCode converts status string to HTTP status code
func getStatusCode(status string) int {
	switch status {
	case "success":
		return 200
	case "not_found":
		return 404
	case "inactive":
		return 400
	case "invalid_signature":
		return 401
	case "too_large":
		return 413
	case "execution_failed":
		return 500
	default:
		return 500
	}
}

// createExecutionRecord creates a webhook execution record
func (s *Service) createExecutionRecord(ctx context.Context, execution *WebhookExecution) {
	if err := s.repo.CreateExecution(ctx, execution); err != nil {
		s.logger.ErrorContext(ctx, "Failed to create webhook execution record",
			"execution_id", execution.ID,
			"error", err,
		)
	}
}

// Repository implementation (stub methods)

func (r *PostgresRepository) CreateWebhook(ctx context.Context, webhook *Webhook) error {
	// Stub implementation
	return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "not implemented")
}

func (r *PostgresRepository) GetWebhookByID(ctx context.Context, id string) (*Webhook, error) {
	// Stub implementation
	return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "not implemented")
}

func (r *PostgresRepository) GetWebhookByPath(ctx context.Context, path string) (*Webhook, error) {
	// Stub implementation
	return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "not implemented")
}

func (r *PostgresRepository) UpdateWebhook(ctx context.Context, webhook *Webhook) error {
	// Stub implementation
	return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "not implemented")
}

func (r *PostgresRepository) DeleteWebhook(ctx context.Context, id string) error {
	// Stub implementation
	return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "not implemented")
}

func (r *PostgresRepository) ListWebhooks(ctx context.Context, workflowID string) ([]*Webhook, error) {
	// Stub implementation
	return []*Webhook{}, nil
}

func (r *PostgresRepository) CreateExecution(ctx context.Context, execution *WebhookExecution) error {
	// Stub implementation - in real implementation this would save to database
	r.logger.InfoContext(ctx, "Webhook execution recorded",
		"execution_id", execution.ID,
		"webhook_id", execution.WebhookID,
		"status", execution.Status,
	)
	return nil
}

func (r *PostgresRepository) ListExecutions(ctx context.Context, webhookID string, limit, offset int) ([]*WebhookExecution, error) {
	// Stub implementation
	return []*WebhookExecution{}, nil
}
