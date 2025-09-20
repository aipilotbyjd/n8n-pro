package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// WebhookEventType represents different types of webhook events
type WebhookEventType string

const (
	WebhookEventSubscriptionCreated  WebhookEventType = "subscription.created"
	WebhookEventSubscriptionUpdated  WebhookEventType = "subscription.updated"
	WebhookEventSubscriptionCanceled WebhookEventType = "subscription.canceled"
	WebhookEventPaymentSucceeded     WebhookEventType = "payment.succeeded"
	WebhookEventPaymentFailed        WebhookEventType = "payment.failed"
	WebhookEventInvoiceCreated       WebhookEventType = "invoice.created"
	WebhookEventInvoicePaid          WebhookEventType = "invoice.paid"
	WebhookEventCustomerCreated      WebhookEventType = "customer.created"
	WebhookEventCustomerUpdated      WebhookEventType = "customer.updated"
)

// WebhookEvent represents a billing webhook event
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      WebhookEventType       `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Provider  string                 `json:"provider"` // stripe, paypal, etc.
	Timestamp time.Time              `json:"timestamp"`
	Processed bool                   `json:"processed"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	ID              string             `json:"id"`
	Provider        string             `json:"provider"`
	URL             string             `json:"url"`
	Secret          string             `json:"secret"`
	Events          []WebhookEventType `json:"events"`
	Active          bool               `json:"active"`
	SignatureHeader string             `json:"signature_header"`
	SignaturePrefix string             `json:"signature_prefix"`
	MaxRetries      int                `json:"max_retries"`
	RetryDelay      time.Duration      `json:"retry_delay"`
	Metadata        map[string]string  `json:"metadata"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// WebhookHandler handles billing webhook events
type WebhookHandler struct {
	service    *Service
	logger     logger.Logger
	configs    map[string]*WebhookConfig
	processors map[WebhookEventType]EventProcessor
}

// EventProcessor defines the interface for processing webhook events
type EventProcessor interface {
	Process(ctx context.Context, event *WebhookEvent) error
	GetEventType() WebhookEventType
}

// WebhookRequest represents an incoming webhook request
type WebhookRequest struct {
	Provider  string            `json:"provider"`
	Headers   map[string]string `json:"headers"`
	Body      []byte            `json:"body"`
	Signature string            `json:"signature"`
	Timestamp time.Time         `json:"timestamp"`
	RequestID string            `json:"request_id"`
	IPAddress string            `json:"ip_address"`
	UserAgent string            `json:"user_agent"`
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(service *Service, logger logger.Logger) *WebhookHandler {
	handler := &WebhookHandler{
		service:    service,
		logger:     logger,
		configs:    make(map[string]*WebhookConfig),
		processors: make(map[WebhookEventType]EventProcessor),
	}

	// Register default event processors
	handler.registerDefaultProcessors()

	return handler
}

// RegisterConfig registers a webhook configuration
func (h *WebhookHandler) RegisterConfig(config *WebhookConfig) error {
	if config.ID == "" {
		config.ID = uuid.New().String()
	}

	if config.Provider == "" {
		return errors.NewValidationError("provider is required")
	}

	if config.Secret == "" {
		return errors.NewValidationError("webhook secret is required")
	}

	h.configs[config.Provider] = config
	h.logger.Info("Webhook config registered", "provider", config.Provider, "url", config.URL)

	return nil
}

// RegisterProcessor registers an event processor
func (h *WebhookHandler) RegisterProcessor(processor EventProcessor) {
	h.processors[processor.GetEventType()] = processor
	h.logger.Info("Event processor registered", "event_type", string(processor.GetEventType()))
}

// HandleWebhook handles an incoming webhook request
func (h *WebhookHandler) HandleWebhook(ctx context.Context, req *WebhookRequest) error {
	h.logger.Info("Processing webhook",
		"provider", req.Provider,
		"request_id", req.RequestID,
		"ip", req.IPAddress)

	// Get webhook config
	config, exists := h.configs[req.Provider]
	if !exists {
		return errors.NewValidationError(fmt.Sprintf("no webhook config for provider: %s", req.Provider))
	}

	// Verify signature
	if err := h.verifySignature(req, config); err != nil {
		h.logger.Error("Webhook signature verification failed",
			"error", err,
			"provider", req.Provider)
		return errors.NewUnauthorizedError("invalid webhook signature")
	}

	// Parse webhook event
	event, err := h.parseWebhookEvent(req, config)
	if err != nil {
		return fmt.Errorf("failed to parse webhook event: %w", err)
	}

	// Process event
	if err := h.processEvent(ctx, event); err != nil {
		h.logger.Error("Failed to process webhook event",
			"error", err,
			"event_type", event.Type,
			"event_id", event.ID)
		return fmt.Errorf("failed to process event: %w", err)
	}

	h.logger.Info("Webhook processed successfully",
		"event_type", event.Type,
		"event_id", event.ID,
		"provider", req.Provider)

	return nil
}

// verifySignature verifies the webhook signature
func (h *WebhookHandler) verifySignature(req *WebhookRequest, config *WebhookConfig) error {
	if config.Secret == "" {
		return nil // Skip verification if no secret configured
	}

	expectedSignature := h.computeSignature(req.Body, config.Secret, config.SignaturePrefix)

	// Get signature from headers or request
	var receivedSignature string
	if config.SignatureHeader != "" {
		receivedSignature = req.Headers[config.SignatureHeader]
	} else {
		receivedSignature = req.Signature
	}

	if receivedSignature == "" {
		return errors.NewValidationError("webhook signature is missing")
	}

	// Compare signatures
	if !hmac.Equal([]byte(expectedSignature), []byte(receivedSignature)) {
		return errors.NewValidationError("webhook signature mismatch")
	}

	return nil
}

// computeSignature computes HMAC signature for webhook verification
func (h *WebhookHandler) computeSignature(payload []byte, secret, prefix string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	if prefix != "" {
		return prefix + signature
	}
	return signature
}

// parseWebhookEvent parses the webhook request into an event
func (h *WebhookHandler) parseWebhookEvent(req *WebhookRequest, config *WebhookConfig) (*WebhookEvent, error) {
	var eventData map[string]interface{}
	if err := json.Unmarshal(req.Body, &eventData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal webhook body: %w", err)
	}

	event := &WebhookEvent{
		ID:        uuid.New().String(),
		Provider:  req.Provider,
		Data:      eventData,
		Timestamp: req.Timestamp,
		Processed: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Extract event type based on provider
	switch req.Provider {
	case "stripe":
		if eventType, ok := eventData["type"].(string); ok {
			event.Type = WebhookEventType(eventType)
		}
		if id, ok := eventData["id"].(string); ok {
			event.ID = id
		}
	case "paypal":
		if eventType, ok := eventData["event_type"].(string); ok {
			event.Type = h.mapPayPalEventType(eventType)
		}
	default:
		return nil, fmt.Errorf("unsupported webhook provider: %s", req.Provider)
	}

	if event.Type == "" {
		return nil, errors.NewValidationError("unable to determine event type")
	}

	return event, nil
}

// processEvent processes a webhook event
func (h *WebhookHandler) processEvent(ctx context.Context, event *WebhookEvent) error {
	processor, exists := h.processors[event.Type]
	if !exists {
		h.logger.Warn("No processor for event type", "event_type", string(event.Type))
		return nil // Don't error on unhandled events
	}

	if err := processor.Process(ctx, event); err != nil {
		return fmt.Errorf("event processor failed: %w", err)
	}

	event.Processed = true
	event.UpdatedAt = time.Now()

	return nil
}

// mapPayPalEventType maps PayPal event types to internal event types
func (h *WebhookHandler) mapPayPalEventType(paypalType string) WebhookEventType {
	mapping := map[string]WebhookEventType{
		"BILLING.SUBSCRIPTION.CREATED":   WebhookEventSubscriptionCreated,
		"BILLING.SUBSCRIPTION.UPDATED":   WebhookEventSubscriptionUpdated,
		"BILLING.SUBSCRIPTION.CANCELLED": WebhookEventSubscriptionCanceled,
		"PAYMENT.SALE.COMPLETED":         WebhookEventPaymentSucceeded,
		"PAYMENT.SALE.DENIED":            WebhookEventPaymentFailed,
	}

	if mapped, exists := mapping[paypalType]; exists {
		return mapped
	}

	return WebhookEventType(strings.ToLower(paypalType))
}

// registerDefaultProcessors registers default event processors
func (h *WebhookHandler) registerDefaultProcessors() {
	h.RegisterProcessor(&SubscriptionCreatedProcessor{service: h.service, logger: h.logger})
	h.RegisterProcessor(&SubscriptionUpdatedProcessor{service: h.service, logger: h.logger})
	h.RegisterProcessor(&SubscriptionCanceledProcessor{service: h.service, logger: h.logger})
	h.RegisterProcessor(&PaymentSucceededProcessor{service: h.service, logger: h.logger})
	h.RegisterProcessor(&PaymentFailedProcessor{service: h.service, logger: h.logger})
}

// Default event processors

// SubscriptionCreatedProcessor handles subscription created events
type SubscriptionCreatedProcessor struct {
	service *Service
	logger  logger.Logger
}

func (p *SubscriptionCreatedProcessor) GetEventType() WebhookEventType {
	return WebhookEventSubscriptionCreated
}

func (p *SubscriptionCreatedProcessor) Process(ctx context.Context, event *WebhookEvent) error {
	p.logger.Info("Processing subscription created event", "event_id", event.ID)
	// Implementation would update subscription status in database
	return nil
}

// SubscriptionUpdatedProcessor handles subscription updated events
type SubscriptionUpdatedProcessor struct {
	service *Service
	logger  logger.Logger
}

func (p *SubscriptionUpdatedProcessor) GetEventType() WebhookEventType {
	return WebhookEventSubscriptionUpdated
}

func (p *SubscriptionUpdatedProcessor) Process(ctx context.Context, event *WebhookEvent) error {
	p.logger.Info("Processing subscription updated event", "event_id", event.ID)
	// Implementation would update subscription details
	return nil
}

// SubscriptionCanceledProcessor handles subscription canceled events
type SubscriptionCanceledProcessor struct {
	service *Service
	logger  logger.Logger
}

func (p *SubscriptionCanceledProcessor) GetEventType() WebhookEventType {
	return WebhookEventSubscriptionCanceled
}

func (p *SubscriptionCanceledProcessor) Process(ctx context.Context, event *WebhookEvent) error {
	p.logger.Info("Processing subscription canceled event", "event_id", event.ID)
	// Implementation would cancel subscription
	return nil
}

// PaymentSucceededProcessor handles payment succeeded events
type PaymentSucceededProcessor struct {
	service *Service
	logger  logger.Logger
}

func (p *PaymentSucceededProcessor) GetEventType() WebhookEventType {
	return WebhookEventPaymentSucceeded
}

func (p *PaymentSucceededProcessor) Process(ctx context.Context, event *WebhookEvent) error {
	p.logger.Info("Processing payment succeeded event", "event_id", event.ID)
	// Implementation would update payment status and subscription
	return nil
}

// PaymentFailedProcessor handles payment failed events
type PaymentFailedProcessor struct {
	service *Service
	logger  logger.Logger
}

func (p *PaymentFailedProcessor) GetEventType() WebhookEventType {
	return WebhookEventPaymentFailed
}

func (p *PaymentFailedProcessor) Process(ctx context.Context, event *WebhookEvent) error {
	p.logger.Info("Processing payment failed event", "event_id", event.ID)
	// Implementation would handle payment failure, retry logic, etc.
	return nil
}

// HTTP handler for webhook endpoints
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract provider from path or query params
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		// Try to extract from path
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) > 0 {
			provider = parts[len(parts)-1]
		}
	}

	if provider == "" {
		http.Error(w, "Provider not specified", http.StatusBadRequest)
		return
	}

	// Read request body
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil && err.Error() != "EOF" {
		h.logger.Error("Failed to read webhook body", "error", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Build headers map
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Create webhook request
	webhookReq := &WebhookRequest{
		Provider:  provider,
		Headers:   headers,
		Body:      body,
		Signature: headers["X-Hub-Signature-256"], // Default for GitHub/Stripe style
		Timestamp: time.Now(),
		RequestID: headers["X-Request-ID"],
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	// Process webhook
	if err := h.HandleWebhook(r.Context(), webhookReq); err != nil {
		h.logger.Error("Webhook processing failed", "error", err, "provider", provider)
		http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}
