package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// NotificationType represents different types of notifications
type NotificationType string

const (
	NotificationTypeWorkflowSuccess   NotificationType = "workflow_success"
	NotificationTypeWorkflowFailure   NotificationType = "workflow_failure"
	NotificationTypeWorkflowTimeout   NotificationType = "workflow_timeout"
	NotificationTypeWorkflowRetry     NotificationType = "workflow_retry"
	NotificationTypeSystemAlert       NotificationType = "system_alert"
	NotificationTypeUserInvite        NotificationType = "user_invite"
	NotificationTypeTeamInvite        NotificationType = "team_invite"
	NotificationTypePasswordReset     NotificationType = "password_reset"
	NotificationTypeEmailVerification NotificationType = "email_verification"
	NotificationTypeQuotaExceeded     NotificationType = "quota_exceeded"
	NotificationTypeBillingAlert      NotificationType = "billing_alert"
	NotificationTypeSecurityAlert     NotificationType = "security_alert"
	NotificationTypeMaintenanceAlert  NotificationType = "maintenance_alert"
	NotificationTypeCustom            NotificationType = "custom"
)

// NotificationChannel represents delivery channels
type NotificationChannel string

const (
	NotificationChannelEmail   NotificationChannel = "email"
	NotificationChannelWebhook NotificationChannel = "webhook"
	NotificationChannelInApp   NotificationChannel = "in_app"
	NotificationChannelSlack   NotificationChannel = "slack"
	NotificationChannelTeams   NotificationChannel = "teams"
	NotificationChannelDiscord NotificationChannel = "discord"
	NotificationChannelSMS     NotificationChannel = "sms"
	NotificationChannelPush    NotificationChannel = "push"
)

// NotificationStatus represents the delivery status
type NotificationStatus string

const (
	NotificationStatusPending   NotificationStatus = "pending"
	NotificationStatusDelivered NotificationStatus = "delivered"
	NotificationStatusFailed    NotificationStatus = "failed"
	NotificationStatusRetrying  NotificationStatus = "retrying"
	NotificationStatusCanceled  NotificationStatus = "canceled"
)

// NotificationPriority represents notification priority levels
type NotificationPriority string

const (
	NotificationPriorityLow      NotificationPriority = "low"
	NotificationPriorityNormal   NotificationPriority = "normal"
	NotificationPriorityHigh     NotificationPriority = "high"
	NotificationPriorityCritical NotificationPriority = "critical"
)

// Notification represents a notification message
type Notification struct {
	ID          string                 `json:"id"`
	Type        NotificationType       `json:"type"`
	Channel     NotificationChannel    `json:"channel"`
	Priority    NotificationPriority   `json:"priority"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Data        map[string]interface{} `json:"data"`
	Recipients  []Recipient            `json:"recipients"`
	Template    string                 `json:"template,omitempty"`
	TemplateVar map[string]interface{} `json:"template_vars,omitempty"`

	// Scheduling
	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`

	// Delivery tracking
	Status      NotificationStatus `json:"status"`
	DeliveredAt *time.Time         `json:"delivered_at,omitempty"`
	FailedAt    *time.Time         `json:"failed_at,omitempty"`
	RetryCount  int                `json:"retry_count"`
	MaxRetries  int                `json:"max_retries"`
	LastError   string             `json:"last_error,omitempty"`

	// Context
	WorkflowID  string            `json:"workflow_id,omitempty"`
	ExecutionID string            `json:"execution_id,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	TeamID      string            `json:"team_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Recipient represents a notification recipient
type Recipient struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"` // user, team, email, webhook
	Address  string                 `json:"address"`
	Name     string                 `json:"name,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// NotificationRequest represents a request to send a notification
type NotificationRequest struct {
	Type        NotificationType       `json:"type"`
	Channel     NotificationChannel    `json:"channel"`
	Priority    NotificationPriority   `json:"priority"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Recipients  []Recipient            `json:"recipients"`
	Template    string                 `json:"template,omitempty"`
	TemplateVar map[string]interface{} `json:"template_vars,omitempty"`

	// Scheduling
	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`

	// Context
	WorkflowID  string            `json:"workflow_id,omitempty"`
	ExecutionID string            `json:"execution_id,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	TeamID      string            `json:"team_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// Delivery options
	MaxRetries int `json:"max_retries,omitempty"`
}

// NotificationFilter represents filters for querying notifications
type NotificationFilter struct {
	Types       []NotificationType    `json:"types,omitempty"`
	Channels    []NotificationChannel `json:"channels,omitempty"`
	Status      NotificationStatus    `json:"status,omitempty"`
	Priority    NotificationPriority  `json:"priority,omitempty"`
	WorkflowID  string                `json:"workflow_id,omitempty"`
	ExecutionID string                `json:"execution_id,omitempty"`
	UserID      string                `json:"user_id,omitempty"`
	TeamID      string                `json:"team_id,omitempty"`
	StartDate   *time.Time            `json:"start_date,omitempty"`
	EndDate     *time.Time            `json:"end_date,omitempty"`
	Limit       int                   `json:"limit,omitempty"`
	Offset      int                   `json:"offset,omitempty"`
}

// Provider defines the interface for notification providers
type Provider interface {
	GetChannel() NotificationChannel
	Send(ctx context.Context, notification *Notification) error
	Validate(recipient Recipient) error
	GetCapabilities() []string
}

// Repository defines the interface for notification storage
type Repository interface {
	Create(ctx context.Context, notification *Notification) error
	GetByID(ctx context.Context, id string) (*Notification, error)
	Update(ctx context.Context, notification *Notification) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *NotificationFilter) ([]*Notification, int, error)
	GetPending(ctx context.Context, limit int) ([]*Notification, error)
	UpdateStatus(ctx context.Context, id string, status NotificationStatus, error string) error
}

// TemplateEngine defines the interface for template processing
type TemplateEngine interface {
	Render(template string, vars map[string]interface{}) (string, error)
	GetTemplate(name string) (string, error)
	RegisterTemplate(name, template string) error
}

// Config holds notification service configuration
type Config struct {
	DefaultChannel    NotificationChannel  `json:"default_channel" yaml:"default_channel"`
	DefaultPriority   NotificationPriority `json:"default_priority" yaml:"default_priority"`
	DefaultMaxRetries int                  `json:"default_max_retries" yaml:"default_max_retries"`
	RetryDelay        time.Duration        `json:"retry_delay" yaml:"retry_delay"`
	BatchSize         int                  `json:"batch_size" yaml:"batch_size"`
	QueueCapacity     int                  `json:"queue_capacity" yaml:"queue_capacity"`
	WorkerCount       int                  `json:"worker_count" yaml:"worker_count"`
	EnableMetrics     bool                 `json:"enable_metrics" yaml:"enable_metrics"`

	// Providers configuration
	Providers map[NotificationChannel]map[string]interface{} `json:"providers" yaml:"providers"`

	// Template settings
	TemplatesPath string `json:"templates_path" yaml:"templates_path"`

	// Rate limiting
	RateLimitPerMinute int `json:"rate_limit_per_minute" yaml:"rate_limit_per_minute"`
}

// DefaultConfig returns default notification service configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultChannel:     NotificationChannelEmail,
		DefaultPriority:    NotificationPriorityNormal,
		DefaultMaxRetries:  3,
		RetryDelay:         5 * time.Minute,
		BatchSize:          100,
		QueueCapacity:      10000,
		WorkerCount:        5,
		EnableMetrics:      true,
		Providers:          make(map[NotificationChannel]map[string]interface{}),
		RateLimitPerMinute: 1000,
	}
}

// Service handles notification operations
type Service struct {
	config     *Config
	repository Repository
	providers  map[NotificationChannel]Provider
	templates  TemplateEngine
	queue      chan *Notification
	logger     logger.Logger

	// Metrics
	metrics struct {
		sent      int64
		failed    int64
		retries   int64
		templated int64
	}

	// Worker control
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	started    bool
	startMutex sync.Mutex
}

// NewService creates a new notification service
func NewService(config *Config, repository Repository, templates TemplateEngine, log logger.Logger) *Service {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		config:     config,
		repository: repository,
		providers:  make(map[NotificationChannel]Provider),
		templates:  templates,
		queue:      make(chan *Notification, config.QueueCapacity),
		logger:     log,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterProvider registers a notification provider
func (s *Service) RegisterProvider(provider Provider) error {
	if provider == nil {
		return errors.NewValidationError("provider cannot be nil")
	}

	channel := provider.GetChannel()
	s.providers[channel] = provider

	s.logger.Info("Notification provider registered", "channel", string(channel))
	return nil
}

// Start starts the notification service workers
func (s *Service) Start() error {
	s.startMutex.Lock()
	defer s.startMutex.Unlock()

	if s.started {
		return errors.NewValidationError("notification service already started")
	}

	// Start worker goroutines
	for i := 0; i < s.config.WorkerCount; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Start scheduler for delayed notifications
	s.wg.Add(1)
	go s.scheduler()

	s.started = true
	s.logger.Info("Notification service started", "workers", s.config.WorkerCount)

	return nil
}

// Stop stops the notification service
func (s *Service) Stop() error {
	s.startMutex.Lock()
	defer s.startMutex.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Info("Stopping notification service...")

	// Cancel context and close queue
	s.cancel()
	close(s.queue)

	// Wait for workers to finish
	s.wg.Wait()

	s.started = false
	s.logger.Info("Notification service stopped")

	return nil
}

// Send sends a notification
func (s *Service) Send(ctx context.Context, req *NotificationRequest) (*Notification, error) {
	if err := s.validateRequest(req); err != nil {
		return nil, err
	}

	// Create notification
	notification := &Notification{
		ID:          uuid.New().String(),
		Type:        req.Type,
		Channel:     req.Channel,
		Priority:    req.Priority,
		Title:       req.Title,
		Message:     req.Message,
		Data:        req.Data,
		Recipients:  req.Recipients,
		Template:    req.Template,
		TemplateVar: req.TemplateVar,
		ScheduledAt: req.ScheduledAt,
		ExpiresAt:   req.ExpiresAt,
		Status:      NotificationStatusPending,
		MaxRetries:  req.MaxRetries,
		WorkflowID:  req.WorkflowID,
		ExecutionID: req.ExecutionID,
		UserID:      req.UserID,
		TeamID:      req.TeamID,
		Metadata:    req.Metadata,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Set defaults
	if notification.Channel == "" {
		notification.Channel = s.config.DefaultChannel
	}
	if notification.Priority == "" {
		notification.Priority = s.config.DefaultPriority
	}
	if notification.MaxRetries == 0 {
		notification.MaxRetries = s.config.DefaultMaxRetries
	}

	// Process template if provided
	if notification.Template != "" && s.templates != nil {
		if err := s.processTemplate(notification); err != nil {
			s.logger.Error("Failed to process template", "error", err, "template", notification.Template)
			// Continue with unprocessed message rather than failing
		}
	}

	// Save to repository
	if s.repository != nil {
		if err := s.repository.Create(ctx, notification); err != nil {
			return nil, fmt.Errorf("failed to save notification: %w", err)
		}
	}

	// Queue for immediate delivery or schedule for later
	if notification.ScheduledAt == nil || notification.ScheduledAt.Before(time.Now()) {
		select {
		case s.queue <- notification:
			s.logger.Debug("Notification queued", "id", notification.ID, "type", string(notification.Type))
		default:
			s.logger.Error("Notification queue full, dropping notification", "id", notification.ID)
			return nil, errors.NewExecutionError("notification queue is full")
		}
	} else {
		s.logger.Info("Notification scheduled", "id", notification.ID, "scheduled_at", notification.ScheduledAt)
	}

	return notification, nil
}

// SendWorkflowNotification sends a workflow-related notification
func (s *Service) SendWorkflowNotification(ctx context.Context, workflowID, executionID, userID string, notType NotificationType, data map[string]interface{}) error {
	title := s.getWorkflowNotificationTitle(notType, data)
	message := s.getWorkflowNotificationMessage(notType, data)

	req := &NotificationRequest{
		Type:        notType,
		Title:       title,
		Message:     message,
		Data:        data,
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		UserID:      userID,
		Recipients:  []Recipient{{ID: userID, Type: "user"}},
	}

	_, err := s.Send(ctx, req)
	return err
}

// GetNotification retrieves a notification by ID
func (s *Service) GetNotification(ctx context.Context, id string) (*Notification, error) {
	if s.repository == nil {
		return nil, errors.NewValidationError("repository not configured")
	}

	return s.repository.GetByID(ctx, id)
}

// ListNotifications lists notifications with filtering
func (s *Service) ListNotifications(ctx context.Context, filter *NotificationFilter) ([]*Notification, int, error) {
	if s.repository == nil {
		return nil, 0, errors.NewValidationError("repository not configured")
	}

	return s.repository.List(ctx, filter)
}

// worker processes notifications from the queue
func (s *Service) worker(id int) {
	defer s.wg.Done()

	s.logger.Debug("Notification worker started", "worker_id", id)

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("Notification worker stopping", "worker_id", id)
			return
		case notification, ok := <-s.queue:
			if !ok {
				s.logger.Debug("Notification queue closed, worker stopping", "worker_id", id)
				return
			}

			s.processNotification(notification)
		}
	}
}

// scheduler handles scheduled notifications
func (s *Service) scheduler() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.processScheduledNotifications()
		}
	}
}

// processScheduledNotifications processes notifications that are due to be sent
func (s *Service) processScheduledNotifications() {
	if s.repository == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get pending scheduled notifications
	filter := &NotificationFilter{
		Status: NotificationStatusPending,
		Limit:  s.config.BatchSize,
	}

	notifications, _, err := s.repository.List(ctx, filter)
	if err != nil {
		s.logger.Error("Failed to get scheduled notifications", "error", err)
		return
	}

	now := time.Now()
	for _, notification := range notifications {
		// Check if it's time to send
		if notification.ScheduledAt != nil && notification.ScheduledAt.After(now) {
			continue
		}

		// Check if expired
		if notification.ExpiresAt != nil && notification.ExpiresAt.Before(now) {
			s.updateNotificationStatus(notification.ID, NotificationStatusCanceled, "notification expired")
			continue
		}

		// Queue for delivery
		select {
		case s.queue <- notification:
		default:
			s.logger.Warn("Queue full, skipping scheduled notification", "id", notification.ID)
		}
	}
}

// processNotification processes a single notification
func (s *Service) processNotification(notification *Notification) {
	provider, exists := s.providers[notification.Channel]
	if !exists {
		s.logger.Error("No provider for channel", "channel", string(notification.Channel), "id", notification.ID)
		s.updateNotificationStatus(notification.ID, NotificationStatusFailed, fmt.Sprintf("no provider for channel: %s", notification.Channel))
		return
	}

	s.logger.Debug("Processing notification", "id", notification.ID, "channel", string(notification.Channel))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := provider.Send(ctx, notification)
	if err != nil {
		s.logger.Error("Failed to send notification", "error", err, "id", notification.ID)
		s.handleNotificationError(notification, err)
		return
	}

	// Mark as delivered
	s.updateNotificationStatus(notification.ID, NotificationStatusDelivered, "")
	s.metrics.sent++

	s.logger.Info("Notification sent successfully", "id", notification.ID, "channel", string(notification.Channel))
}

// handleNotificationError handles notification delivery errors
func (s *Service) handleNotificationError(notification *Notification, err error) {
	notification.RetryCount++
	notification.LastError = err.Error()
	notification.FailedAt = func() *time.Time { t := time.Now(); return &t }()

	if notification.RetryCount >= notification.MaxRetries {
		s.updateNotificationStatus(notification.ID, NotificationStatusFailed, err.Error())
		s.metrics.failed++
		s.logger.Error("Notification failed after max retries", "id", notification.ID, "retries", notification.RetryCount)
		return
	}

	// Schedule retry
	s.updateNotificationStatus(notification.ID, NotificationStatusRetrying, err.Error())
	s.metrics.retries++

	// Retry with exponential backoff
	retryDelay := s.config.RetryDelay * time.Duration(notification.RetryCount)
	notification.ScheduledAt = func() *time.Time { t := time.Now().Add(retryDelay); return &t }()

	if s.repository != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.repository.Update(ctx, notification)
	}

	s.logger.Warn("Notification scheduled for retry", "id", notification.ID, "retry_count", notification.RetryCount, "retry_in", retryDelay)
}

// processTemplate processes notification template
func (s *Service) processTemplate(notification *Notification) error {
	if s.templates == nil {
		return errors.NewValidationError("template engine not configured")
	}

	// Process title template
	if notification.Template != "" {
		template, err := s.templates.GetTemplate(notification.Template + "_title")
		if err == nil {
			title, err := s.templates.Render(template, notification.TemplateVar)
			if err == nil {
				notification.Title = title
			}
		}

		// Process message template
		template, err = s.templates.GetTemplate(notification.Template + "_message")
		if err == nil {
			message, err := s.templates.Render(template, notification.TemplateVar)
			if err == nil {
				notification.Message = message
			}
		}
	}

	s.metrics.templated++
	return nil
}

// updateNotificationStatus updates notification status in repository
func (s *Service) updateNotificationStatus(id string, status NotificationStatus, errorMsg string) {
	if s.repository == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.repository.UpdateStatus(ctx, id, status, errorMsg); err != nil {
		s.logger.Error("Failed to update notification status", "error", err, "id", id)
	}
}

// validateRequest validates a notification request
func (s *Service) validateRequest(req *NotificationRequest) error {
	if req.Type == "" {
		return errors.NewValidationError("notification type is required")
	}

	if len(req.Recipients) == 0 {
		return errors.NewValidationError("at least one recipient is required")
	}

	if req.Title == "" && req.Message == "" && req.Template == "" {
		return errors.NewValidationError("title, message, or template is required")
	}

	// Validate recipients
	for _, recipient := range req.Recipients {
		if recipient.ID == "" && recipient.Address == "" {
			return errors.NewValidationError("recipient must have ID or address")
		}
	}

	return nil
}

// getWorkflowNotificationTitle generates title for workflow notifications
func (s *Service) getWorkflowNotificationTitle(notType NotificationType, data map[string]interface{}) string {
	workflowName := "Workflow"
	if name, ok := data["workflow_name"].(string); ok {
		workflowName = name
	}

	switch notType {
	case NotificationTypeWorkflowSuccess:
		return fmt.Sprintf("✅ %s completed successfully", workflowName)
	case NotificationTypeWorkflowFailure:
		return fmt.Sprintf("❌ %s failed", workflowName)
	case NotificationTypeWorkflowTimeout:
		return fmt.Sprintf("⏰ %s timed out", workflowName)
	case NotificationTypeWorkflowRetry:
		return fmt.Sprintf("🔄 %s is retrying", workflowName)
	default:
		return fmt.Sprintf("📢 %s notification", workflowName)
	}
}

// getWorkflowNotificationMessage generates message for workflow notifications
func (s *Service) getWorkflowNotificationMessage(notType NotificationType, data map[string]interface{}) string {
	workflowName := "Workflow"
	if name, ok := data["workflow_name"].(string); ok {
		workflowName = name
	}

	switch notType {
	case NotificationTypeWorkflowSuccess:
		return fmt.Sprintf("The workflow '%s' has completed successfully.", workflowName)
	case NotificationTypeWorkflowFailure:
		errorMsg := "Unknown error"
		if msg, ok := data["error"].(string); ok {
			errorMsg = msg
		}
		return fmt.Sprintf("The workflow '%s' failed with error: %s", workflowName, errorMsg)
	case NotificationTypeWorkflowTimeout:
		return fmt.Sprintf("The workflow '%s' exceeded its timeout limit.", workflowName)
	case NotificationTypeWorkflowRetry:
		return fmt.Sprintf("The workflow '%s' is being retried after a failure.", workflowName)
	default:
		return fmt.Sprintf("Notification for workflow '%s'.", workflowName)
	}
}

// GetMetrics returns service metrics
func (s *Service) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"notifications_sent":      s.metrics.sent,
		"notifications_failed":    s.metrics.failed,
		"notifications_retries":   s.metrics.retries,
		"notifications_templated": s.metrics.templated,
		"queue_length":            len(s.queue),
		"queue_capacity":          cap(s.queue),
		"providers_registered":    len(s.providers),
		"workers_count":           s.config.WorkerCount,
	}
}
