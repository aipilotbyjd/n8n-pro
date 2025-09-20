package billing

import (
	"context"
	"fmt"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// Service handles billing operations
type Service struct {
	planRepo         PlanRepository
	subscriptionRepo SubscriptionRepository
	customerRepo     CustomerRepository
	paymentRepo      PaymentRepository
	usageRepo        UsageRepository
	paymentProvider  PaymentProvider
	logger           logger.Logger
	config           *ServiceConfig
}

// ServiceConfig holds billing service configuration
type ServiceConfig struct {
	DefaultCurrency         string        `json:"default_currency"`
	TrialPeriodDays         int           `json:"trial_period_days"`
	GracePeriodDays         int           `json:"grace_period_days"`
	EnableUsageTracking     bool          `json:"enable_usage_tracking"`
	BillingCycleDay         int           `json:"billing_cycle_day"`
	ProrationEnabled        bool          `json:"proration_enabled"`
	AutoRetryFailedPayments bool          `json:"auto_retry_failed_payments"`
	MaxRetryAttempts        int           `json:"max_retry_attempts"`
	RetryDelay              time.Duration `json:"retry_delay"`
}

// Repository interfaces
type PlanRepository interface {
	Create(ctx context.Context, plan *Plan) error
	GetByID(ctx context.Context, id string) (*Plan, error)
	List(ctx context.Context, active bool) ([]*Plan, error)
	Update(ctx context.Context, plan *Plan) error
	Delete(ctx context.Context, id string) error
}

type SubscriptionRepository interface {
	Create(ctx context.Context, subscription *Subscription) error
	GetByID(ctx context.Context, id string) (*Subscription, error)
	GetByUserID(ctx context.Context, userID string) (*Subscription, error)
	GetByTeamID(ctx context.Context, teamID string) (*Subscription, error)
	List(ctx context.Context, filter *SubscriptionFilter) ([]*Subscription, error)
	Update(ctx context.Context, subscription *Subscription) error
	Delete(ctx context.Context, id string) error
}

type CustomerRepository interface {
	Create(ctx context.Context, customer *Customer) error
	GetByID(ctx context.Context, id string) (*Customer, error)
	GetByUserID(ctx context.Context, userID string) (*Customer, error)
	Update(ctx context.Context, customer *Customer) error
	Delete(ctx context.Context, id string) error
}

type PaymentRepository interface {
	Create(ctx context.Context, payment *Payment) error
	GetByID(ctx context.Context, id string) (*Payment, error)
	List(ctx context.Context, filter *PaymentFilter) ([]*Payment, error)
	Update(ctx context.Context, payment *Payment) error
}

type UsageRepository interface {
	Create(ctx context.Context, usage *UsageRecord) error
	GetBySubscriptionID(ctx context.Context, subscriptionID string, period time.Time) ([]*UsageRecord, error)
	GetUsageSummary(ctx context.Context, subscriptionID string, start, end time.Time) (map[string]int64, error)
}

// PaymentProvider defines the interface for payment processing
type PaymentProvider interface {
	CreateCustomer(ctx context.Context, customer *Customer) (string, error)
	CreateSubscription(ctx context.Context, customerID, planID string) (string, error)
	CancelSubscription(ctx context.Context, subscriptionID string) error
	ProcessPayment(ctx context.Context, payment *Payment) error
	GetSubscriptionStatus(ctx context.Context, subscriptionID string) (string, error)
	CreateInvoice(ctx context.Context, subscriptionID string) (*Invoice, error)
}

// Filter types
type SubscriptionFilter struct {
	UserID   string
	TeamID   string
	Status   SubscriptionStatus
	PlanType PlanType
	Limit    int
	Offset   int
}

type PaymentFilter struct {
	CustomerID     string
	SubscriptionID string
	Status         PaymentStatus
	StartDate      *time.Time
	EndDate        *time.Time
	Limit          int
	Offset         int
}

// NewService creates a new billing service
func NewService(
	planRepo PlanRepository,
	subscriptionRepo SubscriptionRepository,
	customerRepo CustomerRepository,
	paymentRepo PaymentRepository,
	usageRepo UsageRepository,
	paymentProvider PaymentProvider,
	config *ServiceConfig,
	logger logger.Logger,
) *Service {
	if config == nil {
		config = &ServiceConfig{
			DefaultCurrency:         "usd",
			TrialPeriodDays:         14,
			GracePeriodDays:         3,
			EnableUsageTracking:     true,
			BillingCycleDay:         1,
			ProrationEnabled:        true,
			AutoRetryFailedPayments: true,
			MaxRetryAttempts:        3,
			RetryDelay:              24 * time.Hour,
		}
	}

	return &Service{
		planRepo:         planRepo,
		subscriptionRepo: subscriptionRepo,
		customerRepo:     customerRepo,
		paymentRepo:      paymentRepo,
		usageRepo:        usageRepo,
		paymentProvider:  paymentProvider,
		config:           config,
		logger:           logger,
	}
}

// Plan Management

// CreatePlan creates a new billing plan
func (s *Service) CreatePlan(ctx context.Context, req *CreatePlanRequest) (*Plan, error) {
	plan := &Plan{
		ID:                    uuid.New().String(),
		Name:                  req.Name,
		Type:                  req.Type,
		Description:           req.Description,
		Price:                 req.Price,
		Currency:              req.Currency,
		Period:                req.Period,
		MaxWorkflows:          req.MaxWorkflows,
		MaxExecutionsPerMonth: req.MaxExecutionsPerMonth,
		MaxActiveExecutions:   req.MaxActiveExecutions,
		MaxTeamMembers:        req.MaxTeamMembers,
		MaxDataRetentionDays:  req.MaxDataRetentionDays,
		HasAdvancedNodes:      req.HasAdvancedNodes,
		HasCustomDomains:      req.HasCustomDomains,
		HasSSO:                req.HasSSO,
		HasAPIAccess:          req.HasAPIAccess,
		HasPrioritySupport:    req.HasPrioritySupport,
		HasWhiteLabeling:      req.HasWhiteLabeling,
		IsActive:              true,
		IsPublic:              req.IsPublic,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if plan.Currency == "" {
		plan.Currency = s.config.DefaultCurrency
	}

	if err := s.planRepo.Create(ctx, plan); err != nil {
		return nil, fmt.Errorf("failed to create plan: %w", err)
	}

	s.logger.Info("Plan created", "plan_id", plan.ID, "name", plan.Name, "type", plan.Type)
	return plan, nil
}

// GetPlan retrieves a plan by ID
func (s *Service) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	return s.planRepo.GetByID(ctx, planID)
}

// ListPlans retrieves all active plans
func (s *Service) ListPlans(ctx context.Context, activeOnly bool) ([]*Plan, error) {
	return s.planRepo.List(ctx, activeOnly)
}

// Subscription Management

// CreateSubscription creates a new subscription
func (s *Service) CreateSubscription(ctx context.Context, req *CreateSubscriptionRequest) (*Subscription, error) {
	// Get plan details
	plan, err := s.planRepo.GetByID(ctx, req.PlanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}

	// Create or get customer
	customer, err := s.getOrCreateCustomer(ctx, req.UserID, req.TeamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create customer: %w", err)
	}

	// Create subscription
	now := time.Now()
	subscription := &Subscription{
		ID:                 uuid.New().String(),
		UserID:             req.UserID,
		TeamID:             req.TeamID,
		PlanID:             req.PlanID,
		Status:             SubscriptionStatusTrial,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   now.AddDate(0, 0, s.config.TrialPeriodDays),
		TrialStart:         now,
		CreatedAt:          now,
		UpdatedAt:          now,
		Plan:               plan,
	}

	// Set trial end if trial is enabled
	if s.config.TrialPeriodDays > 0 {
		trialEnd := now.AddDate(0, 0, s.config.TrialPeriodDays)
		subscription.TrialEnd = &trialEnd
	} else {
		subscription.Status = SubscriptionStatusActive
	}

	// Create subscription with payment provider
	if s.paymentProvider != nil {
		providerSubID, err := s.paymentProvider.CreateSubscription(ctx, customer.ProviderID, plan.ProviderID)
		if err != nil {
			return nil, fmt.Errorf("failed to create subscription with payment provider: %w", err)
		}
		subscription.ProviderID = providerSubID
		subscription.ProviderCustomerID = customer.ProviderID
	}

	if err := s.subscriptionRepo.Create(ctx, subscription); err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	s.logger.Info("Subscription created",
		"subscription_id", subscription.ID,
		"user_id", req.UserID,
		"plan_id", req.PlanID,
		"status", subscription.Status)

	return subscription, nil
}

// GetSubscription retrieves a subscription by ID
func (s *Service) GetSubscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	return s.subscriptionRepo.GetByID(ctx, subscriptionID)
}

// GetUserSubscription retrieves the active subscription for a user
func (s *Service) GetUserSubscription(ctx context.Context, userID string) (*Subscription, error) {
	return s.subscriptionRepo.GetByUserID(ctx, userID)
}

// UpdateSubscription updates a subscription plan
func (s *Service) UpdateSubscription(ctx context.Context, subscriptionID, newPlanID string) error {
	subscription, err := s.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	newPlan, err := s.planRepo.GetByID(ctx, newPlanID)
	if err != nil {
		return fmt.Errorf("failed to get new plan: %w", err)
	}

	// Calculate proration if enabled
	var prorationAmount int64
	if s.config.ProrationEnabled {
		prorationAmount = s.calculateProration(subscription, newPlan)
	}

	// Update subscription
	subscription.PlanID = newPlanID
	subscription.Plan = newPlan
	subscription.UpdatedAt = time.Now()

	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	// Log the change
	s.logger.Info("Subscription updated",
		"subscription_id", subscriptionID,
		"old_plan", subscription.PlanID,
		"new_plan", newPlanID,
		"proration_amount", prorationAmount)

	return nil
}

// CancelSubscription cancels a subscription
func (s *Service) CancelSubscription(ctx context.Context, subscriptionID string, cancelAtPeriodEnd bool, reason string) error {
	subscription, err := s.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	subscription.CancelAtPeriodEnd = cancelAtPeriodEnd
	subscription.CancellationReason = reason

	if !cancelAtPeriodEnd {
		now := time.Now()
		subscription.Status = SubscriptionStatusCanceled
		subscription.CanceledAt = &now
	}

	subscription.UpdatedAt = time.Now()

	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	// Cancel with payment provider
	if s.paymentProvider != nil && subscription.ProviderID != "" {
		if err := s.paymentProvider.CancelSubscription(ctx, subscription.ProviderID); err != nil {
			s.logger.Error("Failed to cancel subscription with payment provider",
				"error", err, "subscription_id", subscriptionID)
		}
	}

	s.logger.Info("Subscription canceled",
		"subscription_id", subscriptionID,
		"cancel_at_period_end", cancelAtPeriodEnd,
		"reason", reason)

	return nil
}

// Usage Tracking

// RecordUsage records usage for a subscription
func (s *Service) RecordUsage(ctx context.Context, subscriptionID, metricName string, quantity int64) error {
	if !s.config.EnableUsageTracking {
		return nil
	}

	usage := &UsageRecord{
		ID:             uuid.New().String(),
		SubscriptionID: subscriptionID,
		MetricName:     metricName,
		Quantity:       quantity,
		Timestamp:      time.Now(),
		PeriodStart:    s.getPeriodStart(time.Now()),
		PeriodEnd:      s.getPeriodEnd(time.Now()),
	}

	if err := s.usageRepo.Create(ctx, usage); err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	return nil
}

// GetUsage retrieves usage for a subscription
func (s *Service) GetUsage(ctx context.Context, subscriptionID string, start, end time.Time) (map[string]int64, error) {
	return s.usageRepo.GetUsageSummary(ctx, subscriptionID, start, end)
}

// CheckUsageLimits checks if a subscription is exceeding its limits
func (s *Service) CheckUsageLimits(ctx context.Context, subscriptionID string) (bool, error) {
	subscription, err := s.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return false, fmt.Errorf("failed to get subscription: %w", err)
	}

	if subscription.Plan == nil {
		return false, fmt.Errorf("subscription plan not loaded")
	}

	// Check execution limits
	if subscription.Plan.MaxExecutionsPerMonth > 0 {
		if subscription.ExecutionsUsedThisMonth >= subscription.Plan.MaxExecutionsPerMonth {
			return false, nil
		}
	}

	return true, nil
}

// Payment Processing

// ProcessPayment processes a payment
func (s *Service) ProcessPayment(ctx context.Context, payment *Payment) error {
	if s.paymentProvider == nil {
		return errors.NewValidationError("payment provider not configured")
	}

	payment.ID = uuid.New().String()
	payment.CreatedAt = time.Now()
	payment.UpdatedAt = time.Now()

	if err := s.paymentProvider.ProcessPayment(ctx, payment); err != nil {
		payment.Status = PaymentStatusFailed
		payment.FailureMessage = err.Error()
		s.paymentRepo.Create(ctx, payment)
		return fmt.Errorf("payment processing failed: %w", err)
	}

	payment.Status = PaymentStatusSucceeded
	now := time.Now()
	payment.ProcessedAt = &now

	if err := s.paymentRepo.Create(ctx, payment); err != nil {
		return fmt.Errorf("failed to save payment: %w", err)
	}

	s.logger.Info("Payment processed successfully",
		"payment_id", payment.ID,
		"amount", payment.Amount,
		"currency", payment.Currency)

	return nil
}

// Helper methods

func (s *Service) getOrCreateCustomer(ctx context.Context, userID, teamID string) (*Customer, error) {
	customer, err := s.customerRepo.GetByUserID(ctx, userID)
	if err == nil {
		return customer, nil
	}

	// Create new customer
	customer = &Customer{
		ID:        uuid.New().String(),
		UserID:    userID,
		TeamID:    teamID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create customer with payment provider
	if s.paymentProvider != nil {
		providerID, err := s.paymentProvider.CreateCustomer(ctx, customer)
		if err != nil {
			return nil, fmt.Errorf("failed to create customer with payment provider: %w", err)
		}
		customer.ProviderID = providerID
	}

	if err := s.customerRepo.Create(ctx, customer); err != nil {
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}

	return customer, nil
}

func (s *Service) calculateProration(subscription *Subscription, newPlan *Plan) int64 {
	// Simple proration calculation
	// In a real implementation, this would be more sophisticated
	if subscription.Plan == nil {
		return 0
	}

	priceDiff := newPlan.Price - subscription.Plan.Price
	remainingDays := int64(time.Until(subscription.CurrentPeriodEnd).Hours() / 24)
	totalDays := int64(subscription.CurrentPeriodEnd.Sub(subscription.CurrentPeriodStart).Hours() / 24)

	if totalDays == 0 {
		return 0
	}

	return (priceDiff * remainingDays) / totalDays
}

func (s *Service) getPeriodStart(t time.Time) time.Time {
	year, month, _ := t.Date()
	return time.Date(year, month, s.config.BillingCycleDay, 0, 0, 0, 0, t.Location())
}

func (s *Service) getPeriodEnd(t time.Time) time.Time {
	start := s.getPeriodStart(t)
	return start.AddDate(0, 1, 0).Add(-time.Second)
}

// Request/Response types

type CreatePlanRequest struct {
	Name        string        `json:"name"`
	Type        PlanType      `json:"type"`
	Description string        `json:"description"`
	Price       int64         `json:"price"`
	Currency    string        `json:"currency"`
	Period      BillingPeriod `json:"period"`

	MaxWorkflows          int  `json:"max_workflows"`
	MaxExecutionsPerMonth int  `json:"max_executions_per_month"`
	MaxActiveExecutions   int  `json:"max_active_executions"`
	MaxTeamMembers        int  `json:"max_team_members"`
	MaxDataRetentionDays  int  `json:"max_data_retention_days"`
	HasAdvancedNodes      bool `json:"has_advanced_nodes"`
	HasCustomDomains      bool `json:"has_custom_domains"`
	HasSSO                bool `json:"has_sso"`
	HasAPIAccess          bool `json:"has_api_access"`
	HasPrioritySupport    bool `json:"has_priority_support"`
	HasWhiteLabeling      bool `json:"has_white_labeling"`
	IsPublic              bool `json:"is_public"`
}

type CreateSubscriptionRequest struct {
	UserID string `json:"user_id"`
	TeamID string `json:"team_id"`
	PlanID string `json:"plan_id"`
}
