package billing

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PlanType represents different types of subscription plans
type PlanType string

const (
	PlanTypeFree       PlanType = "free"
	PlanTypeStarter    PlanType = "starter"
	PlanTypePro        PlanType = "pro"
	PlanTypeTeam       PlanType = "team"
	PlanTypeEnterprise PlanType = "enterprise"
)

// BillingPeriod represents billing frequency
type BillingPeriod string

const (
	BillingPeriodMonthly BillingPeriod = "monthly"
	BillingPeriodYearly  BillingPeriod = "yearly"
)

// SubscriptionStatus represents the current state of a subscription
type SubscriptionStatus string

const (
	SubscriptionStatusTrial             SubscriptionStatus = "trial"
	SubscriptionStatusActive            SubscriptionStatus = "active"
	SubscriptionStatusPastDue           SubscriptionStatus = "past_due"
	SubscriptionStatusCanceled          SubscriptionStatus = "canceled"
	SubscriptionStatusUnpaid            SubscriptionStatus = "unpaid"
	SubscriptionStatusIncomplete        SubscriptionStatus = "incomplete"
	SubscriptionStatusIncompleteExpired SubscriptionStatus = "incomplete_expired"
	SubscriptionStatusPaused            SubscriptionStatus = "paused"
)

// PaymentStatus represents payment transaction status
type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusSucceeded PaymentStatus = "succeeded"
	PaymentStatusFailed    PaymentStatus = "failed"
	PaymentStatusCanceled  PaymentStatus = "canceled"
	PaymentStatusRefunded  PaymentStatus = "refunded"
)

// InvoiceStatus represents invoice status
type InvoiceStatus string

const (
	InvoiceStatusDraft         InvoiceStatus = "draft"
	InvoiceStatusOpen          InvoiceStatus = "open"
	InvoiceStatusPaid          InvoiceStatus = "paid"
	InvoiceStatusUncollectible InvoiceStatus = "uncollectible"
	InvoiceStatusVoid          InvoiceStatus = "void"
)

// Plan represents a billing plan
type Plan struct {
	ID          string        `json:"id" db:"id"`
	Name        string        `json:"name" db:"name"`
	Type        PlanType      `json:"type" db:"type"`
	Description string        `json:"description" db:"description"`
	Price       int64         `json:"price" db:"price"` // Price in cents
	Currency    string        `json:"currency" db:"currency"`
	Period      BillingPeriod `json:"period" db:"period"`

	// Feature limits
	MaxWorkflows          int `json:"max_workflows" db:"max_workflows"`
	MaxExecutionsPerMonth int `json:"max_executions_per_month" db:"max_executions_per_month"`
	MaxActiveExecutions   int `json:"max_active_executions" db:"max_active_executions"`
	MaxTeamMembers        int `json:"max_team_members" db:"max_team_members"`
	MaxDataRetentionDays  int `json:"max_data_retention_days" db:"max_data_retention_days"`

	// Feature flags
	HasAdvancedNodes   bool `json:"has_advanced_nodes" db:"has_advanced_nodes"`
	HasCustomDomains   bool `json:"has_custom_domains" db:"has_custom_domains"`
	HasSSO             bool `json:"has_sso" db:"has_sso"`
	HasAPIAccess       bool `json:"has_api_access" db:"has_api_access"`
	HasPrioritySupport bool `json:"has_priority_support" db:"has_priority_support"`
	HasWhiteLabeling   bool `json:"has_white_labeling" db:"has_white_labeling"`

	// Metadata
	IsActive  bool      `json:"is_active" db:"is_active"`
	IsPublic  bool      `json:"is_public" db:"is_public"`
	SortOrder int       `json:"sort_order" db:"sort_order"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Stripe/Payment provider specific
	ProviderID       string            `json:"provider_id" db:"provider_id"`
	ProviderMetadata map[string]string `json:"provider_metadata" db:"provider_metadata"`
}

// Subscription represents a user's subscription to a plan
type Subscription struct {
	ID     string `json:"id" db:"id"`
	UserID string `json:"user_id" db:"user_id"`
	TeamID string `json:"team_id" db:"team_id"`
	PlanID string `json:"plan_id" db:"plan_id"`

	Status             SubscriptionStatus `json:"status" db:"status"`
	CurrentPeriodStart time.Time          `json:"current_period_start" db:"current_period_start"`
	CurrentPeriodEnd   time.Time          `json:"current_period_end" db:"current_period_end"`

	// Trial information
	TrialStart time.Time  `json:"trial_start" db:"trial_start"`
	TrialEnd   *time.Time `json:"trial_end" db:"trial_end"`

	// Cancellation information
	CancelAtPeriodEnd  bool       `json:"cancel_at_period_end" db:"cancel_at_period_end"`
	CanceledAt         *time.Time `json:"canceled_at" db:"canceled_at"`
	CancellationReason string     `json:"cancellation_reason" db:"cancellation_reason"`

	// Payment information
	LastPaymentDate *time.Time `json:"last_payment_date" db:"last_payment_date"`
	NextPaymentDate *time.Time `json:"next_payment_date" db:"next_payment_date"`

	// Usage tracking
	ExecutionsUsedThisMonth int       `json:"executions_used_this_month" db:"executions_used_this_month"`
	LastUsageUpdate         time.Time `json:"last_usage_update" db:"last_usage_update"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Provider specific
	ProviderID         string            `json:"provider_id" db:"provider_id"`
	ProviderCustomerID string            `json:"provider_customer_id" db:"provider_customer_id"`
	ProviderMetadata   map[string]string `json:"provider_metadata" db:"provider_metadata"`

	// Relations
	Plan *Plan `json:"plan,omitempty"`
}

// Customer represents billing customer information
type Customer struct {
	ID     string `json:"id" db:"id"`
	UserID string `json:"user_id" db:"user_id"`
	TeamID string `json:"team_id" db:"team_id"`

	// Contact information
	Email       string `json:"email" db:"email"`
	Name        string `json:"name" db:"name"`
	CompanyName string `json:"company_name" db:"company_name"`

	// Billing address
	AddressLine1 string `json:"address_line1" db:"address_line1"`
	AddressLine2 string `json:"address_line2" db:"address_line2"`
	City         string `json:"city" db:"city"`
	State        string `json:"state" db:"state"`
	PostalCode   string `json:"postal_code" db:"postal_code"`
	Country      string `json:"country" db:"country"`

	// Tax information
	TaxID     string `json:"tax_id" db:"tax_id"`
	TaxExempt bool   `json:"tax_exempt" db:"tax_exempt"`

	// Payment methods
	DefaultPaymentMethodID string `json:"default_payment_method_id" db:"default_payment_method_id"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Provider specific
	ProviderID       string            `json:"provider_id" db:"provider_id"`
	ProviderMetadata map[string]string `json:"provider_metadata" db:"provider_metadata"`
}

// PaymentMethod represents a payment method
type PaymentMethod struct {
	ID         string `json:"id" db:"id"`
	CustomerID string `json:"customer_id" db:"customer_id"`

	Type      string `json:"type" db:"type"` // card, bank_account, etc.
	IsDefault bool   `json:"is_default" db:"is_default"`

	// Card information (if type is card)
	CardBrand    string `json:"card_brand" db:"card_brand"`
	CardLast4    string `json:"card_last4" db:"card_last4"`
	CardExpMonth int    `json:"card_exp_month" db:"card_exp_month"`
	CardExpYear  int    `json:"card_exp_year" db:"card_exp_year"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Provider specific
	ProviderID       string            `json:"provider_id" db:"provider_id"`
	ProviderMetadata map[string]string `json:"provider_metadata" db:"provider_metadata"`
}

// Invoice represents an invoice
type Invoice struct {
	ID             string `json:"id" db:"id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`
	CustomerID     string `json:"customer_id" db:"customer_id"`

	Number   string        `json:"number" db:"number"`
	Status   InvoiceStatus `json:"status" db:"status"`
	Currency string        `json:"currency" db:"currency"`

	// Amounts in cents
	Subtotal   int64 `json:"subtotal" db:"subtotal"`
	TaxAmount  int64 `json:"tax_amount" db:"tax_amount"`
	Total      int64 `json:"total" db:"total"`
	AmountPaid int64 `json:"amount_paid" db:"amount_paid"`
	AmountDue  int64 `json:"amount_due" db:"amount_due"`

	// Dates
	PeriodStart time.Time  `json:"period_start" db:"period_start"`
	PeriodEnd   time.Time  `json:"period_end" db:"period_end"`
	DueDate     time.Time  `json:"due_date" db:"due_date"`
	PaidAt      *time.Time `json:"paid_at" db:"paid_at"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Provider specific
	ProviderID       string            `json:"provider_id" db:"provider_id"`
	ProviderMetadata map[string]string `json:"provider_metadata" db:"provider_metadata"`

	// Relations
	Items []InvoiceItem `json:"items,omitempty"`
}

// InvoiceItem represents a line item on an invoice
type InvoiceItem struct {
	ID        string `json:"id" db:"id"`
	InvoiceID string `json:"invoice_id" db:"invoice_id"`

	Description string `json:"description" db:"description"`
	Quantity    int    `json:"quantity" db:"quantity"`
	UnitAmount  int64  `json:"unit_amount" db:"unit_amount"` // in cents
	Amount      int64  `json:"amount" db:"amount"`           // in cents

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Payment represents a payment transaction
type Payment struct {
	ID             string `json:"id" db:"id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`
	InvoiceID      string `json:"invoice_id" db:"invoice_id"`
	CustomerID     string `json:"customer_id" db:"customer_id"`

	Amount   int64         `json:"amount" db:"amount"` // in cents
	Currency string        `json:"currency" db:"currency"`
	Status   PaymentStatus `json:"status" db:"status"`

	PaymentMethodID string `json:"payment_method_id" db:"payment_method_id"`

	// Failure information
	FailureCode    string `json:"failure_code" db:"failure_code"`
	FailureMessage string `json:"failure_message" db:"failure_message"`

	// Dates
	ProcessedAt *time.Time `json:"processed_at" db:"processed_at"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Provider specific
	ProviderID       string            `json:"provider_id" db:"provider_id"`
	ProviderMetadata map[string]string `json:"provider_metadata" db:"provider_metadata"`
}

// UsageRecord represents usage tracking for metered billing
type UsageRecord struct {
	ID             string `json:"id" db:"id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`

	MetricName string    `json:"metric_name" db:"metric_name"` // executions, storage, etc.
	Quantity   int64     `json:"quantity" db:"quantity"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`

	// Aggregation period
	PeriodStart time.Time `json:"period_start" db:"period_start"`
	PeriodEnd   time.Time `json:"period_end" db:"period_end"`

	// Metadata
	Metadata  map[string]string `json:"metadata" db:"metadata"`
	CreatedAt time.Time         `json:"created_at" db:"created_at"`
}

// BillingEvent represents billing-related events for auditing
type BillingEvent struct {
	ID   string `json:"id" db:"id"`
	Type string `json:"type" db:"type"` // subscription_created, payment_failed, etc.

	UserID         string `json:"user_id" db:"user_id"`
	TeamID         string `json:"team_id" db:"team_id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`

	Data      map[string]interface{} `json:"data" db:"data"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
}

// SubscriptionChange represents a pending subscription change
type SubscriptionChange struct {
	ID             string `json:"id" db:"id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`

	FromPlanID string `json:"from_plan_id" db:"from_plan_id"`
	ToPlanID   string `json:"to_plan_id" db:"to_plan_id"`

	ChangeType    string    `json:"change_type" db:"change_type"` // upgrade, downgrade, cancel
	EffectiveDate time.Time `json:"effective_date" db:"effective_date"`

	// Prorations
	ProrationAmount int64  `json:"proration_amount" db:"proration_amount"`
	Currency        string `json:"currency" db:"currency"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Coupon represents discount coupons
type Coupon struct {
	ID   string `json:"id" db:"id"`
	Code string `json:"code" db:"code"`
	Name string `json:"name" db:"name"`

	// Discount configuration
	PercentOff int64  `json:"percent_off" db:"percent_off"` // 0-100
	AmountOff  int64  `json:"amount_off" db:"amount_off"`   // in cents
	Currency   string `json:"currency" db:"currency"`

	// Usage limits
	MaxRedemptions int `json:"max_redemptions" db:"max_redemptions"`
	TimesRedeemed  int `json:"times_redeemed" db:"times_redeemed"`

	// Duration
	DurationInMonths int        `json:"duration_in_months" db:"duration_in_months"`
	RedeemBy         *time.Time `json:"redeem_by" db:"redeem_by"`

	// Status
	IsActive bool `json:"is_active" db:"is_active"`

	// Metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SubscriptionCoupon represents applied coupons to subscriptions
type SubscriptionCoupon struct {
	ID             string `json:"id" db:"id"`
	SubscriptionID string `json:"subscription_id" db:"subscription_id"`
	CouponID       string `json:"coupon_id" db:"coupon_id"`

	StartDate time.Time  `json:"start_date" db:"start_date"`
	EndDate   *time.Time `json:"end_date" db:"end_date"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Helper methods

// IsActive checks if subscription is in active state
func (s *Subscription) IsActive() bool {
	return s.Status == SubscriptionStatusActive || s.Status == SubscriptionStatusTrial
}

// IsInTrial checks if subscription is in trial period
func (s *Subscription) IsInTrial() bool {
	if s.TrialEnd == nil {
		return false
	}
	return time.Now().Before(*s.TrialEnd)
}

// DaysUntilRenewal returns days until next renewal
func (s *Subscription) DaysUntilRenewal() int {
	return int(time.Until(s.CurrentPeriodEnd).Hours() / 24)
}

// IsOverdue checks if subscription payment is overdue
func (s *Subscription) IsOverdue() bool {
	return s.Status == SubscriptionStatusPastDue
}

// GetMonthlyPrice returns the monthly equivalent price for any billing period
func (p *Plan) GetMonthlyPrice() int64 {
	switch p.Period {
	case BillingPeriodYearly:
		return p.Price / 12
	default:
		return p.Price
	}
}

// GetYearlyPrice returns the yearly equivalent price for any billing period
func (p *Plan) GetYearlyPrice() int64 {
	switch p.Period {
	case BillingPeriodMonthly:
		return p.Price * 12
	default:
		return p.Price
	}
}

// IsExceedingLimits checks if current usage exceeds plan limits
func (s *Subscription) IsExceedingLimits() bool {
	if s.Plan == nil {
		return false
	}

	if s.Plan.MaxExecutionsPerMonth > 0 && s.ExecutionsUsedThisMonth > s.Plan.MaxExecutionsPerMonth {
		return true
	}

	return false
}

// GenerateInvoiceNumber generates a unique invoice number
func GenerateInvoiceNumber() string {
	return fmt.Sprintf("INV-%d-%s", time.Now().Unix(), uuid.New().String()[:8])
}
