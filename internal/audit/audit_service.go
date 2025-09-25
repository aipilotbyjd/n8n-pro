package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/errors"
	"n8n-pro/internal/database"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Authentication events
	EventTypeUserLogin            AuditEventType = "user.login"
	EventTypeUserLogout           AuditEventType = "user.logout"
	EventTypeUserLoginFailed      AuditEventType = "user.login_failed"
	EventTypeUserRegistered       AuditEventType = "user.registered"
	EventTypeUserPasswordChanged  AuditEventType = "user.password_changed"
	EventTypeUserEmailChanged     AuditEventType = "user.email_changed"
	EventTypeUserMFAEnabled       AuditEventType = "user.mfa_enabled"
	EventTypeUserMFADisabled      AuditEventType = "user.mfa_disabled"
	EventTypeUserAccountLocked    AuditEventType = "user.account_locked"
	EventTypeUserAccountUnlocked  AuditEventType = "user.account_unlocked"
	EventTypeUserDeleted          AuditEventType = "user.deleted"
	EventTypeUserImpersonated     AuditEventType = "user.impersonated"

	// Enterprise authentication
	EventTypeUserOAuthLogin       AuditEventType = "user.oauth_login"
	EventTypeUserSAMLLogin        AuditEventType = "user.saml_login"
	EventTypeUserLDAPLogin        AuditEventType = "user.ldap_login"
	EventTypeUserSAMLRegistered   AuditEventType = "user.saml_registered"
	EventTypeUserLDAPRegistered   AuditEventType = "user.ldap_registered"

	// Organization events
	EventTypeOrgCreated           AuditEventType = "organization.created"
	EventTypeOrgUpdated           AuditEventType = "organization.updated"
	EventTypeOrgDeleted           AuditEventType = "organization.deleted"
	EventTypeOrgMemberAdded       AuditEventType = "organization.member_added"
	EventTypeOrgMemberRemoved     AuditEventType = "organization.member_removed"
	EventTypeOrgMemberRoleChanged AuditEventType = "organization.member_role_changed"
	EventTypeOrgInviteCreated     AuditEventType = "organization.invite_created"
	EventTypeOrgInviteAccepted    AuditEventType = "organization.invite_accepted"
	EventTypeOrgInviteRevoked     AuditEventType = "organization.invite_revoked"

	// Team events
	EventTypeTeamCreated          AuditEventType = "team.created"
	EventTypeTeamUpdated          AuditEventType = "team.updated"
	EventTypeTeamDeleted          AuditEventType = "team.deleted"
	EventTypeTeamMemberAdded      AuditEventType = "team.member_added"
	EventTypeTeamMemberRemoved    AuditEventType = "team.member_removed"
	EventTypeTeamMemberRoleChanged AuditEventType = "team.member_role_changed"

	// Permission and role events
	EventTypeRoleCreated          AuditEventType = "role.created"
	EventTypeRoleUpdated          AuditEventType = "role.updated"
	EventTypeRoleDeleted          AuditEventType = "role.deleted"
	EventTypePermissionGranted    AuditEventType = "permission.granted"
	EventTypePermissionRevoked    AuditEventType = "permission.revoked"
	EventTypeAccessDenied         AuditEventType = "access.denied"

	// API and security events
	EventTypeAPIKeyCreated        AuditEventType = "api_key.created"
	EventTypeAPIKeyRevoked        AuditEventType = "api_key.revoked"
	EventTypeAPIKeyUsed           AuditEventType = "api_key.used"
	EventTypeSessionCreated       AuditEventType = "session.created"
	EventTypeSessionExpired       AuditEventType = "session.expired"
	EventTypeSecurityPolicyViolation AuditEventType = "security.policy_violation"

	// System events
	EventTypeSystemBackup         AuditEventType = "system.backup"
	EventTypeSystemRestore        AuditEventType = "system.restore"
	EventTypeSystemMaintenance    AuditEventType = "system.maintenance"
	EventTypeSystemConfigChanged  AuditEventType = "system.config_changed"
)

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID             string                 `json:"id" db:"id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	ActorType      string                 `json:"actor_type" db:"actor_type"` // "user", "system", "api"
	ActorID        *string                `json:"actor_id,omitempty" db:"actor_id"`
	EventType      AuditEventType         `json:"event_type" db:"event_type"`
	ResourceType   string                 `json:"resource_type" db:"resource_type"`
	ResourceID     string                 `json:"resource_id" db:"resource_id"`
	Details        map[string]interface{} `json:"details" db:"details"`
	IPAddress      string                 `json:"ip_address" db:"ip_address"`
	UserAgent      string                 `json:"user_agent" db:"user_agent"`
	Success        bool                   `json:"success" db:"success"`
	ErrorMessage   *string                `json:"error_message,omitempty" db:"error_message"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	SessionID      *string                `json:"session_id,omitempty" db:"session_id"`
	RequestID      *string                `json:"request_id,omitempty" db:"request_id"`
	Severity       string                 `json:"severity" db:"severity"` // "low", "medium", "high", "critical"
}

// AuditQuery represents query parameters for filtering audit events
type AuditQuery struct {
	OrganizationID string          `json:"organization_id"`
	EventTypes     []AuditEventType `json:"event_types,omitempty"`
	ActorID        *string          `json:"actor_id,omitempty"`
	ResourceType   *string          `json:"resource_type,omitempty"`
	ResourceID     *string          `json:"resource_id,omitempty"`
	IPAddress      *string          `json:"ip_address,omitempty"`
	Success        *bool            `json:"success,omitempty"`
	Severity       *string          `json:"severity,omitempty"`
	StartDate      *time.Time       `json:"start_date,omitempty"`
	EndDate        *time.Time       `json:"end_date,omitempty"`
	Limit          int              `json:"limit"`
	Offset         int              `json:"offset"`
	SortBy         string           `json:"sort_by"`
	SortOrder      string           `json:"sort_order"` // "asc" or "desc"
}

// AuditRepository defines the interface for audit log persistence
type AuditRepository interface {
	Create(ctx context.Context, event *AuditEvent) error
	GetByID(ctx context.Context, id string) (*AuditEvent, error)
	Query(ctx context.Context, query *AuditQuery) ([]*AuditEvent, int, error)
	DeleteOldEvents(ctx context.Context, olderThan time.Time) (int64, error)
	GetEventsByDateRange(ctx context.Context, organizationID string, startDate, endDate time.Time) ([]*AuditEvent, error)
}

// AuditService provides audit logging functionality
type AuditService struct {
	repository AuditRepository
	logger     logger.Logger
	config     *AuditConfig
}

// AuditConfig contains audit service configuration
type AuditConfig struct {
	RetentionDays      int  `json:"retention_days"`      // How long to keep audit logs
	AsyncLogging       bool `json:"async_logging"`       // Whether to log asynchronously
	CompressionEnabled bool `json:"compression_enabled"` // Whether to compress old logs
	ExportEnabled      bool `json:"export_enabled"`      // Whether export is enabled
	AlertingEnabled    bool `json:"alerting_enabled"`    // Whether to send alerts for critical events
}

// NewAuditService creates a new audit service
func NewAuditService(repository AuditRepository, logger logger.Logger, config *AuditConfig) *AuditService {
	if config == nil {
		config = &AuditConfig{
			RetentionDays:      365, // Default: 1 year
			AsyncLogging:       true,
			CompressionEnabled: true,
			ExportEnabled:      true,
			AlertingEnabled:    true,
		}
	}

	return &AuditService{
		repository: repository,
		logger:     logger,
		config:     config,
	}
}

// LogEvent creates an audit log entry
func (s *AuditService) LogEvent(ctx context.Context, organizationID string, actorID *string, eventType AuditEventType, resourceType string, resourceID string, details map[string]interface{}, ipAddress string, userAgent string) error {
	event := &AuditEvent{
		ID:             generateID(),
		OrganizationID: organizationID,
		ActorType:      "user",
		ActorID:        actorID,
		EventType:      eventType,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Details:        details,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Success:        true,
		CreatedAt:      time.Now().UTC(),
		Severity:       s.determineSeverity(eventType),
	}

	// Add session and request IDs if available in context
	if sessionID := getSessionIDFromContext(ctx); sessionID != "" {
		event.SessionID = &sessionID
	}
	if requestID := getRequestIDFromContext(ctx); requestID != "" {
		event.RequestID = &requestID
	}

	if s.config.AsyncLogging {
		go s.logEventAsync(event)
	} else {
		return s.repository.Create(ctx, event)
	}

	return nil
}

// LogFailureEvent creates an audit log entry for failed operations
func (s *AuditService) LogFailureEvent(ctx context.Context, organizationID string, actorID *string, eventType AuditEventType, resourceType string, resourceID string, details map[string]interface{}, ipAddress string, userAgent string, errorMsg string) error {
	event := &AuditEvent{
		ID:             generateID(),
		OrganizationID: organizationID,
		ActorType:      "user",
		ActorID:        actorID,
		EventType:      eventType,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Details:        details,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Success:        false,
		ErrorMessage:   &errorMsg,
		CreatedAt:      time.Now().UTC(),
		Severity:       s.determineSeverity(eventType),
	}

	// Add session and request IDs if available in context
	if sessionID := getSessionIDFromContext(ctx); sessionID != "" {
		event.SessionID = &sessionID
	}
	if requestID := getRequestIDFromContext(ctx); requestID != "" {
		event.RequestID = &requestID
	}

	if s.config.AsyncLogging {
		go s.logEventAsync(event)
	} else {
		return s.repository.Create(ctx, event)
	}

	return nil
}

// LogSystemEvent creates an audit log entry for system events
func (s *AuditService) LogSystemEvent(ctx context.Context, eventType AuditEventType, resourceType string, resourceID string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:             generateID(),
		OrganizationID: "system", // System-wide events
		ActorType:      "system",
		ActorID:        nil,
		EventType:      eventType,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Details:        details,
		IPAddress:      "127.0.0.1",
		UserAgent:      "system",
		Success:        true,
		CreatedAt:      time.Now().UTC(),
		Severity:       s.determineSeverity(eventType),
	}

	if s.config.AsyncLogging {
		go s.logEventAsync(event)
	} else {
		return s.repository.Create(ctx, event)
	}

	return nil
}

// QueryEvents retrieves audit events based on query parameters
func (s *AuditService) QueryEvents(ctx context.Context, query *AuditQuery) ([]*AuditEvent, int, error) {
	// Set default values
	if query.Limit <= 0 {
		query.Limit = 100
	}
	if query.Limit > 1000 {
		query.Limit = 1000
	}
	if query.SortBy == "" {
		query.SortBy = "created_at"
	}
	if query.SortOrder == "" {
		query.SortOrder = "desc"
	}

	return s.repository.Query(ctx, query)
}

// GetEventByID retrieves a specific audit event by ID
func (s *AuditService) GetEventByID(ctx context.Context, id string) (*AuditEvent, error) {
	return s.repository.GetByID(ctx, id)
}

// CleanupOldEvents removes audit events older than the configured retention period
func (s *AuditService) CleanupOldEvents(ctx context.Context) (int64, error) {
	cutoffDate := time.Now().AddDate(0, 0, -s.config.RetentionDays)
	deleted, err := s.repository.DeleteOldEvents(ctx, cutoffDate)
	if err != nil {
		s.logger.Error("Failed to cleanup old audit events", "error", err)
		return 0, err
	}

	if deleted > 0 {
		s.logger.Info("Cleaned up old audit events", "deleted_count", deleted, "cutoff_date", cutoffDate)
	}

	return deleted, nil
}

// ExportEvents exports audit events to various formats
func (s *AuditService) ExportEvents(ctx context.Context, query *AuditQuery, format string) ([]byte, error) {
	if !s.config.ExportEnabled {
		return nil, errors.NewForbiddenError("Audit export is disabled")
	}

	events, _, err := s.repository.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.MarshalIndent(events, "", "  ")
	case "csv":
		return s.exportToCSV(events)
	default:
		return nil, errors.NewValidationError("Unsupported export format: " + format)
	}
}

// GetAuditStatistics returns audit statistics for a given organization
func (s *AuditService) GetAuditStatistics(ctx context.Context, organizationID string, days int) (*AuditStatistics, error) {
	startDate := time.Now().AddDate(0, 0, -days)
	endDate := time.Now()

	events, err := s.repository.GetEventsByDateRange(ctx, organizationID, startDate, endDate)
	if err != nil {
		return nil, err
	}

	stats := &AuditStatistics{
		OrganizationID: organizationID,
		Period:         fmt.Sprintf("Last %d days", days),
		StartDate:      startDate,
		EndDate:        endDate,
		TotalEvents:    len(events),
		EventsByType:   make(map[string]int),
		EventsBySeverity: make(map[string]int),
		SuccessfulEvents: 0,
		FailedEvents:     0,
		UniqueUsers:      make(map[string]bool),
		UniqueIPs:        make(map[string]bool),
	}

	for _, event := range events {
		// Count by type
		stats.EventsByType[string(event.EventType)]++

		// Count by severity
		stats.EventsBySeverity[event.Severity]++

		// Count success/failure
		if event.Success {
			stats.SuccessfulEvents++
		} else {
			stats.FailedEvents++
		}

		// Track unique users
		if event.ActorID != nil {
			stats.UniqueUsers[*event.ActorID] = true
		}

		// Track unique IPs
		stats.UniqueIPs[event.IPAddress] = true
	}

	stats.UniqueUserCount = len(stats.UniqueUsers)
	stats.UniqueIPCount = len(stats.UniqueIPs)

	return stats, nil
}

// GetSecurityAlerts returns security-related audit events that may require attention
func (s *AuditService) GetSecurityAlerts(ctx context.Context, organizationID string, hours int) ([]*AuditEvent, error) {
	startDate := time.Now().Add(-time.Duration(hours) * time.Hour)
	query := &AuditQuery{
		OrganizationID: organizationID,
		EventTypes: []AuditEventType{
			EventTypeUserLoginFailed,
			EventTypeUserAccountLocked,
			EventTypeAccessDenied,
			EventTypeSecurityPolicyViolation,
		},
		StartDate: &startDate,
		Limit:     100,
		SortBy:    "created_at",
		SortOrder: "desc",
	}

	events, _, err := s.repository.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	// Filter for high-severity events or patterns
	var alerts []*AuditEvent
	for _, event := range events {
		if event.Severity == "high" || event.Severity == "critical" || !event.Success {
			alerts = append(alerts, event)
		}
	}

	return alerts, nil
}

// Private methods

func (s *AuditService) logEventAsync(event *AuditEvent) {
	ctx := context.Background()
	if err := s.repository.Create(ctx, event); err != nil {
		s.logger.Error("Failed to log audit event asynchronously", "error", err, "event_id", event.ID)
	}
}

func (s *AuditService) determineSeverity(eventType AuditEventType) string {
	switch eventType {
	case EventTypeUserLoginFailed, EventTypeUserAccountLocked, EventTypeAccessDenied, EventTypeSecurityPolicyViolation:
		return "high"
	case EventTypeUserDeleted, EventTypeOrgDeleted, EventTypeAPIKeyRevoked:
		return "medium"
	case EventTypeUserLogin, EventTypeUserLogout, EventTypeUserRegistered:
		return "low"
	case EventTypeSystemConfigChanged, EventTypeUserImpersonated:
		return "critical"
	default:
		return "medium"
	}
}

func (s *AuditService) exportToCSV(events []*AuditEvent) ([]byte, error) {
	// CSV header
	csv := "ID,Organization ID,Actor Type,Actor ID,Event Type,Resource Type,Resource ID,IP Address,User Agent,Success,Error Message,Created At,Session ID,Request ID,Severity\n"

	// CSV data
	for _, event := range events {
		actorID := ""
		if event.ActorID != nil {
			actorID = *event.ActorID
		}
		
		errorMsg := ""
		if event.ErrorMessage != nil {
			errorMsg = *event.ErrorMessage
		}

		sessionID := ""
		if event.SessionID != nil {
			sessionID = *event.SessionID
		}

		requestID := ""
		if event.RequestID != nil {
			requestID = *event.RequestID
		}

		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%t,%s,%s,%s,%s,%s\n",
			event.ID,
			event.OrganizationID,
			event.ActorType,
			actorID,
			string(event.EventType),
			event.ResourceType,
			event.ResourceID,
			event.IPAddress,
			event.UserAgent,
			event.Success,
			errorMsg,
			event.CreatedAt.Format(time.RFC3339),
			sessionID,
			requestID,
			event.Severity,
		)
	}

	return []byte(csv), nil
}

// AuditStatistics represents audit statistics for a given period
type AuditStatistics struct {
	OrganizationID    string            `json:"organization_id"`
	Period            string            `json:"period"`
	StartDate         time.Time         `json:"start_date"`
	EndDate           time.Time         `json:"end_date"`
	TotalEvents       int               `json:"total_events"`
	SuccessfulEvents  int               `json:"successful_events"`
	FailedEvents      int               `json:"failed_events"`
	EventsByType      map[string]int    `json:"events_by_type"`
	EventsBySeverity  map[string]int    `json:"events_by_severity"`
	UniqueUserCount   int               `json:"unique_user_count"`
	UniqueIPCount     int               `json:"unique_ip_count"`
	UniqueUsers       map[string]bool   `json:"-"` // Internal use only
	UniqueIPs         map[string]bool   `json:"-"` // Internal use only
}

// Utility functions

func generateID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

func getSessionIDFromContext(ctx context.Context) string {
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			return id
		}
	}
	return ""
}

func getRequestIDFromContext(ctx context.Context) string {
	if requestID := ctx.Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// Compliance helpers

// ComplianceReport represents a compliance audit report
type ComplianceReport struct {
	OrganizationID     string                 `json:"organization_id"`
	ReportType         string                 `json:"report_type"`
	GeneratedAt        time.Time              `json:"generated_at"`
	Period             string                 `json:"period"`
	StartDate          time.Time              `json:"start_date"`
	EndDate            time.Time              `json:"end_date"`
	TotalEvents        int                    `json:"total_events"`
	UserAccessEvents   int                    `json:"user_access_events"`
	AdminActions       int                    `json:"admin_actions"`
	FailedAttempts     int                    `json:"failed_attempts"`
	DataAccess         int                    `json:"data_access"`
	PolicyViolations   int                    `json:"policy_violations"`
	SecurityIncidents  int                    `json:"security_incidents"`
	Summary            string                 `json:"summary"`
	Recommendations    []string               `json:"recommendations"`
	Events             []*AuditEvent          `json:"events,omitempty"`
}

// GenerateComplianceReport generates a compliance report for audit purposes
func (s *AuditService) GenerateComplianceReport(ctx context.Context, organizationID string, reportType string, startDate, endDate time.Time) (*ComplianceReport, error) {
	query := &AuditQuery{
		OrganizationID: organizationID,
		StartDate:      &startDate,
		EndDate:        &endDate,
		Limit:          10000, // Large limit for comprehensive report
		SortBy:         "created_at",
		SortOrder:      "asc",
	}

	events, total, err := s.repository.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		OrganizationID: organizationID,
		ReportType:     reportType,
		GeneratedAt:    time.Now().UTC(),
		Period:         fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		StartDate:      startDate,
		EndDate:        endDate,
		TotalEvents:    total,
		Events:         events,
	}

	// Analyze events for compliance metrics
	for _, event := range events {
		switch event.EventType {
		case EventTypeUserLogin, EventTypeUserLogout, EventTypeUserOAuthLogin, EventTypeUserSAMLLogin, EventTypeUserLDAPLogin:
			report.UserAccessEvents++
		case EventTypeUserDeleted, EventTypeOrgDeleted, EventTypeRoleCreated, EventTypeRoleDeleted:
			report.AdminActions++
		case EventTypeUserLoginFailed, EventTypeAccessDenied:
			report.FailedAttempts++
		case EventTypeSecurityPolicyViolation:
			report.PolicyViolations++
		}

		if !event.Success {
			report.SecurityIncidents++
		}
	}

	// Generate summary and recommendations
	report.Summary = s.generateComplianceSummary(report)
	report.Recommendations = s.generateComplianceRecommendations(report)

	return report, nil
}

func (s *AuditService) generateComplianceSummary(report *ComplianceReport) string {
	return fmt.Sprintf("Compliance report for organization %s covering period %s. Total of %d audit events recorded with %d user access events, %d administrative actions, %d failed attempts, and %d policy violations.",
		report.OrganizationID,
		report.Period,
		report.TotalEvents,
		report.UserAccessEvents,
		report.AdminActions,
		report.FailedAttempts,
		report.PolicyViolations,
	)
}

func (s *AuditService) generateComplianceRecommendations(report *ComplianceReport) []string {
	var recommendations []string

	if report.FailedAttempts > report.UserAccessEvents*10/100 { // More than 10% failed attempts
		recommendations = append(recommendations, "High number of failed login attempts detected. Consider implementing additional security measures such as account lockout policies or IP-based restrictions.")
	}

	if report.PolicyViolations > 0 {
		recommendations = append(recommendations, "Security policy violations detected. Review and strengthen security policies and user training programs.")
	}

	if report.AdminActions > report.UserAccessEvents*20/100 { // More than 20% admin actions
		recommendations = append(recommendations, "High number of administrative actions detected. Ensure proper segregation of duties and approval processes for sensitive operations.")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No immediate security concerns identified. Continue regular monitoring and periodic security reviews.")
	}

	return recommendations
}