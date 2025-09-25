package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"

	"github.com/gorilla/mux"
)

// AuditHandler provides HTTP endpoints for audit log functionality
type AuditHandler struct {
	auditService *AuditService
	logger       logger.Logger
	validator    *validator.Validator
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditService *AuditService, logger logger.Logger, validator *validator.Validator) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
		logger:       logger,
		validator:    validator,
	}
}

// QueryEventsRequest represents the request for querying audit events
type QueryEventsRequest struct {
	OrganizationID string              `json:"organization_id" validate:"required"`
	EventTypes     []string            `json:"event_types,omitempty"`
	ActorID        *string             `json:"actor_id,omitempty"`
	ResourceType   *string             `json:"resource_type,omitempty"`
	ResourceID     *string             `json:"resource_id,omitempty"`
	IPAddress      *string             `json:"ip_address,omitempty"`
	Success        *bool               `json:"success,omitempty"`
	Severity       *string             `json:"severity,omitempty"`
	StartDate      *string             `json:"start_date,omitempty"`
	EndDate        *string             `json:"end_date,omitempty"`
	Limit          int                 `json:"limit,omitempty"`
	Offset         int                 `json:"offset,omitempty"`
	SortBy         string              `json:"sort_by,omitempty"`
	SortOrder      string              `json:"sort_order,omitempty"`
}

// QueryEventsResponse represents the response for audit event queries
type QueryEventsResponse struct {
	Events     []*AuditEvent `json:"events"`
	Total      int           `json:"total"`
	Limit      int           `json:"limit"`
	Offset     int           `json:"offset"`
	HasMore    bool          `json:"has_more"`
}

// QueryEvents retrieves audit events based on query parameters
func (h *AuditHandler) QueryEvents(w http.ResponseWriter, r *http.Request) {
	var req QueryEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Convert request to audit query
	query, err := h.convertToAuditQuery(&req)
	if err != nil {
		h.writeErrorResponse(w, err, http.StatusBadRequest)
		return
	}

	events, total, err := h.auditService.QueryEvents(r.Context(), query)
	if err != nil {
		h.logger.Error("Failed to query audit events", "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("Failed to query audit events"), http.StatusInternalServerError)
		return
	}

	response := &QueryEventsResponse{
		Events:  events,
		Total:   total,
		Limit:   query.Limit,
		Offset:  query.Offset,
		HasMore: (query.Offset + query.Limit) < total,
	}

	h.writeJSONResponse(w, response, http.StatusOK)
}

// GetEventByID retrieves a specific audit event by ID
func (h *AuditHandler) GetEventByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	eventID := vars["id"]

	if eventID == "" {
		h.writeErrorResponse(w, errors.NewValidationError("Event ID is required"), http.StatusBadRequest)
		return
	}

	event, err := h.auditService.GetEventByID(r.Context(), eventID)
	if err != nil {
		h.logger.Error("Failed to get audit event by ID", "event_id", eventID, "error", err)
		h.writeErrorResponse(w, errors.NewNotFoundError("Audit event not found"), http.StatusNotFound)
		return
	}

	h.writeJSONResponse(w, event, http.StatusOK)
}

// ExportEventsRequest represents the request for exporting audit events
type ExportEventsRequest struct {
	OrganizationID string    `json:"organization_id" validate:"required"`
	Format         string    `json:"format" validate:"required,oneof=json csv"`
	EventTypes     []string  `json:"event_types,omitempty"`
	ActorID        *string   `json:"actor_id,omitempty"`
	StartDate      *string   `json:"start_date,omitempty"`
	EndDate        *string   `json:"end_date,omitempty"`
	Limit          int       `json:"limit,omitempty"`
}

// ExportEvents exports audit events to various formats
func (h *AuditHandler) ExportEvents(w http.ResponseWriter, r *http.Request) {
	var req ExportEventsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Convert to audit query
	query := &AuditQuery{
		OrganizationID: req.OrganizationID,
		Limit:          req.Limit,
	}

	if req.Limit <= 0 {
		query.Limit = 10000 // Default export limit
	}

	// Convert event types
	if len(req.EventTypes) > 0 {
		for _, eventType := range req.EventTypes {
			query.EventTypes = append(query.EventTypes, AuditEventType(eventType))
		}
	}

	if req.ActorID != nil {
		query.ActorID = req.ActorID
	}

	// Parse dates
	if req.StartDate != nil {
		if startDate, err := time.Parse(time.RFC3339, *req.StartDate); err == nil {
			query.StartDate = &startDate
		}
	}

	if req.EndDate != nil {
		if endDate, err := time.Parse(time.RFC3339, *req.EndDate); err == nil {
			query.EndDate = &endDate
		}
	}

	data, err := h.auditService.ExportEvents(r.Context(), query, req.Format)
	if err != nil {
		h.logger.Error("Failed to export audit events", "format", req.Format, "error", err)
		h.writeErrorResponse(w, err, http.StatusInternalServerError)
		return
	}

	// Set appropriate content type and headers
	switch req.Format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit_export_%s.json", time.Now().Format("20060102_150405")))
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit_export_%s.csv", time.Now().Format("20060102_150405")))
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// GetStatisticsRequest represents the request for audit statistics
type GetStatisticsRequest struct {
	OrganizationID string `json:"organization_id" validate:"required"`
	Days           int    `json:"days" validate:"min=1,max=365"`
}

// GetStatistics retrieves audit statistics for a given organization and period
func (h *AuditHandler) GetStatistics(w http.ResponseWriter, r *http.Request) {
	var req GetStatisticsRequest

	// Handle both POST and GET requests
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
			return
		}
	} else {
		// GET request - parse query parameters
		req.OrganizationID = r.URL.Query().Get("organization_id")
		if daysStr := r.URL.Query().Get("days"); daysStr != "" {
			if days, err := strconv.Atoi(daysStr); err == nil {
				req.Days = days
			}
		}
	}

	if req.Days <= 0 {
		req.Days = 30 // Default to 30 days
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	statistics, err := h.auditService.GetAuditStatistics(r.Context(), req.OrganizationID, req.Days)
	if err != nil {
		h.logger.Error("Failed to get audit statistics", "organization_id", req.OrganizationID, "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("Failed to get audit statistics"), http.StatusInternalServerError)
		return
	}

	h.writeJSONResponse(w, statistics, http.StatusOK)
}

// GetSecurityAlertsRequest represents the request for security alerts
type GetSecurityAlertsRequest struct {
	OrganizationID string `json:"organization_id" validate:"required"`
	Hours          int    `json:"hours" validate:"min=1,max=168"` // Max 1 week
}

// GetSecurityAlerts retrieves security alerts for a given organization
func (h *AuditHandler) GetSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	var req GetSecurityAlertsRequest

	// Handle both POST and GET requests
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
			return
		}
	} else {
		// GET request - parse query parameters
		req.OrganizationID = r.URL.Query().Get("organization_id")
		if hoursStr := r.URL.Query().Get("hours"); hoursStr != "" {
			if hours, err := strconv.Atoi(hoursStr); err == nil {
				req.Hours = hours
			}
		}
	}

	if req.Hours <= 0 {
		req.Hours = 24 // Default to last 24 hours
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	alerts, err := h.auditService.GetSecurityAlerts(r.Context(), req.OrganizationID, req.Hours)
	if err != nil {
		h.logger.Error("Failed to get security alerts", "organization_id", req.OrganizationID, "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("Failed to get security alerts"), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"alerts":  alerts,
		"count":   len(alerts),
		"period":  fmt.Sprintf("Last %d hours", req.Hours),
		"generated_at": time.Now().UTC(),
	}

	h.writeJSONResponse(w, response, http.StatusOK)
}

// ComplianceReportRequest represents the request for generating compliance reports
type ComplianceReportRequest struct {
	OrganizationID string `json:"organization_id" validate:"required"`
	ReportType     string `json:"report_type" validate:"required,oneof=soc2 gdpr hipaa pci general"`
	StartDate      string `json:"start_date" validate:"required"`
	EndDate        string `json:"end_date" validate:"required"`
	IncludeEvents  bool   `json:"include_events,omitempty"`
}

// GenerateComplianceReport generates a compliance report for audit purposes
func (h *AuditHandler) GenerateComplianceReport(w http.ResponseWriter, r *http.Request) {
	var req ComplianceReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid request body"), http.StatusBadRequest)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Validation failed: "+err.Error()), http.StatusBadRequest)
		return
	}

	// Parse dates
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid start date format. Use YYYY-MM-DD"), http.StatusBadRequest)
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		h.writeErrorResponse(w, errors.NewValidationError("Invalid end date format. Use YYYY-MM-DD"), http.StatusBadRequest)
		return
	}

	if endDate.Before(startDate) {
		h.writeErrorResponse(w, errors.NewValidationError("End date must be after start date"), http.StatusBadRequest)
		return
	}

	// Generate compliance report
	report, err := h.auditService.GenerateComplianceReport(r.Context(), req.OrganizationID, req.ReportType, startDate, endDate)
	if err != nil {
		h.logger.Error("Failed to generate compliance report", "organization_id", req.OrganizationID, "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("Failed to generate compliance report"), http.StatusInternalServerError)
		return
	}

	// Remove detailed events if not requested to reduce response size
	if !req.IncludeEvents {
		report.Events = nil
	}

	h.writeJSONResponse(w, report, http.StatusOK)
}

// CleanupOldEvents removes old audit events based on retention policy
func (h *AuditHandler) CleanupOldEvents(w http.ResponseWriter, r *http.Request) {
	deletedCount, err := h.auditService.CleanupOldEvents(r.Context())
	if err != nil {
		h.logger.Error("Failed to cleanup old audit events", "error", err)
		h.writeErrorResponse(w, errors.NewInternalError("Failed to cleanup old events"), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("Successfully cleaned up %d old audit events", deletedCount),
		"cleaned_at":    time.Now().UTC(),
	}

	h.writeJSONResponse(w, response, http.StatusOK)
}

// GetEventTypes returns all available audit event types
func (h *AuditHandler) GetEventTypes(w http.ResponseWriter, r *http.Request) {
	eventTypes := map[string][]string{
		"authentication": {
			string(EventTypeUserLogin),
			string(EventTypeUserLogout),
			string(EventTypeUserLoginFailed),
			string(EventTypeUserRegistered),
			string(EventTypeUserPasswordChanged),
			string(EventTypeUserEmailChanged),
			string(EventTypeUserMFAEnabled),
			string(EventTypeUserMFADisabled),
			string(EventTypeUserAccountLocked),
			string(EventTypeUserAccountUnlocked),
			string(EventTypeUserDeleted),
			string(EventTypeUserImpersonated),
		},
		"enterprise_auth": {
			string(EventTypeUserOAuthLogin),
			string(EventTypeUserSAMLLogin),
			string(EventTypeUserLDAPLogin),
			string(EventTypeUserSAMLRegistered),
			string(EventTypeUserLDAPRegistered),
		},
		"organization": {
			string(EventTypeOrgCreated),
			string(EventTypeOrgUpdated),
			string(EventTypeOrgDeleted),
			string(EventTypeOrgMemberAdded),
			string(EventTypeOrgMemberRemoved),
			string(EventTypeOrgMemberRoleChanged),
			string(EventTypeOrgInviteCreated),
			string(EventTypeOrgInviteAccepted),
			string(EventTypeOrgInviteRevoked),
		},
		"team": {
			string(EventTypeTeamCreated),
			string(EventTypeTeamUpdated),
			string(EventTypeTeamDeleted),
			string(EventTypeTeamMemberAdded),
			string(EventTypeTeamMemberRemoved),
			string(EventTypeTeamMemberRoleChanged),
		},
		"permissions": {
			string(EventTypeRoleCreated),
			string(EventTypeRoleUpdated),
			string(EventTypeRoleDeleted),
			string(EventTypePermissionGranted),
			string(EventTypePermissionRevoked),
			string(EventTypeAccessDenied),
		},
		"api_security": {
			string(EventTypeAPIKeyCreated),
			string(EventTypeAPIKeyRevoked),
			string(EventTypeAPIKeyUsed),
			string(EventTypeSessionCreated),
			string(EventTypeSessionExpired),
			string(EventTypeSecurityPolicyViolation),
		},
		"system": {
			string(EventTypeSystemBackup),
			string(EventTypeSystemRestore),
			string(EventTypeSystemMaintenance),
			string(EventTypeSystemConfigChanged),
		},
	}

	h.writeJSONResponse(w, eventTypes, http.StatusOK)
}

// Utility methods

func (h *AuditHandler) convertToAuditQuery(req *QueryEventsRequest) (*AuditQuery, error) {
	query := &AuditQuery{
		OrganizationID: req.OrganizationID,
		ActorID:        req.ActorID,
		ResourceType:   req.ResourceType,
		ResourceID:     req.ResourceID,
		IPAddress:      req.IPAddress,
		Success:        req.Success,
		Severity:       req.Severity,
		Limit:          req.Limit,
		Offset:         req.Offset,
		SortBy:         req.SortBy,
		SortOrder:      req.SortOrder,
	}

	// Convert event types
	if len(req.EventTypes) > 0 {
		for _, eventType := range req.EventTypes {
			query.EventTypes = append(query.EventTypes, AuditEventType(eventType))
		}
	}

	// Parse dates
	if req.StartDate != nil {
		startDate, err := time.Parse(time.RFC3339, *req.StartDate)
		if err != nil {
			return nil, errors.NewValidationError("Invalid start date format. Use RFC3339")
		}
		query.StartDate = &startDate
	}

	if req.EndDate != nil {
		endDate, err := time.Parse(time.RFC3339, *req.EndDate)
		if err != nil {
			return nil, errors.NewValidationError("Invalid end date format. Use RFC3339")
		}
		query.EndDate = &endDate
	}

	return query, nil
}

func (h *AuditHandler) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

func (h *AuditHandler) writeErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error": err.Error(),
		"code":  statusCode,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode error response", "error", err)
	}
}

// RegisterRoutes registers audit-related routes
func (h *AuditHandler) RegisterRoutes(router *mux.Router) {
	// Query and retrieval endpoints
	auditRouter := router.PathPrefix("/audit").Subrouter()
	auditRouter.HandleFunc("/events/query", h.QueryEvents).Methods("POST")
	auditRouter.HandleFunc("/events/{id}", h.GetEventByID).Methods("GET")
	auditRouter.HandleFunc("/events/export", h.ExportEvents).Methods("POST")

	// Statistics and analytics
	auditRouter.HandleFunc("/statistics", h.GetStatistics).Methods("GET", "POST")
	auditRouter.HandleFunc("/security/alerts", h.GetSecurityAlerts).Methods("GET", "POST")

	// Compliance and reporting
	auditRouter.HandleFunc("/compliance/report", h.GenerateComplianceReport).Methods("POST")

	// Maintenance
	auditRouter.HandleFunc("/cleanup", h.CleanupOldEvents).Methods("POST")

	// Metadata
	auditRouter.HandleFunc("/event-types", h.GetEventTypes).Methods("GET")
}