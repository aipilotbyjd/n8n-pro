package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/pkg/errors"

	"github.com/gorilla/mux"
)

// Organization settings request/response types

type OrganizationSettingsRequest struct {
	Settings map[string]interface{} `json:"settings" validate:"required"`
}

type OrganizationSettingsResponse struct {
	Settings map[string]interface{} `json:"settings"`
}

// GetOrganizationSettings returns organization settings (owner/admin only)
func (h *OrganizationHandler) GetOrganizationSettings(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Use team ID as organization ID placeholder for now
	orgID := user.TeamID
	if orgID == "" {
		orgID = "default-org"
	}

	org, err := h.authService.GetOrganizationByID(r.Context(), orgID)
	if err != nil {
		h.logger.Error("Failed to get organization for settings", "org_id", orgID, "error", err)
		writeError(w, errors.InternalError("Failed to get organization"))
		return
	}

	// Convert OrganizationSettings struct to map for response
	settingsMap := make(map[string]interface{})
	settingsBytes, _ := json.Marshal(org.Settings)
	json.Unmarshal(settingsBytes, &settingsMap)

	response := OrganizationSettingsResponse{
		Settings: settingsMap,
	}

	writeSuccess(w, http.StatusOK, response)
}

// UpdateOrganizationSettings updates organization settings (owner/admin only)
func (h *OrganizationHandler) UpdateOrganizationSettings(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req OrganizationSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Update organization settings
	updateReq := &UpdateOrganizationRequest{
		Settings: req.Settings,
	}

	// Use team ID as organization ID placeholder for now
	orgID := user.TeamID
	if orgID == "" {
		orgID = "default-org"
	}

	err := h.authService.UpdateOrganization(r.Context(), orgID, updateReq)
	if err != nil {
		h.logger.Error("Failed to update organization settings", "org_id", orgID, "error", err)
		writeError(w, errors.InternalError("Failed to update organization settings"))
		return
	}

	// Log the action
	h.authService.CreateAuditLog(r.Context(), orgID, &user.ID, "organization.settings_updated", "organization", orgID, map[string]interface{}{
		"updated_settings": getSettingsKeys(req.Settings),
	}, getClientIP(r), "organization-settings-update")

	h.logger.Info("Organization settings updated", "org_id", orgID, "user_id", user.ID)

	response := map[string]interface{}{
		"message": "Organization settings updated successfully",
	}
	writeSuccess(w, http.StatusOK, response)
}

// Admin-only organization management methods

// GetAllOrganizations returns all organizations (system admin only)
func (h *OrganizationHandler) GetAllOrganizations(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	status := query.Get("status")
	search := query.Get("search")

	organizations, total, err := h.authService.GetAllOrganizations(r.Context(), page, limit, status, search)
	if err != nil {
		h.logger.Error("Failed to get all organizations", "error", err)
		writeError(w, errors.InternalError("Failed to get organizations"))
		return
	}

	var orgResponses []OrganizationResponse
	for _, org := range organizations {
		// Get basic stats for each organization
		memberCount, _ := h.authService.GetOrganizationMemberCount(r.Context(), org.ID)
		teamCount, _ := h.authService.GetOrganizationTeamCount(r.Context(), org.ID)
		owner, _ := h.authService.GetOrganizationOwner(r.Context(), org.ID)

		// Convert OrganizationSettings struct to map for response
		settingsMap := make(map[string]interface{})
		settingsBytes, _ := json.Marshal(org.Settings)
		json.Unmarshal(settingsBytes, &settingsMap)

		response := OrganizationResponse{
			ID:          org.ID,
			Name:        org.Name,
			Slug:        org.Slug,
			Description: nil, // Organization model doesn't have Description field
			Plan:        org.Plan,
			PlanLimits:  org.PlanLimits,
			Status:      org.Status,
			Settings:    settingsMap,
			MemberCount: memberCount,
			TeamCount:   teamCount,
			CreatedAt:   org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   org.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}

		if owner != nil {
			response.Owner = &UserSummary{
				ID:        owner.ID,
				Email:     owner.Email,
				FirstName: owner.FirstName,
				LastName:  owner.LastName,
				FullName:  owner.FirstName + " " + owner.LastName,
			}
		}

		orgResponses = append(orgResponses, response)
	}

	response := map[string]interface{}{
		"organizations": orgResponses,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + limit - 1) / limit,
		},
	}

	writeSuccess(w, http.StatusOK, response)
}

// GetOrganization returns a specific organization (system admin only)
func (h *OrganizationHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	orgID := vars["orgID"]
	if orgID == "" {
		writeError(w, errors.NewValidationError("Organization ID is required"))
		return
	}

	org, err := h.authService.GetOrganizationByID(r.Context(), orgID)
	if err != nil {
		h.logger.Error("Failed to get organization", "org_id", orgID, "error", err)
		writeError(w, errors.NewNotFoundError("Organization not found"))
		return
	}

	// Get organization statistics
	memberCount, _ := h.authService.GetOrganizationMemberCount(r.Context(), org.ID)
	teamCount, _ := h.authService.GetOrganizationTeamCount(r.Context(), org.ID)
	owner, _ := h.authService.GetOrganizationOwner(r.Context(), org.ID)

	// Convert OrganizationSettings struct to map for response
	settingsMap := make(map[string]interface{})
	settingsBytes, _ := json.Marshal(org.Settings)
	json.Unmarshal(settingsBytes, &settingsMap)

	response := OrganizationResponse{
		ID:          org.ID,
		Name:        org.Name,
		Slug:        org.Slug,
		Description: nil, // Organization model doesn't have Description field
		Plan:        org.Plan,
		PlanLimits:  org.PlanLimits,
		Status:      org.Status,
		Settings:    settingsMap,
		MemberCount: memberCount,
		TeamCount:   teamCount,
		CreatedAt:   org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   org.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if owner != nil {
		response.Owner = &UserSummary{
			ID:        owner.ID,
			Email:     owner.Email,
			FirstName: owner.FirstName,
			LastName:  owner.LastName,
			FullName:  owner.FirstName + " " + owner.LastName,
		}
	}

	writeSuccess(w, http.StatusOK, response)
}

// AdminUpdateOrganization updates an organization (system admin only)
func (h *OrganizationHandler) AdminUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	orgID := vars["orgID"]
	if orgID == "" {
		writeError(w, errors.NewValidationError("Organization ID is required"))
		return
	}

	var req UpdateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	err := h.authService.UpdateOrganization(r.Context(), orgID, &req)
	if err != nil {
		h.logger.Error("Failed to admin update organization", "org_id", orgID, "error", err)
		writeError(w, errors.InternalError("Failed to update organization"))
		return
	}

	// Log the admin action
	h.authService.CreateAuditLog(r.Context(), orgID, &user.ID, "organization.admin_updated", "organization", orgID, map[string]interface{}{
		"updated_fields": getUpdatedFields(&req),
		"admin_user_id":  user.ID,
	}, getClientIP(r), "admin-organization-update")

	h.logger.Info("Organization updated by admin", "org_id", orgID, "admin_user_id", user.ID)

	response := map[string]interface{}{
		"message": "Organization updated successfully",
		"org_id":  orgID,
	}
	writeSuccess(w, http.StatusOK, response)
}

// SuspendOrganization suspends an organization (system admin only)
func (h *OrganizationHandler) SuspendOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	orgID := vars["orgID"]
	if orgID == "" {
		writeError(w, errors.NewValidationError("Organization ID is required"))
		return
	}

	err := h.authService.UpdateOrganizationStatus(r.Context(), orgID, auth.OrgStatusSuspended)
	if err != nil {
		h.logger.Error("Failed to suspend organization", "org_id", orgID, "error", err)
		writeError(w, errors.InternalError("Failed to suspend organization"))
		return
	}

	// Log the admin action
	h.authService.CreateAuditLog(r.Context(), orgID, &user.ID, "organization.suspended", "organization", orgID, map[string]interface{}{
		"admin_user_id": user.ID,
		"reason":        "admin_action",
	}, getClientIP(r), "admin-organization-suspend")

	h.logger.Info("Organization suspended by admin", "org_id", orgID, "admin_user_id", user.ID)

	response := map[string]interface{}{
		"message": "Organization suspended successfully",
		"org_id":  orgID,
		"status":  auth.OrgStatusSuspended,
	}
	writeSuccess(w, http.StatusOK, response)
}

// ActivateOrganization activates a suspended organization (system admin only)
func (h *OrganizationHandler) ActivateOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	orgID := vars["orgID"]
	if orgID == "" {
		writeError(w, errors.NewValidationError("Organization ID is required"))
		return
	}

	err := h.authService.UpdateOrganizationStatus(r.Context(), orgID, auth.OrgStatusActive)
	if err != nil {
		h.logger.Error("Failed to activate organization", "org_id", orgID, "error", err)
		writeError(w, errors.InternalError("Failed to activate organization"))
		return
	}

	// Log the admin action
	h.authService.CreateAuditLog(r.Context(), orgID, &user.ID, "organization.activated", "organization", orgID, map[string]interface{}{
		"admin_user_id": user.ID,
		"reason":        "admin_action",
	}, getClientIP(r), "admin-organization-activate")

	h.logger.Info("Organization activated by admin", "org_id", orgID, "admin_user_id", user.ID)

	response := map[string]interface{}{
		"message": "Organization activated successfully",
		"org_id":  orgID,
		"status":  auth.OrgStatusActive,
	}
	writeSuccess(w, http.StatusOK, response)
}

// Helper functions

// getSettingsKeys returns the keys of updated settings
func getSettingsKeys(settings map[string]interface{}) []string {
	var keys []string
	for key := range settings {
		keys = append(keys, key)
	}
	return keys
}