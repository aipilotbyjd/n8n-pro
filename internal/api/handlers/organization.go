package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/auth"
	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/gorilla/mux"
)

type OrganizationHandler struct {
	authService *auth.EnhancedAuthService
	logger      logger.Logger
}

func NewOrganizationHandler(authService *auth.EnhancedAuthService, logger logger.Logger) *OrganizationHandler {
	return &OrganizationHandler{
		authService: authService,
		logger:      logger,
	}
}

// Organization management request/response types

type CreateOrganizationRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=100"`
	Description *string           `json:"description,omitempty" validate:"omitempty,max=500"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type UpdateOrganizationRequest struct {
	Name        *string           `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string           `json:"description,omitempty" validate:"omitempty,max=500"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type OrganizationResponse struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Slug        string                    `json:"slug"`
	Description *string                   `json:"description"`
	Plan        auth.PlanType             `json:"plan"`
	PlanLimits  auth.PlanLimits           `json:"plan_limits"`
	Status      auth.OrganizationStatus   `json:"status"`
	Settings    map[string]interface{}    `json:"settings"`
	MemberCount int                       `json:"member_count"`
	TeamCount   int                       `json:"team_count"`
	Owner       *UserSummary              `json:"owner,omitempty"`
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
}

type OrganizationMemberResponse struct {
	ID            string                `json:"id"`
	Email         string                `json:"email"`
	FirstName     string                `json:"first_name"`
	LastName      string                `json:"last_name"`
	FullName      string                `json:"full_name"`
	Role          auth.RoleType         `json:"role"`
	Status        auth.UserStatus       `json:"status"`
	EmailVerified bool                  `json:"email_verified"`
	JoinedAt      string                `json:"joined_at"`
	LastLoginAt   *string               `json:"last_login_at"`
	Teams         []TeamMembershipInfo  `json:"teams"`
}

type TeamMembershipInfo struct {
	TeamID   string        `json:"team_id"`
	TeamName string        `json:"team_name"`
	Role     auth.RoleType `json:"role"`
	JoinedAt string        `json:"joined_at"`
}

type UserSummary struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	FullName  string `json:"full_name"`
}

type InviteUserRequest struct {
	Email   string        `json:"email" validate:"required,email"`
	Role    auth.RoleType `json:"role" validate:"required,oneof=owner admin member viewer"`
	TeamIDs []string      `json:"team_ids,omitempty"`
	Message *string       `json:"message,omitempty" validate:"omitempty,max=500"`
}

type UpdateMemberRoleRequest struct {
	Role auth.RoleType `json:"role" validate:"required,oneof=owner admin member viewer"`
}

// GetCurrentOrganization returns the current user's organization details
func (h *OrganizationHandler) GetCurrentOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	org, err := h.authService.GetOrganizationByID(r.Context(), user.OrganizationID)
	if err != nil {
		h.logger.Error("Failed to get organization", "org_id", user.OrganizationID, "error", err)
		writeError(w, errors.InternalError("Failed to get organization"))
		return
	}

	// Get organization statistics
	memberCount, err := h.authService.GetOrganizationMemberCount(r.Context(), org.ID)
	if err != nil {
		h.logger.Error("Failed to get member count", "org_id", org.ID, "error", err)
		memberCount = 0 // Default to 0 on error
	}

	teamCount, err := h.authService.GetOrganizationTeamCount(r.Context(), org.ID)
	if err != nil {
		h.logger.Error("Failed to get team count", "org_id", org.ID, "error", err)
		teamCount = 0 // Default to 0 on error
	}

	// Get organization owner
	owner, err := h.authService.GetOrganizationOwner(r.Context(), org.ID)
	if err != nil {
		h.logger.Error("Failed to get organization owner", "org_id", org.ID, "error", err)
		owner = nil // Set to nil on error
	}

	response := &OrganizationResponse{
		ID:          org.ID,
		Name:        org.Name,
		Slug:        org.Slug,
		Description: org.Description,
		Plan:        org.Plan,
		PlanLimits:  org.PlanLimits,
		Status:      org.Status,
		Settings:    org.Settings,
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

// UpdateOrganization updates organization details (owner/admin only)
func (h *OrganizationHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to update organization
	if user.Role != auth.RoleOwner && user.Role != auth.RoleAdmin {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to update organization"))
		return
	}

	var req UpdateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	err := h.authService.UpdateOrganization(r.Context(), user.OrganizationID, &req)
	if err != nil {
		h.logger.Error("Failed to update organization", "org_id", user.OrganizationID, "error", err)
		writeError(w, errors.InternalError("Failed to update organization"))
		return
	}

	// Get updated organization
	org, err := h.authService.GetOrganizationByID(r.Context(), user.OrganizationID)
	if err != nil {
		h.logger.Error("Failed to get updated organization", "org_id", user.OrganizationID, "error", err)
		writeError(w, errors.InternalError("Failed to get updated organization"))
		return
	}

	// Log the action
	h.authService.CreateAuditLog(r.Context(), user.OrganizationID, &user.ID, "organization.updated", "organization", org.ID, map[string]interface{}{
		"updated_fields": getUpdatedFields(&req),
	}, getClientIP(r), "organization-update")

	h.logger.Info("Organization updated", "org_id", org.ID, "user_id", user.ID)

	response := &OrganizationResponse{
		ID:          org.ID,
		Name:        org.Name,
		Slug:        org.Slug,
		Description: org.Description,
		Plan:        org.Plan,
		PlanLimits:  org.PlanLimits,
		Status:      org.Status,
		Settings:    org.Settings,
		CreatedAt:   org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   org.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeSuccess(w, http.StatusOK, response)
}

// GetOrganizationMembers returns organization members (admin+ only)
func (h *OrganizationHandler) GetOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to view members
	if user.Role == auth.RoleViewer {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to view organization members"))
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

	members, total, err := h.authService.GetOrganizationMembers(r.Context(), user.OrganizationID, page, limit)
	if err != nil {
		h.logger.Error("Failed to get organization members", "org_id", user.OrganizationID, "error", err)
		writeError(w, errors.InternalError("Failed to get organization members"))
		return
	}

	var memberResponses []OrganizationMemberResponse
	for _, member := range members {
		// Get user's team memberships
		teams, err := h.authService.GetUserTeamMemberships(r.Context(), member.ID)
		if err != nil {
			h.logger.Error("Failed to get user team memberships", "user_id", member.ID, "error", err)
			teams = []*auth.TeamMembership{} // Default to empty on error
		}

		var teamInfos []TeamMembershipInfo
		for _, team := range teams {
			teamInfos = append(teamInfos, TeamMembershipInfo{
				TeamID:   team.TeamID,
				TeamName: team.Team.Name,
				Role:     team.Role,
				JoinedAt: team.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}

		var lastLoginStr *string
		if member.LastLoginAt != nil {
			str := member.LastLoginAt.Format("2006-01-02T15:04:05Z07:00")
			lastLoginStr = &str
		}

		memberResponses = append(memberResponses, OrganizationMemberResponse{
			ID:            member.ID,
			Email:         member.Email,
			FirstName:     member.FirstName,
			LastName:      member.LastName,
			FullName:      member.FirstName + " " + member.LastName,
			Role:          member.Role,
			Status:        member.Status,
			EmailVerified: member.EmailVerified,
			JoinedAt:      member.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastLoginAt:   lastLoginStr,
			Teams:         teamInfos,
		})
	}

	response := map[string]interface{}{
		"members": memberResponses,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"total_pages": (total + limit - 1) / limit,
		},
	}

	writeSuccess(w, http.StatusOK, response)
}

// InviteUser invites a new user to the organization (admin+ only)
func (h *OrganizationHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to invite users
	if user.Role != auth.RoleOwner && user.Role != auth.RoleAdmin {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to invite users"))
		return
	}

	var req InviteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate role - can't invite someone with higher privileges
	if (user.Role == auth.RoleAdmin && req.Role == auth.RoleOwner) {
		writeError(w, errors.NewValidationError("Cannot invite user with higher privileges"))
		return
	}

	invitation, err := h.authService.InviteUser(r.Context(), user.OrganizationID, user.ID, req.Email, req.Role, req.TeamIDs, req.Message, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to invite user", "org_id", user.OrganizationID, "email", req.Email, "error", err)
		if err.Error() == "user already exists in organization" {
			writeError(w, errors.NewValidationError("User is already a member of this organization"))
			return
		}
		writeError(w, errors.InternalError("Failed to send invitation"))
		return
	}

	h.logger.Info("User invited successfully", "org_id", user.OrganizationID, "invited_email", req.Email, "inviter_id", user.ID)

	response := map[string]interface{}{
		"message":        "Invitation sent successfully",
		"invitation_id":  invitation.ID,
		"invited_email":  invitation.Email,
		"role":           invitation.Role,
		"expires_at":     invitation.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeSuccess(w, http.StatusCreated, response)
}

// UpdateMemberRole updates a member's role (owner/admin only)
func (h *OrganizationHandler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to update member roles
	if user.Role != auth.RoleOwner && user.Role != auth.RoleAdmin {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to update member roles"))
		return
	}

	vars := mux.Vars(r)
	memberID := vars["memberID"]
	if memberID == "" {
		writeError(w, errors.NewValidationError("Member ID is required"))
		return
	}

	var req UpdateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate role - can't assign someone with higher privileges than yourself
	if (user.Role == auth.RoleAdmin && req.Role == auth.RoleOwner) {
		writeError(w, errors.NewValidationError("Cannot assign role with higher privileges"))
		return
	}

	// Can't update your own role
	if memberID == user.ID {
		writeError(w, errors.NewValidationError("Cannot update your own role"))
		return
	}

	err := h.authService.UpdateMemberRole(r.Context(), user.OrganizationID, memberID, req.Role, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to update member role", "org_id", user.OrganizationID, "member_id", memberID, "new_role", req.Role, "error", err)
		if err.Error() == "member not found" {
			writeError(w, errors.NewNotFoundError("Member not found"))
			return
		}
		writeError(w, errors.InternalError("Failed to update member role"))
		return
	}

	h.logger.Info("Member role updated", "org_id", user.OrganizationID, "member_id", memberID, "new_role", req.Role, "updated_by", user.ID)

	response := map[string]interface{}{
		"message":   "Member role updated successfully",
		"member_id": memberID,
		"new_role":  req.Role,
	}

	writeSuccess(w, http.StatusOK, response)
}

// RemoveMember removes a member from the organization (owner/admin only)
func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to remove members
	if user.Role != auth.RoleOwner && user.Role != auth.RoleAdmin {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to remove members"))
		return
	}

	vars := mux.Vars(r)
	memberID := vars["memberID"]
	if memberID == "" {
		writeError(w, errors.NewValidationError("Member ID is required"))
		return
	}

	// Can't remove yourself
	if memberID == user.ID {
		writeError(w, errors.NewValidationError("Cannot remove yourself from the organization"))
		return
	}

	err := h.authService.RemoveOrganizationMember(r.Context(), user.OrganizationID, memberID, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to remove member", "org_id", user.OrganizationID, "member_id", memberID, "error", err)
		if err.Error() == "member not found" {
			writeError(w, errors.NewNotFoundError("Member not found"))
			return
		}
		if err.Error() == "cannot remove organization owner" {
			writeError(w, errors.NewValidationError("Cannot remove organization owner"))
			return
		}
		writeError(w, errors.InternalError("Failed to remove member"))
		return
	}

	h.logger.Info("Member removed from organization", "org_id", user.OrganizationID, "member_id", memberID, "removed_by", user.ID)

	response := map[string]interface{}{
		"message":   "Member removed successfully",
		"member_id": memberID,
	}

	writeSuccess(w, http.StatusOK, response)
}

// Helper functions

func getUpdatedFields(req *UpdateOrganizationRequest) []string {
	var fields []string
	if req.Name != nil {
		fields = append(fields, "name")
	}
	if req.Description != nil {
		fields = append(fields, "description")
	}
	if req.Settings != nil {
		fields = append(fields, "settings")
	}
	return fields
}