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

type TeamHandler struct {
	authService *auth.EnhancedAuthService
	logger      logger.Logger
}

func NewTeamHandler(authService *auth.EnhancedAuthService, logger logger.Logger) *TeamHandler {
	return &TeamHandler{
		authService: authService,
		logger:      logger,
	}
}

// Team management request/response types

type CreateTeamRequest struct {
	Name        string                 `json:"name" validate:"required,min=1,max=100"`
	Description *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type UpdateTeamRequest struct {
	Name        *string                `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type TeamResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description *string                `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
	MemberCount int                    `json:"member_count"`
	Owner       *UserSummary           `json:"owner,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
	UserRole    auth.RoleType          `json:"user_role"` // Current user's role in this team
}

type TeamMemberResponse struct {
	ID            string        `json:"id"`
	Email         string        `json:"email"`
	FirstName     string        `json:"first_name"`
	LastName      string        `json:"last_name"`
	FullName      string        `json:"full_name"`
	Role          auth.RoleType `json:"role"`
	Status        auth.UserStatus `json:"status"`
	EmailVerified bool          `json:"email_verified"`
	JoinedAt      string        `json:"joined_at"`
	LastLoginAt   *string       `json:"last_login_at"`
}

type AddTeamMemberRequest struct {
	UserID string        `json:"user_id" validate:"required"`
	Role   auth.RoleType `json:"role" validate:"required,oneof=owner admin member viewer"`
}

type UpdateTeamMemberRoleRequest struct {
	Role auth.RoleType `json:"role" validate:"required,oneof=owner admin member viewer"`
}

// GetUserTeams returns teams that the current user is a member of
func (h *TeamHandler) GetUserTeams(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	teams, err := h.authService.GetUserTeamMemberships(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("Failed to get user teams", "user_id", user.ID, "error", err)
		writeError(w, errors.InternalError("Failed to get user teams"))
		return
	}

	var teamResponses []TeamResponse
	for _, membership := range teams {
		team := membership.Team
		
		// Get team member count
		memberCount, err := h.authService.GetTeamMemberCount(r.Context(), team.ID)
		if err != nil {
			h.logger.Error("Failed to get team member count", "team_id", team.ID, "error", err)
			memberCount = 0 // Default to 0 on error
		}

		// Get team owner
		owner, err := h.authService.GetTeamOwner(r.Context(), team.ID)
		if err != nil {
			h.logger.Error("Failed to get team owner", "team_id", team.ID, "error", err)
			owner = nil // Set to nil on error
		}

		response := TeamResponse{
			ID:          team.ID,
			Name:        team.Name,
			Description: team.Description,
			Settings:    team.Settings,
			MemberCount: memberCount,
			CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UserRole:    membership.Role,
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

		teamResponses = append(teamResponses, response)
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"teams": teamResponses,
	})
}

// GetOrganizationTeams returns all teams in the organization (admin+ only)
func (h *TeamHandler) GetOrganizationTeams(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to view all teams
	if user.Role == auth.RoleViewer || user.Role == auth.RoleMember {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to view all organization teams"))
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

	teams, total, err := h.authService.GetOrganizationTeams(r.Context(), user.OrganizationID, page, limit)
	if err != nil {
		h.logger.Error("Failed to get organization teams", "org_id", user.OrganizationID, "error", err)
		writeError(w, errors.InternalError("Failed to get organization teams"))
		return
	}

	var teamResponses []TeamResponse
	for _, team := range teams {
		// Get team member count
		memberCount, err := h.authService.GetTeamMemberCount(r.Context(), team.ID)
		if err != nil {
			h.logger.Error("Failed to get team member count", "team_id", team.ID, "error", err)
			memberCount = 0 // Default to 0 on error
		}

		// Get team owner
		owner, err := h.authService.GetTeamOwner(r.Context(), team.ID)
		if err != nil {
			h.logger.Error("Failed to get team owner", "team_id", team.ID, "error", err)
			owner = nil // Set to nil on error
		}

		// Get current user's role in this team
		userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, team.ID)
		if err != nil {
			h.logger.Error("Failed to get user role in team", "user_id", user.ID, "team_id", team.ID, "error", err)
			userRole = auth.RoleViewer // Default to viewer on error
		}

		response := TeamResponse{
			ID:          team.ID,
			Name:        team.Name,
			Description: team.Description,
			Settings:    team.Settings,
			MemberCount: memberCount,
			CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UserRole:    userRole,
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

		teamResponses = append(teamResponses, response)
	}

	response := map[string]interface{}{
		"teams": teamResponses,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + limit - 1) / limit,
		},
	}

	writeSuccess(w, http.StatusOK, response)
}

// GetTeam returns details of a specific team
func (h *TeamHandler) GetTeam(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	// Check if user has access to this team
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil {
		h.logger.Error("Failed to get user role in team", "user_id", user.ID, "team_id", teamID, "error", err)
		writeError(w, errors.NewForbiddenError("Access denied to this team"))
		return
	}

	team, err := h.authService.GetTeamByID(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to get team", "team_id", teamID, "error", err)
		if err.Error() == "team not found" {
			writeError(w, errors.NewNotFoundError("Team not found"))
			return
		}
		writeError(w, errors.InternalError("Failed to get team"))
		return
	}

	// Check if team belongs to user's organization
	if team.OrganizationID != user.OrganizationID {
		writeError(w, errors.NewForbiddenError("Access denied to this team"))
		return
	}

	// Get team statistics
	memberCount, err := h.authService.GetTeamMemberCount(r.Context(), team.ID)
	if err != nil {
		h.logger.Error("Failed to get team member count", "team_id", team.ID, "error", err)
		memberCount = 0 // Default to 0 on error
	}

	// Get team owner
	owner, err := h.authService.GetTeamOwner(r.Context(), team.ID)
	if err != nil {
		h.logger.Error("Failed to get team owner", "team_id", team.ID, "error", err)
		owner = nil // Set to nil on error
	}

	response := &TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Description: team.Description,
		Settings:    team.Settings,
		MemberCount: memberCount,
		CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UserRole:    userRole,
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

// CreateTeam creates a new team (admin+ only)
func (h *TeamHandler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Check if user has permission to create teams
	if user.Role == auth.RoleViewer || user.Role == auth.RoleMember {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to create teams"))
		return
	}

	var req CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	team, err := h.authService.CreateTeam(r.Context(), user.OrganizationID, user.ID, &req, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to create team", "org_id", user.OrganizationID, "name", req.Name, "error", err)
		if err.Error() == "team name already exists" {
			writeError(w, errors.NewValidationError("A team with this name already exists"))
			return
		}
		writeError(w, errors.InternalError("Failed to create team"))
		return
	}

	h.logger.Info("Team created successfully", "team_id", team.ID, "name", team.Name, "created_by", user.ID)

	response := &TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Description: team.Description,
		Settings:    team.Settings,
		MemberCount: 1, // Creator is the first member
		CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UserRole:    auth.RoleOwner, // Creator becomes team owner
		Owner: &UserSummary{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			FullName:  user.FirstName + " " + user.LastName,
		},
	}

	writeSuccess(w, http.StatusCreated, response)
}

// UpdateTeam updates team details (team admin+ only)
func (h *TeamHandler) UpdateTeam(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	// Check if user has permission to update this team
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil || (userRole != auth.RoleOwner && userRole != auth.RoleAdmin) {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to update this team"))
		return
	}

	var req UpdateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	err = h.authService.UpdateTeam(r.Context(), teamID, &req, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to update team", "team_id", teamID, "error", err)
		if err.Error() == "team not found" {
			writeError(w, errors.NewNotFoundError("Team not found"))
			return
		}
		writeError(w, errors.InternalError("Failed to update team"))
		return
	}

	// Get updated team
	team, err := h.authService.GetTeamByID(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to get updated team", "team_id", teamID, "error", err)
		writeError(w, errors.InternalError("Failed to get updated team"))
		return
	}

	h.logger.Info("Team updated successfully", "team_id", teamID, "updated_by", user.ID)

	response := &TeamResponse{
		ID:          team.ID,
		Name:        team.Name,
		Description: team.Description,
		Settings:    team.Settings,
		CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UserRole:    userRole,
	}

	writeSuccess(w, http.StatusOK, response)
}

// GetTeamMembers returns team members (team member+ only)
func (h *TeamHandler) GetTeamMembers(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	// Check if user has access to this team
	_, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil {
		writeError(w, errors.NewForbiddenError("Access denied to this team"))
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

	members, total, err := h.authService.GetTeamMembers(r.Context(), teamID, page, limit)
	if err != nil {
		h.logger.Error("Failed to get team members", "team_id", teamID, "error", err)
		writeError(w, errors.InternalError("Failed to get team members"))
		return
	}

	var memberResponses []TeamMemberResponse
	for _, membership := range members {
		member := membership.User
		
		var lastLoginStr *string
		if member.LastLoginAt != nil {
			str := member.LastLoginAt.Format("2006-01-02T15:04:05Z07:00")
			lastLoginStr = &str
		}

		memberResponses = append(memberResponses, TeamMemberResponse{
			ID:            member.ID,
			Email:         member.Email,
			FirstName:     member.FirstName,
			LastName:      member.LastName,
			FullName:      member.FirstName + " " + member.LastName,
			Role:          membership.Role,
			Status:        member.Status,
			EmailVerified: member.EmailVerified,
			JoinedAt:      membership.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastLoginAt:   lastLoginStr,
		})
	}

	response := map[string]interface{}{
		"members": memberResponses,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + limit - 1) / limit,
		},
	}

	writeSuccess(w, http.StatusOK, response)
}

// AddTeamMember adds a user to the team (team admin+ only)
func (h *TeamHandler) AddTeamMember(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	// Check if user has permission to add members to this team
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil || (userRole != auth.RoleOwner && userRole != auth.RoleAdmin) {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to add members to this team"))
		return
	}

	var req AddTeamMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate role - can't assign someone with higher privileges than yourself
	if (userRole == auth.RoleAdmin && req.Role == auth.RoleOwner) {
		writeError(w, errors.NewValidationError("Cannot assign role with higher privileges"))
		return
	}

	err = h.authService.AddUserToTeam(r.Context(), teamID, req.UserID, req.Role, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to add user to team", "team_id", teamID, "user_id", req.UserID, "role", req.Role, "error", err)
		if err.Error() == "user not found" {
			writeError(w, errors.NewNotFoundError("User not found"))
			return
		}
		if err.Error() == "user already in team" {
			writeError(w, errors.NewValidationError("User is already a member of this team"))
			return
		}
		if err.Error() == "user not in organization" {
			writeError(w, errors.NewValidationError("User is not a member of this organization"))
			return
		}
		writeError(w, errors.InternalError("Failed to add user to team"))
		return
	}

	h.logger.Info("User added to team", "team_id", teamID, "user_id", req.UserID, "role", req.Role, "added_by", user.ID)

	response := map[string]interface{}{
		"message": "User added to team successfully",
		"user_id": req.UserID,
		"role":    req.Role,
	}

	writeSuccess(w, http.StatusCreated, response)
}

// UpdateTeamMemberRole updates a team member's role (team admin+ only)
func (h *TeamHandler) UpdateTeamMemberRole(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	memberID := vars["memberID"]
	if teamID == "" || memberID == "" {
		writeError(w, errors.NewValidationError("Team ID and Member ID are required"))
		return
	}

	// Check if user has permission to update member roles in this team
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil || (userRole != auth.RoleOwner && userRole != auth.RoleAdmin) {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to update member roles in this team"))
		return
	}

	var req UpdateTeamMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Validate role - can't assign someone with higher privileges than yourself
	if (userRole == auth.RoleAdmin && req.Role == auth.RoleOwner) {
		writeError(w, errors.NewValidationError("Cannot assign role with higher privileges"))
		return
	}

	// Can't update your own role
	if memberID == user.ID {
		writeError(w, errors.NewValidationError("Cannot update your own role"))
		return
	}

	err = h.authService.UpdateTeamMemberRole(r.Context(), teamID, memberID, req.Role, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to update team member role", "team_id", teamID, "member_id", memberID, "new_role", req.Role, "error", err)
		if err.Error() == "member not found in team" {
			writeError(w, errors.NewNotFoundError("Member not found in team"))
			return
		}
		writeError(w, errors.InternalError("Failed to update member role"))
		return
	}

	h.logger.Info("Team member role updated", "team_id", teamID, "member_id", memberID, "new_role", req.Role, "updated_by", user.ID)

	response := map[string]interface{}{
		"message":   "Team member role updated successfully",
		"member_id": memberID,
		"new_role":  req.Role,
	}

	writeSuccess(w, http.StatusOK, response)
}

// RemoveTeamMember removes a member from the team (team admin+ only)
func (h *TeamHandler) RemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	memberID := vars["memberID"]
	if teamID == "" || memberID == "" {
		writeError(w, errors.NewValidationError("Team ID and Member ID are required"))
		return
	}

	// Check if user has permission to remove members from this team
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil || (userRole != auth.RoleOwner && userRole != auth.RoleAdmin) {
		writeError(w, errors.NewForbiddenError("Insufficient permissions to remove members from this team"))
		return
	}

	err = h.authService.RemoveUserFromTeam(r.Context(), teamID, memberID, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to remove member from team", "team_id", teamID, "member_id", memberID, "error", err)
		if err.Error() == "member not found in team" {
			writeError(w, errors.NewNotFoundError("Member not found in team"))
			return
		}
		if err.Error() == "cannot remove team owner" {
			writeError(w, errors.NewValidationError("Cannot remove team owner. Transfer ownership first."))
			return
		}
		writeError(w, errors.InternalError("Failed to remove member from team"))
		return
	}

	h.logger.Info("Member removed from team", "team_id", teamID, "member_id", memberID, "removed_by", user.ID)

	response := map[string]interface{}{
		"message":   "Member removed from team successfully",
		"member_id": memberID,
	}

	writeSuccess(w, http.StatusOK, response)
}

// DeleteTeam deletes a team (team owner only)
func (h *TeamHandler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	vars := mux.Vars(r)
	teamID := vars["teamID"]
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	// Check if user has permission to delete this team (only team owner can delete)
	userRole, err := h.authService.GetUserRoleInTeam(r.Context(), user.ID, teamID)
	if err != nil || userRole != auth.RoleOwner {
		writeError(w, errors.NewForbiddenError("Only team owner can delete the team"))
		return
	}

	err = h.authService.DeleteTeam(r.Context(), teamID, getClientIP(r))
	if err != nil {
		h.logger.Error("Failed to delete team", "team_id", teamID, "error", err)
		if err.Error() == "team not found" {
			writeError(w, errors.NewNotFoundError("Team not found"))
			return
		}
		if err.Error() == "cannot delete default team" {
			writeError(w, errors.NewValidationError("Cannot delete the default team"))
			return
		}
		writeError(w, errors.InternalError("Failed to delete team"))
		return
	}

	h.logger.Info("Team deleted successfully", "team_id", teamID, "deleted_by", user.ID)

	response := map[string]interface{}{
		"message": "Team deleted successfully",
		"team_id": teamID,
	}

	writeSuccess(w, http.StatusOK, response)
}