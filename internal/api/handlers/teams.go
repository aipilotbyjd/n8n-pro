package handlers

import (
	"encoding/json"
	"net/http"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/teams"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TeamsHandler handles team-related HTTP requests
type TeamsHandler struct {
	service *teams.Service
	logger  logger.Logger
}

// NewTeamsHandler creates a new teams handler
func NewTeamsHandler(service *teams.Service, logger logger.Logger) *TeamsHandler {
	return &TeamsHandler{
		service: service,
		logger:  logger,
	}
}

// TeamsCreateRequest represents the request to create a team (teams service)
type TeamsCreateRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Description string `json:"description,omitempty" validate:"max=500"`
	PlanType    string `json:"plan_type,omitempty" validate:"oneof=free pro enterprise"`
}

// TeamsUpdateRequest represents the request to update a team (teams service)
type TeamsUpdateRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=500"`
	PlanType    *string `json:"plan_type,omitempty" validate:"omitempty,oneof=free pro enterprise"`
	Active      *bool   `json:"active,omitempty"`
}

// AddMemberRequest represents the request to add a team member
type AddMemberRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Role   string `json:"role" validate:"required,oneof=admin member viewer"`
}

// TeamsResponse represents a team in API responses (teams service)
type TeamsResponse struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	OwnerID     string                   `json:"owner_id"`
	PlanType    string                   `json:"plan_type"`
	Active      bool                     `json:"active"`
	Settings    map[string]interface{}   `json:"settings"`
	Members     []TeamsMemberResponse    `json:"members,omitempty"`
	Stats       *TeamsStatsResponse      `json:"stats,omitempty"`
	CreatedAt   string                   `json:"created_at"`
	UpdatedAt   string                   `json:"updated_at"`
}

// TeamsMemberResponse represents a team member in API responses (teams service)
type TeamsMemberResponse struct {
	ID       string `json:"id"`
	TeamID   string `json:"team_id"`
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	JoinedAt string `json:"joined_at"`
}

// TeamsStatsResponse represents team statistics (teams service)
type TeamsStatsResponse struct {
	MemberCount      int `json:"member_count"`
	WorkflowCount    int `json:"workflow_count"`
	ExecutionCount   int `json:"execution_count"`
	CredentialCount  int `json:"credential_count"`
}

// CreateTeam creates a new team
func (h *TeamsHandler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	var req TeamsCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in create team request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	// Get current user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Create team
	team := &teams.Team{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     userCtx.ID,
		PlanType:    req.PlanType,
		Active:      true,
		Settings:    "{}",
	}

	if team.PlanType == "" {
		team.PlanType = "free"
	}

	err := h.service.CreateTeam(r.Context(), team)
	if err != nil {
		h.logger.Error("Failed to create team", "error", err, "user_id", userCtx.ID)
		writeError(w, err)
		return
	}

	// Add creator as admin member
	member := &teams.TeamMember{
		ID:     uuid.New().String(),
		TeamID: team.ID,
		UserID: userCtx.ID,
		Role:   "admin",
	}

	err = h.service.AddMember(r.Context(), member)
	if err != nil {
		h.logger.Error("Failed to add creator as team member", "error", err, "team_id", team.ID)
		// Continue anyway, team is created
	}

	// Return team
	response := h.teamToResponse(team)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"team": response,
	})

	h.logger.Info("Team created successfully", "team_id", team.ID, "user_id", userCtx.ID)
}

// ListTeams lists teams for the current user
func (h *TeamsHandler) ListTeams(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	teams, err := h.service.ListTeams(r.Context(), userCtx.ID)
	if err != nil {
		h.logger.Error("Failed to list teams", "error", err, "user_id", userCtx.ID)
		writeError(w, err)
		return
	}

	// Convert to response format
	responses := make([]TeamsResponse, len(teams))
	for i, team := range teams {
		responses[i] = h.teamToResponse(team)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"teams": responses,
		"count": len(responses),
	})
}

// GetTeam retrieves a specific team by ID
func (h *TeamsHandler) GetTeam(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	team, err := h.service.GetTeamByID(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to get team", "error", err, "team_id", teamID)
		writeError(w, err)
		return
	}

	// Get team members
	members, err := h.service.ListMembers(r.Context(), teamID)
	if err != nil {
		h.logger.Warn("Failed to get team members", "error", err, "team_id", teamID)
		// Continue without members
	}

	response := h.teamToResponse(team)
	if members != nil {
		response.Members = h.membersToResponse(members)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"team": response,
	})
}

// UpdateTeam updates a team
func (h *TeamsHandler) UpdateTeam(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	var req TeamsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in update team request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get existing team
	team, err := h.service.GetTeamByID(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to get team for update", "error", err, "team_id", teamID)
		writeError(w, err)
		return
	}

	// Update fields
	if req.Name != nil {
		team.Name = *req.Name
	}
	if req.Description != nil {
		team.Description = *req.Description
	}
	if req.PlanType != nil {
		team.PlanType = *req.PlanType
	}
	if req.Active != nil {
		team.Active = *req.Active
	}

	err = h.service.UpdateTeam(r.Context(), team)
	if err != nil {
		h.logger.Error("Failed to update team", "error", err, "team_id", teamID)
		writeError(w, err)
		return
	}

	response := h.teamToResponse(team)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"team": response,
	})

	h.logger.Info("Team updated successfully", "team_id", teamID, "user_id", userCtx.ID)
}

// DeleteTeam deletes a team
func (h *TeamsHandler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	err := h.service.DeleteTeam(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to delete team", "error", err, "team_id", teamID)
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.logger.Info("Team deleted successfully", "team_id", teamID, "user_id", userCtx.ID)
}

// AddMember adds a member to a team
func (h *TeamsHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in add member request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	member := &teams.TeamMember{
		ID:     uuid.New().String(),
		TeamID: teamID,
		UserID: req.UserID,
		Role:   req.Role,
	}

	err := h.service.AddMember(r.Context(), member)
	if err != nil {
		h.logger.Error("Failed to add team member", "error", err, "team_id", teamID, "user_id", req.UserID)
		writeError(w, err)
		return
	}

	response := h.memberToResponse(member)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"member": response,
	})

	h.logger.Info("Team member added successfully", "team_id", teamID, "member_user_id", req.UserID)
}

// RemoveMember removes a member from a team
func (h *TeamsHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	memberUserID := chi.URLParam(r, "user_id")
	
	if teamID == "" || memberUserID == "" {
		writeError(w, errors.NewValidationError("Team ID and User ID are required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	err := h.service.RemoveMember(r.Context(), teamID, memberUserID)
	if err != nil {
		h.logger.Error("Failed to remove team member", "error", err, "team_id", teamID, "user_id", memberUserID)
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.logger.Info("Team member removed successfully", "team_id", teamID, "member_user_id", memberUserID)
}

// ListMembers lists members of a team
func (h *TeamsHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	teamID := chi.URLParam(r, "id")
	if teamID == "" {
		writeError(w, errors.NewValidationError("Team ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	members, err := h.service.ListMembers(r.Context(), teamID)
	if err != nil {
		h.logger.Error("Failed to list team members", "error", err, "team_id", teamID)
		writeError(w, err)
		return
	}

	responses := h.membersToResponse(members)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"members": responses,
		"count":   len(responses),
	})
}

// Helper methods

func (h *TeamsHandler) teamToResponse(team *teams.Team) TeamsResponse {
	var settings map[string]interface{}
	if team.Settings != "" {
		json.Unmarshal([]byte(team.Settings), &settings)
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}

return TeamsResponse{
		ID:          team.ID,
		Name:        team.Name,
		Description: team.Description,
		OwnerID:     team.OwnerID,
		PlanType:    team.PlanType,
		Active:      team.Active,
		Settings:    settings,
		CreatedAt:   team.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   team.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (h *TeamsHandler) memberToResponse(member *teams.TeamMember) TeamsMemberResponse {
return TeamsMemberResponse{
		ID:       member.ID,
		TeamID:   member.TeamID,
		UserID:   member.UserID,
		Role:     member.Role,
		JoinedAt: member.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (h *TeamsHandler) membersToResponse(members []*teams.TeamMember) []TeamsMemberResponse {
responses := make([]TeamsMemberResponse, len(members))
	for i, member := range members {
		responses[i] = h.memberToResponse(member)
	}
	return responses
}