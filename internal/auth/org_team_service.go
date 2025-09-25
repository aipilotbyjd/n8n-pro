package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/common"
	"n8n-pro/pkg/errors"
)

// Organization Management Methods

// GetOrganizationByID gets an organization by ID
func (s *EnhancedAuthService) GetOrganizationByID(ctx context.Context, orgID string) (*Organization, error) {
	return s.orgRepo.GetOrganizationByID(ctx, orgID)
}

// UpdateOrganization updates organization details
func (s *EnhancedAuthService) UpdateOrganization(ctx context.Context, orgID string, req interface{}) error {
	// Cast to the appropriate update request type
	updateReq, ok := req.(*UpdateOrganizationRequest)
	if !ok {
		// Handle other update request types or create a generic interface
		return errors.NewValidationError("Invalid update request type")
	}

	org, err := s.orgRepo.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return err
	}

	// Update fields if provided
	updated := false
	if updateReq.Name != nil && *updateReq.Name != org.Name {
		org.Name = *updateReq.Name
		org.Slug = generateOrgSlug(*updateReq.Name) // Regenerate slug
		updated = true
	}
	if updateReq.Description != nil && *updateReq.Description != *org.Description {
		org.Description = updateReq.Description
		updated = true
	}
	if updateReq.Settings != nil {
		org.Settings = updateReq.Settings
		updated = true
	}

	if updated {
		org.UpdatedAt = time.Now()
		return s.orgRepo.UpdateOrganization(ctx, org)
	}

	return nil
}

// GetOrganizationMemberCount gets the count of organization members
func (s *EnhancedAuthService) GetOrganizationMemberCount(ctx context.Context, orgID string) (int, error) {
	return s.userRepo.GetOrganizationMemberCount(ctx, orgID)
}

// GetOrganizationTeamCount gets the count of organization teams
func (s *EnhancedAuthService) GetOrganizationTeamCount(ctx context.Context, orgID string) (int, error) {
	return s.teamRepo.GetOrganizationTeamCount(ctx, orgID)
}

// GetOrganizationOwner gets the organization owner
func (s *EnhancedAuthService) GetOrganizationOwner(ctx context.Context, orgID string) (*EnhancedUser, error) {
	return s.userRepo.GetOrganizationOwner(ctx, orgID)
}

// GetOrganizationMembers gets paginated organization members
func (s *EnhancedAuthService) GetOrganizationMembers(ctx context.Context, orgID string, page, limit int) ([]*EnhancedUser, int, error) {
	offset := (page - 1) * limit
	members, err := s.userRepo.GetOrganizationMembers(ctx, orgID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.userRepo.GetOrganizationMemberCount(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return members, total, nil
}

// InviteUser invites a user to the organization
func (s *EnhancedAuthService) InviteUser(ctx context.Context, orgID, inviterID, email string, role RoleType, teamIDs []string, message *string, ipAddress string) (*Invitation, error) {
	// Check if user already exists in the organization
	existingUser, err := s.userRepo.GetUserByEmail(ctx, strings.ToLower(email))
	if err == nil && existingUser.OrganizationID == orgID {
		return nil, fmt.Errorf("user already exists in organization")
	}

	// Generate invitation token
	token, err := generateInvitationToken()
	if err != nil {
		return nil, errors.InternalError("Failed to generate invitation token")
	}

	invitation := &Invitation{
		ID:             common.GenerateID(),
		OrganizationID: orgID,
		InviterID:      inviterID,
		Email:          strings.ToLower(email),
		Role:           role,
		Token:          token,
		Status:         InviteStatusPending,
		ExpiresAt:      time.Now().Add(7 * 24 * time.Hour), // 7 days
		Metadata:       map[string]interface{}{},
	}

	if message != nil {
		invitation.Metadata["message"] = *message
	}

	if len(teamIDs) > 0 {
		// For simplicity, we'll use the first team ID as the primary team
		invitation.TeamID = &teamIDs[0]
	}

	err = s.invitationRepo.CreateInvitation(ctx, invitation)
	if err != nil {
		return nil, err
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, &inviterID, "user.invited", "invitation", invitation.ID, map[string]interface{}{
		"email": email,
		"role":  role,
	}, ipAddress, "user-invitation")

	return invitation, nil
}

// UpdateMemberRole updates a member's role
func (s *EnhancedAuthService) UpdateMemberRole(ctx context.Context, orgID, memberID string, role RoleType, ipAddress string) error {
	user, err := s.userRepo.GetUserByID(ctx, memberID)
	if err != nil {
		return fmt.Errorf("member not found")
	}

	if user.OrganizationID != orgID {
		return fmt.Errorf("member not found")
	}

	user.Role = role
	user.UpdatedAt = time.Now()

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return err
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, nil, "member.role_updated", "user", memberID, map[string]interface{}{
		"new_role": role,
	}, ipAddress, "member-role-update")

	return nil
}

// RemoveOrganizationMember removes a member from the organization
func (s *EnhancedAuthService) RemoveOrganizationMember(ctx context.Context, orgID, memberID string, ipAddress string) error {
	user, err := s.userRepo.GetUserByID(ctx, memberID)
	if err != nil {
		return fmt.Errorf("member not found")
	}

	if user.OrganizationID != orgID {
		return fmt.Errorf("member not found")
	}

	if user.Role == RoleOwner {
		return fmt.Errorf("cannot remove organization owner")
	}

	// Remove user from all teams first
	teams, err := s.teamRepo.GetUserTeamMemberships(ctx, memberID)
	if err == nil {
		for _, team := range teams {
			s.teamRepo.RemoveUserFromTeam(ctx, team.TeamID, memberID)
		}
	}

	// Deactivate user instead of deleting
	user.Status = UserStatusInactive
	user.UpdatedAt = time.Now()

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return err
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, nil, "member.removed", "user", memberID, map[string]interface{}{
		"email": user.Email,
	}, ipAddress, "member-removal")

	return nil
}

// CreateAuditLog creates an audit log entry (public method)
func (s *EnhancedAuthService) CreateAuditLog(ctx context.Context, orgID string, userID *string, action, resourceType, resourceID string, metadata map[string]interface{}, ipAddress, userAgent string) {
	s.createAuditLog(ctx, orgID, userID, action, resourceType, resourceID, metadata, ipAddress, userAgent)
}

// Team Management Methods

// GetTeamByID gets a team by ID
func (s *EnhancedAuthService) GetTeamByID(ctx context.Context, teamID string) (*Team, error) {
	return s.teamRepo.GetTeamByID(ctx, teamID)
}

// GetUserTeamMemberships gets user's team memberships
func (s *EnhancedAuthService) GetUserTeamMemberships(ctx context.Context, userID string) ([]*TeamMembership, error) {
	return s.teamRepo.GetUserTeamMemberships(ctx, userID)
}

// GetOrganizationTeams gets paginated teams in an organization
func (s *EnhancedAuthService) GetOrganizationTeams(ctx context.Context, orgID string, page, limit int) ([]*Team, int, error) {
	offset := (page - 1) * limit
	teams, err := s.teamRepo.GetOrganizationTeams(ctx, orgID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.teamRepo.GetOrganizationTeamCount(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return teams, total, nil
}

// GetTeamMemberCount gets the count of team members
func (s *EnhancedAuthService) GetTeamMemberCount(ctx context.Context, teamID string) (int, error) {
	return s.teamRepo.GetTeamMemberCount(ctx, teamID)
}

// GetTeamOwner gets the team owner
func (s *EnhancedAuthService) GetTeamOwner(ctx context.Context, teamID string) (*EnhancedUser, error) {
	return s.teamRepo.GetTeamOwner(ctx, teamID)
}

// GetUserRoleInTeam gets user's role in a specific team
func (s *EnhancedAuthService) GetUserRoleInTeam(ctx context.Context, userID, teamID string) (RoleType, error) {
	membership, err := s.teamRepo.GetTeamMembership(ctx, teamID, userID)
	if err != nil {
		return "", fmt.Errorf("user not found in team")
	}
	return membership.Role, nil
}

// CreateTeam creates a new team
func (s *EnhancedAuthService) CreateTeam(ctx context.Context, orgID, creatorID string, req interface{}, ipAddress string) (*Team, error) {
	// Cast to the appropriate request type
	createReq, ok := req.(*CreateTeamRequest)
	if !ok {
		return nil, errors.NewValidationError("Invalid create request type")
	}

	// Check if team name already exists in the organization
	existing, err := s.teamRepo.GetTeamByName(ctx, orgID, createReq.Name)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("team name already exists")
	}

	team := &Team{
		ID:             common.GenerateID(),
		OrganizationID: orgID,
		Name:           createReq.Name,
		Description:    createReq.Description,
		Settings:       createReq.Settings,
	}

	if team.Settings == nil {
		team.Settings = getDefaultTeamSettings()
	}

	err = s.teamRepo.CreateTeam(ctx, team)
	if err != nil {
		return nil, err
	}

	// Add creator as team owner
	membership := &TeamMembership{
		ID:       common.GenerateID(),
		TeamID:   team.ID,
		UserID:   creatorID,
		Role:     RoleOwner,
		JoinedAt: time.Now(),
	}

	err = s.teamRepo.AddUserToTeam(ctx, membership)
	if err != nil {
		// Rollback team creation
		s.teamRepo.DeleteTeam(ctx, team.ID)
		return nil, err
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, &creatorID, "team.created", "team", team.ID, map[string]interface{}{
		"name": team.Name,
	}, ipAddress, "team-creation")

	return team, nil
}

// UpdateTeam updates team details
func (s *EnhancedAuthService) UpdateTeam(ctx context.Context, teamID string, req interface{}, ipAddress string) error {
	// Cast to the appropriate update request type
	updateReq, ok := req.(*UpdateTeamRequest)
	if !ok {
		return errors.NewValidationError("Invalid update request type")
	}

	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil {
		return fmt.Errorf("team not found")
	}

	// Update fields if provided
	updated := false
	if updateReq.Name != nil && *updateReq.Name != team.Name {
		team.Name = *updateReq.Name
		updated = true
	}
	if updateReq.Description != nil {
		team.Description = updateReq.Description
		updated = true
	}
	if updateReq.Settings != nil {
		team.Settings = updateReq.Settings
		updated = true
	}

	if updated {
		team.UpdatedAt = time.Now()
		return s.teamRepo.UpdateTeam(ctx, team)
	}

	return nil
}

// GetTeamMembers gets paginated team members
func (s *EnhancedAuthService) GetTeamMembers(ctx context.Context, teamID string, page, limit int) ([]*TeamMembership, int, error) {
	offset := (page - 1) * limit
	members, err := s.teamRepo.GetTeamMembers(ctx, teamID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.teamRepo.GetTeamMemberCount(ctx, teamID)
	if err != nil {
		return nil, 0, err
	}

	return members, total, nil
}

// AddUserToTeam adds a user to a team
func (s *EnhancedAuthService) AddUserToTeam(ctx context.Context, teamID, userID string, role RoleType, ipAddress string) error {
	// Check if user exists and get their organization
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Get team to verify organization
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil {
		return fmt.Errorf("team not found")
	}

	// Check if user belongs to the same organization
	if user.OrganizationID != team.OrganizationID {
		return fmt.Errorf("user not in organization")
	}

	// Check if user is already in the team
	existing, err := s.teamRepo.GetTeamMembership(ctx, teamID, userID)
	if err == nil && existing != nil {
		return fmt.Errorf("user already in team")
	}

	membership := &TeamMembership{
		ID:       common.GenerateID(),
		TeamID:   teamID,
		UserID:   userID,
		Role:     role,
		JoinedAt: time.Now(),
	}

	err = s.teamRepo.AddUserToTeam(ctx, membership)
	if err != nil {
		return err
	}

	// Create audit log
	s.createAuditLog(ctx, team.OrganizationID, nil, "team.member_added", "team_membership", membership.ID, map[string]interface{}{
		"team_id": teamID,
		"user_id": userID,
		"role":    role,
	}, ipAddress, "team-member-addition")

	return nil
}

// UpdateTeamMemberRole updates a team member's role
func (s *EnhancedAuthService) UpdateTeamMemberRole(ctx context.Context, teamID, memberID string, role RoleType, ipAddress string) error {
	membership, err := s.teamRepo.GetTeamMembership(ctx, teamID, memberID)
	if err != nil {
		return fmt.Errorf("member not found in team")
	}

	membership.Role = role
	err = s.teamRepo.UpdateTeamMembership(ctx, membership)
	if err != nil {
		return err
	}

	// Get team for organization ID
	team, _ := s.teamRepo.GetTeamByID(ctx, teamID)
	orgID := ""
	if team != nil {
		orgID = team.OrganizationID
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, nil, "team.member_role_updated", "team_membership", membership.ID, map[string]interface{}{
		"team_id":  teamID,
		"user_id":  memberID,
		"new_role": role,
	}, ipAddress, "team-member-role-update")

	return nil
}

// RemoveUserFromTeam removes a user from a team
func (s *EnhancedAuthService) RemoveUserFromTeam(ctx context.Context, teamID, memberID string, ipAddress string) error {
	membership, err := s.teamRepo.GetTeamMembership(ctx, teamID, memberID)
	if err != nil {
		return fmt.Errorf("member not found in team")
	}

	if membership.Role == RoleOwner {
		return fmt.Errorf("cannot remove team owner")
	}

	err = s.teamRepo.RemoveUserFromTeam(ctx, teamID, memberID)
	if err != nil {
		return err
	}

	// Get team for organization ID
	team, _ := s.teamRepo.GetTeamByID(ctx, teamID)
	orgID := ""
	if team != nil {
		orgID = team.OrganizationID
	}

	// Create audit log
	s.createAuditLog(ctx, orgID, nil, "team.member_removed", "team_membership", membership.ID, map[string]interface{}{
		"team_id": teamID,
		"user_id": memberID,
	}, ipAddress, "team-member-removal")

	return nil
}

// DeleteTeam deletes a team
func (s *EnhancedAuthService) DeleteTeam(ctx context.Context, teamID string, ipAddress string) error {
	team, err := s.teamRepo.GetTeamByID(ctx, teamID)
	if err != nil {
		return fmt.Errorf("team not found")
	}

	// Check if it's the default team (by name convention)
	if team.Name == "Default Team" {
		return fmt.Errorf("cannot delete default team")
	}

	// Remove all team memberships first
	members, err := s.teamRepo.GetTeamMembers(ctx, teamID, 1000, 0) // Get all members
	if err == nil {
		for _, member := range members {
			s.teamRepo.RemoveUserFromTeam(ctx, teamID, member.UserID)
		}
	}

	err = s.teamRepo.DeleteTeam(ctx, teamID)
	if err != nil {
		return err
	}

	// Create audit log
	s.createAuditLog(ctx, team.OrganizationID, nil, "team.deleted", "team", teamID, map[string]interface{}{
		"name": team.Name,
	}, ipAddress, "team-deletion")

	return nil
}

// Helper methods

// generateInvitationToken generates a secure invitation token
func generateInvitationToken() (string, error) {
	return generateSecureToken(32)
}

// getDefaultTeamSettings returns default team settings
func getDefaultTeamSettings() map[string]interface{} {
	return map[string]interface{}{
		"workflow_execution_timeout": 600,
		"max_workflow_executions":    1000,
		"enable_debug_logs":          false,
		"auto_cleanup_executions":    true,
		"cleanup_execution_days":     30,
	}
}

// Helper types (these should be defined where request types are defined, but including here for completeness)

type UpdateOrganizationRequest struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type CreateTeamRequest struct {
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type UpdateTeamRequest struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}