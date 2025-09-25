package auth

import (
	"context"
	"fmt"
	"time"
)

// Simple in-memory repository implementations for getting the API server running
// These can be replaced with proper database implementations later

// SimpleUserRepository provides basic user operations
type SimpleUserRepository struct {
	users map[string]*EnhancedUser
}

// NewSimpleUserRepository creates a new simple user repository
func NewSimpleUserRepository() *SimpleUserRepository {
	return &SimpleUserRepository{
		users: make(map[string]*EnhancedUser),
	}
}

// CreateUser creates a new user
func (r *SimpleUserRepository) CreateUser(ctx context.Context, user *EnhancedUser) error {
	if _, exists := r.users[user.ID]; exists {
		return fmt.Errorf("user already exists")
	}
	r.users[user.ID] = user
	return nil
}

// GetUserByID gets a user by ID
func (r *SimpleUserRepository) GetUserByID(ctx context.Context, userID string) (*EnhancedUser, error) {
	if user, exists := r.users[userID]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

// GetUserByEmail gets a user by email
func (r *SimpleUserRepository) GetUserByEmail(ctx context.Context, email string) (*EnhancedUser, error) {
	for _, user := range r.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// UpdateUser updates a user
func (r *SimpleUserRepository) UpdateUser(ctx context.Context, user *EnhancedUser) error {
	if _, exists := r.users[user.ID]; !exists {
		return fmt.Errorf("user not found")
	}
	r.users[user.ID] = user
	return nil
}

// GetOrganizationMembers gets organization members (simplified)
func (r *SimpleUserRepository) GetOrganizationMembers(ctx context.Context, orgID string, limit, offset int) ([]*EnhancedUser, error) {
	var members []*EnhancedUser
	count := 0
	for _, user := range r.users {
		if user.OrganizationID == orgID {
			if count >= offset && len(members) < limit {
				members = append(members, user)
			}
			count++
		}
	}
	return members, nil
}

// ClearAccountLock clears account lock for user
func (r *SimpleUserRepository) ClearAccountLock(ctx context.Context, userID string) error {
	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	return nil
}

// DeleteUser deletes a user
func (r *SimpleUserRepository) DeleteUser(ctx context.Context, userID string) error {
	if _, exists := r.users[userID]; !exists {
		return fmt.Errorf("user not found")
	}
	delete(r.users, userID)
	return nil
}

// SimpleTeamRepository provides basic team operations
type SimpleTeamRepository struct {
	teams       map[string]*Team
	memberships map[string]*TeamMembership
}

// NewSimpleTeamRepository creates a new simple team repository
func NewSimpleTeamRepository() *SimpleTeamRepository {
	return &SimpleTeamRepository{
		teams:       make(map[string]*Team),
		memberships: make(map[string]*TeamMembership),
	}
}

// CreateTeam creates a new team
func (r *SimpleTeamRepository) CreateTeam(ctx context.Context, team *Team) error {
	if _, exists := r.teams[team.ID]; exists {
		return fmt.Errorf("team already exists")
	}
	r.teams[team.ID] = team
	return nil
}

// GetTeamByID gets a team by ID
func (r *SimpleTeamRepository) GetTeamByID(ctx context.Context, teamID string) (*Team, error) {
	if team, exists := r.teams[teamID]; exists {
		return team, nil
	}
	return nil, fmt.Errorf("team not found")
}

// GetTeamByName gets a team by name
func (r *SimpleTeamRepository) GetTeamByName(ctx context.Context, organizationID, name string) (*Team, error) {
	for _, team := range r.teams {
		if team.OrganizationID == organizationID && team.Name == name {
			return team, nil
		}
	}
	return nil, fmt.Errorf("team not found")
}

// UpdateTeam updates a team
func (r *SimpleTeamRepository) UpdateTeam(ctx context.Context, team *Team) error {
	if _, exists := r.teams[team.ID]; !exists {
		return fmt.Errorf("team not found")
	}
	r.teams[team.ID] = team
	return nil
}

// DeleteTeam deletes a team
func (r *SimpleTeamRepository) DeleteTeam(ctx context.Context, teamID string) error {
	if _, exists := r.teams[teamID]; !exists {
		return fmt.Errorf("team not found")
	}
	delete(r.teams, teamID)
	return nil
}

// GetOrganizationTeams gets teams in an organization
func (r *SimpleTeamRepository) GetOrganizationTeams(ctx context.Context, organizationID string) ([]*Team, error) {
	var teams []*Team
	for _, team := range r.teams {
		if team.OrganizationID == organizationID {
			teams = append(teams, team)
		}
	}
	return teams, nil
}

// GetTeamsByOrganization gets teams in an organization (alias for GetOrganizationTeams)
func (r *SimpleTeamRepository) GetTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	return r.GetOrganizationTeams(ctx, orgID)
}

// AddUserToTeam adds a user to a team
func (r *SimpleTeamRepository) AddUserToTeam(ctx context.Context, membership *TeamMembership) error {
	key := fmt.Sprintf("%s:%s", membership.TeamID, membership.UserID)
	if _, exists := r.memberships[key]; exists {
		return fmt.Errorf("user already in team")
	}
	r.memberships[key] = membership
	return nil
}

// RemoveUserFromTeam removes a user from a team
func (r *SimpleTeamRepository) RemoveUserFromTeam(ctx context.Context, teamID, userID string) error {
	key := fmt.Sprintf("%s:%s", teamID, userID)
	if _, exists := r.memberships[key]; !exists {
		return fmt.Errorf("user not in team")
	}
	delete(r.memberships, key)
	return nil
}

// GetTeamMembership gets a team membership
func (r *SimpleTeamRepository) GetTeamMembership(ctx context.Context, teamID, userID string) (*TeamMembership, error) {
	key := fmt.Sprintf("%s:%s", teamID, userID)
	if membership, exists := r.memberships[key]; exists {
		return membership, nil
	}
	return nil, fmt.Errorf("membership not found")
}

// UpdateTeamMembership updates a team membership
func (r *SimpleTeamRepository) UpdateTeamMembership(ctx context.Context, membership *TeamMembership) error {
	key := fmt.Sprintf("%s:%s", membership.TeamID, membership.UserID)
	if _, exists := r.memberships[key]; !exists {
		return fmt.Errorf("membership not found")
	}
	r.memberships[key] = membership
	return nil
}

// UpdateUserTeamRole updates a user's role in a team
func (r *SimpleTeamRepository) UpdateUserTeamRole(ctx context.Context, teamID, userID string, role RoleType) error {
	key := fmt.Sprintf("%s:%s", teamID, userID)
	if membership, exists := r.memberships[key]; exists {
		membership.Role = role
		return nil
	}
	return fmt.Errorf("membership not found")
}

// GetUserTeamMemberships gets all team memberships for a user
func (r *SimpleTeamRepository) GetUserTeamMemberships(ctx context.Context, userID string) ([]*TeamMembership, error) {
	var memberships []*TeamMembership
	for _, membership := range r.memberships {
		if membership.UserID == userID {
			memberships = append(memberships, membership)
		}
	}
	return memberships, nil
}

// GetTeamMemberships gets all memberships for a team
func (r *SimpleTeamRepository) GetTeamMemberships(ctx context.Context, teamID string) ([]*TeamMembership, error) {
	var memberships []*TeamMembership
	for _, membership := range r.memberships {
		if membership.TeamID == teamID {
			memberships = append(memberships, membership)
		}
	}
	return memberships, nil
}

// GetTeamMembers gets all members of a team
func (r *SimpleTeamRepository) GetTeamMembers(ctx context.Context, teamID string, limit, offset int) ([]*TeamMembership, error) {
	var members []*TeamMembership
	count := 0
	for _, membership := range r.memberships {
		if membership.TeamID == teamID {
			if count >= offset && len(members) < limit {
				members = append(members, membership)
			}
			count++
		}
	}
	return members, nil
}

// GetTeamMemberCount gets the count of team members
func (r *SimpleTeamRepository) GetTeamMemberCount(ctx context.Context, teamID string) (int, error) {
	count := 0
	for _, membership := range r.memberships {
		if membership.TeamID == teamID {
			count++
		}
	}
	return count, nil
}

// GetTeamOwner gets the team owner
func (r *SimpleTeamRepository) GetTeamOwner(ctx context.Context, teamID string) (*TeamMembership, error) {
	for _, membership := range r.memberships {
		if membership.TeamID == teamID && membership.Role == RoleOwner {
			return membership, nil
		}
	}
	return nil, fmt.Errorf("team owner not found")
}

// SimpleOrganizationRepository provides basic organization operations
type SimpleOrganizationRepository struct {
	organizations map[string]*Organization
}

// NewSimpleOrganizationRepository creates a new simple organization repository
func NewSimpleOrganizationRepository() *SimpleOrganizationRepository {
	return &SimpleOrganizationRepository{
		organizations: make(map[string]*Organization),
	}
}

// CreateOrganization creates a new organization
func (r *SimpleOrganizationRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	if _, exists := r.organizations[org.ID]; exists {
		return fmt.Errorf("organization already exists")
	}
	r.organizations[org.ID] = org
	return nil
}

// GetOrganizationByID gets an organization by ID
func (r *SimpleOrganizationRepository) GetOrganizationByID(ctx context.Context, orgID string) (*Organization, error) {
	if org, exists := r.organizations[orgID]; exists {
		return org, nil
	}
	return nil, fmt.Errorf("organization not found")
}

// DeleteOrganization deletes an organization
func (r *SimpleOrganizationRepository) DeleteOrganization(ctx context.Context, orgID string) error {
	if _, exists := r.organizations[orgID]; !exists {
		return fmt.Errorf("organization not found")
	}
	delete(r.organizations, orgID)
	return nil
}

// GetOrganizationByDomain gets organization by domain
func (r *SimpleOrganizationRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	return nil, fmt.Errorf("organization not found for domain: %s", domain)
}

// UpdateOrganization updates an organization
func (r *SimpleOrganizationRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	if _, exists := r.organizations[org.ID]; !exists {
		return fmt.Errorf("organization not found")
	}
	r.organizations[org.ID] = org
	return nil
}

// Simple implementations for other repositories

// SimpleInvitationRepository provides basic invitation operations
type SimpleInvitationRepository struct {
	invitations map[string]*Invitation
}

func NewSimpleInvitationRepository() *SimpleInvitationRepository {
	return &SimpleInvitationRepository{
		invitations: make(map[string]*Invitation),
	}
}

func (r *SimpleInvitationRepository) CreateInvitation(ctx context.Context, invitation *Invitation) error {
	r.invitations[invitation.ID] = invitation
	return nil
}

func (r *SimpleInvitationRepository) GetInvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	for _, invitation := range r.invitations {
		if invitation.Token == token {
			return invitation, nil
		}
	}
	return nil, fmt.Errorf("invitation not found")
}

func (r *SimpleInvitationRepository) UpdateInvitation(ctx context.Context, invitation *Invitation) error {
	if _, exists := r.invitations[invitation.ID]; !exists {
		return fmt.Errorf("invitation not found")
	}
	r.invitations[invitation.ID] = invitation
	return nil
}

// AcceptInvitation accepts an invitation
func (r *SimpleInvitationRepository) AcceptInvitation(ctx context.Context, invitationID, userID string) error {
	invitation, exists := r.invitations[invitationID]
	if !exists {
		return fmt.Errorf("invitation not found")
	}
	invitation.Status = InviteStatusAccepted
	return nil
}

// Simple implementations for other required repositories
type SimpleAPIKeyRepository struct{}
type SimpleAuditLogRepository struct{}
type SimpleSessionRepository struct{}

func NewSimpleAPIKeyRepository() *SimpleAPIKeyRepository     { return &SimpleAPIKeyRepository{} }
func NewSimpleAuditLogRepository() *SimpleAuditLogRepository { return &SimpleAuditLogRepository{} }
func NewSimpleSessionRepository() *SimpleSessionRepository   { return &SimpleSessionRepository{} }

// Placeholder methods - implement as needed
func (r *SimpleAPIKeyRepository) CreateAPIKey(ctx context.Context, apiKey *APIKey) error { return nil }
func (r *SimpleAPIKeyRepository) DeleteAPIKey(ctx context.Context, keyID string) error { return nil }
func (r *SimpleAuditLogRepository) CreateLog(ctx context.Context, log interface{}) error     { return nil }
func (r *SimpleAuditLogRepository) CleanupOldAuditLogs(ctx context.Context, before time.Time) error { return nil }
func (r *SimpleSessionRepository) CreateSession(ctx context.Context, session *Session) error { return nil }
func (r *SimpleSessionRepository) CleanupExpiredSessions(ctx context.Context) error { return nil }
