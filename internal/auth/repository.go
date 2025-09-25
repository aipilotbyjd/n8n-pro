package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v5"

	"n8n-pro/internal/db/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)
// Enhanced repository interfaces for comprehensive auth system

// OrganizationRepository defines organization data access methods
type OrganizationRepository interface {
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context, limit, offset int) ([]*Organization, error)
	GetOrganizationStats(ctx context.Context, orgID string) (*OrganizationStats, error)
}

// TeamRepository defines team data access methods  
type TeamRepository interface {
	CreateTeam(ctx context.Context, team *Team) error
	GetTeamByID(ctx context.Context, id string) (*Team, error)
	GetTeamByName(ctx context.Context, organizationID, name string) (*Team, error)
	GetTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error)
	GetOrganizationTeams(ctx context.Context, organizationID string) ([]*Team, error)
	UpdateTeam(ctx context.Context, team *Team) error
	DeleteTeam(ctx context.Context, id string) error
	AddUserToTeam(ctx context.Context, membership *TeamMembership) error
	RemoveUserFromTeam(ctx context.Context, teamID, userID string) error
	UpdateUserTeamRole(ctx context.Context, teamID, userID string, role RoleType) error
	GetTeamMemberships(ctx context.Context, teamID string) ([]*TeamMembership, error)
	GetUserTeamMemberships(ctx context.Context, userID string) ([]*TeamMembership, error)
	GetTeamMembership(ctx context.Context, teamID, userID string) (*TeamMembership, error)
	UpdateTeamMembership(ctx context.Context, membership *TeamMembership) error
	GetTeamMembers(ctx context.Context, teamID string, limit, offset int) ([]*TeamMembership, error)
	GetTeamMemberCount(ctx context.Context, teamID string) (int, error)
	GetTeamOwner(ctx context.Context, teamID string) (*TeamMembership, error)
}

// EnhancedUserRepository defines enhanced user data access methods
type EnhancedUserRepository interface {
	CreateUser(ctx context.Context, user *EnhancedUser) error
	GetUserByID(ctx context.Context, id string) (*EnhancedUser, error)
	GetUserByEmail(ctx context.Context, email string) (*EnhancedUser, error)
	GetUserByEmailInOrganization(ctx context.Context, email, orgID string) (*EnhancedUser, error)
	GetUsersByOrganization(ctx context.Context, orgID string, limit, offset int) ([]*EnhancedUser, error)
	UpdateUser(ctx context.Context, user *EnhancedUser) error
	DeleteUser(ctx context.Context, id string) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	UpdateLastLogin(ctx context.Context, userID, ipAddress string) error
	IncrementFailedLogin(ctx context.Context, userID string) error
	ResetFailedLogins(ctx context.Context, userID string) error
	SetAccountLock(ctx context.Context, userID string, lockUntil time.Time) error
	ClearAccountLock(ctx context.Context, userID string) error
	GetUserByEmailVerificationToken(ctx context.Context, token string) (*EnhancedUser, error)
	GetUserByPasswordResetToken(ctx context.Context, token string) (*EnhancedUser, error)
	GetUserByAPIKey(ctx context.Context, apiKey string) (*EnhancedUser, error)
}

// InvitationRepository defines invitation data access methods
type InvitationRepository interface {
	CreateInvitation(ctx context.Context, invitation *Invitation) error
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)
	GetInvitationByToken(ctx context.Context, token string) (*Invitation, error)
	GetInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error)
	GetInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error)
	UpdateInvitation(ctx context.Context, invitation *Invitation) error
	DeleteInvitation(ctx context.Context, id string) error
	AcceptInvitation(ctx context.Context, token string, userID string) error
	RevokeInvitation(ctx context.Context, id string) error
	CleanupExpiredInvitations(ctx context.Context) error
}

// APIKeyRepository defines API key data access methods
type APIKeyRepository interface {
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	GetAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, apiKey *APIKey) error
	DeleteAPIKey(ctx context.Context, id string) error
	RevokeAPIKey(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string) error
}

// AuditLogRepository defines audit log data access methods
type AuditLogRepository interface {
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogsByOrganization(ctx context.Context, orgID string, limit, offset int) ([]*AuditLog, error)
	GetAuditLogsByUser(ctx context.Context, userID string, limit, offset int) ([]*AuditLog, error)
	GetAuditLogsByResource(ctx context.Context, orgID, resource, resourceID string, limit, offset int) ([]*AuditLog, error)
	CleanupOldAuditLogs(ctx context.Context, olderThan time.Time) error
}

// SessionRepository defines session data access methods  
type SessionRepository interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id string) (*Session, error)
	GetSessionByRefreshToken(ctx context.Context, tokenHash string) (*Session, error)
	GetSessionsByUser(ctx context.Context, userID string) ([]*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	RevokeSession(ctx context.Context, id string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error
}

// OrganizationStats contains organization usage statistics
type OrganizationStats struct {
	UserCount         int `json:"user_count"`
	TeamCount         int `json:"team_count"`
	ActiveUserCount   int `json:"active_user_count"`
	ThisMonthLogins   int `json:"this_month_logins"`
}

// PostgreSQL implementations

// PostgresOrganizationRepository implements OrganizationRepository
type PostgresOrganizationRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresOrganizationRepository creates a new organization repository
func NewPostgresOrganizationRepository(db *postgres.DB) OrganizationRepository {
	return &PostgresOrganizationRepository{
		db:     db,
		logger: logger.New("organization-repository"),
	}
}

// CreateOrganization creates a new organization
func (r *PostgresOrganizationRepository) CreateOrganization(ctx context.Context, org *Organization) error {
	if org == nil {
		return errors.NewValidationError("organization cannot be nil")
	}

	query := `
		INSERT INTO organizations (
			id, name, slug, domain, logo_url, plan, plan_limits, settings, status,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		org.ID, org.Name, org.Slug, org.Domain, org.LogoURL, org.Plan,
		org.PlanLimits, org.Settings, org.Status, now, now,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			if strings.Contains(err.Error(), "slug") {
				return errors.NewValidationError("organization slug already exists")
			}
			return errors.NewValidationError("organization already exists")
		}
		r.logger.Error("Failed to create organization", "error", err)
		return errors.InternalError("failed to create organization")
	}

	r.logger.Info("Organization created successfully", "org_id", org.ID, "name", org.Name)
	return nil
}

// GetOrganizationByID retrieves an organization by ID
func (r *PostgresOrganizationRepository) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	if id == "" {
		return nil, errors.NewValidationError("organization ID is required")
	}

	query := `
		SELECT id, name, slug, domain, logo_url, plan, plan_limits, settings, status,
			   created_at, updated_at, deleted_at
		FROM organizations 
		WHERE id = $1 AND deleted_at IS NULL`

	var org Organization
	err := r.db.QueryRow(ctx, query, id).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.LogoURL, &org.Plan,
		&org.PlanLimits, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt, &org.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("organization not found")
		}
		r.logger.Error("Failed to get organization by ID", "error", err, "org_id", id)
		return nil, errors.InternalError("failed to retrieve organization")
	}

	return &org, nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (r *PostgresOrganizationRepository) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	if slug == "" {
		return nil, errors.NewValidationError("organization slug is required")
	}

	query := `
		SELECT id, name, slug, domain, logo_url, plan, plan_limits, settings, status,
			   created_at, updated_at, deleted_at
		FROM organizations 
		WHERE slug = $1 AND deleted_at IS NULL`

	var org Organization
	err := r.db.QueryRow(ctx, query, slug).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.LogoURL, &org.Plan,
		&org.PlanLimits, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt, &org.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("organization not found")
		}
		r.logger.Error("Failed to get organization by slug", "error", err, "slug", slug)
		return nil, errors.InternalError("failed to retrieve organization")
	}

	return &org, nil
}

// GetOrganizationByDomain retrieves an organization by domain
func (r *PostgresOrganizationRepository) GetOrganizationByDomain(ctx context.Context, domain string) (*Organization, error) {
	if domain == "" {
		return nil, errors.NewValidationError("domain is required")
	}

	query := `
		SELECT id, name, slug, domain, logo_url, plan, plan_limits, settings, status,
			   created_at, updated_at, deleted_at
		FROM organizations 
		WHERE domain = $1 AND deleted_at IS NULL`

	var org Organization
	err := r.db.QueryRow(ctx, query, domain).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Domain, &org.LogoURL, &org.Plan,
		&org.PlanLimits, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt, &org.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("organization not found")
		}
		r.logger.Error("Failed to get organization by domain", "error", err, "domain", domain)
		return nil, errors.InternalError("failed to retrieve organization")
	}

	return &org, nil
}

// UpdateOrganization updates an organization
func (r *PostgresOrganizationRepository) UpdateOrganization(ctx context.Context, org *Organization) error {
	if org == nil || org.ID == "" {
		return errors.NewValidationError("organization and ID are required")
	}

	query := `
		UPDATE organizations SET
			name = $2, slug = $3, domain = $4, logo_url = $5, plan = $6,
			plan_limits = $7, settings = $8, status = $9, updated_at = $10
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query,
		org.ID, org.Name, org.Slug, org.Domain, org.LogoURL, org.Plan,
		org.PlanLimits, org.Settings, org.Status, time.Now(),
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") && strings.Contains(err.Error(), "slug") {
			return errors.NewValidationError("organization slug already exists")
		}
		r.logger.Error("Failed to update organization", "error", err, "org_id", org.ID)
		return errors.InternalError("failed to update organization")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("organization not found")
	}

	r.logger.Info("Organization updated successfully", "org_id", org.ID)
	return nil
}

// DeleteOrganization soft deletes an organization
func (r *PostgresOrganizationRepository) DeleteOrganization(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("organization ID is required")
	}

	query := `UPDATE organizations SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.logger.Error("Failed to delete organization", "error", err, "org_id", id)
		return errors.InternalError("failed to delete organization")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("organization not found")
	}

	r.logger.Info("Organization deleted successfully", "org_id", id)
	return nil
}

// ListOrganizations lists organizations with pagination
func (r *PostgresOrganizationRepository) ListOrganizations(ctx context.Context, limit, offset int) ([]*Organization, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, name, slug, domain, logo_url, plan, plan_limits, settings, status,
			   created_at, updated_at, deleted_at
		FROM organizations 
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		r.logger.Error("Failed to list organizations", "error", err)
		return nil, errors.InternalError("failed to list organizations")
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		var org Organization
		err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.Domain, &org.LogoURL, &org.Plan,
			&org.PlanLimits, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt, &org.DeletedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan organization row", "error", err)
			return nil, errors.InternalError("failed to scan organization data")
		}
		orgs = append(orgs, &org)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating organization rows", "error", err)
		return nil, errors.InternalError("failed to iterate organization data")
	}

	return orgs, nil
}

// GetOrganizationStats returns organization usage statistics
func (r *PostgresOrganizationRepository) GetOrganizationStats(ctx context.Context, orgID string) (*OrganizationStats, error) {
	if orgID == "" {
		return nil, errors.NewValidationError("organization ID is required")
	}

	query := `SELECT * FROM get_organization_stats($1)`

	var stats OrganizationStats
	err := r.db.QueryRow(ctx, query, orgID).Scan(
		&stats.UserCount, &stats.TeamCount, &stats.ActiveUserCount, &stats.ThisMonthLogins,
	)

	if err != nil {
		r.logger.Error("Failed to get organization stats", "error", err, "org_id", orgID)
		return nil, errors.InternalError("failed to get organization statistics")
	}

	return &stats, nil
}

// PostgresTeamRepository implements TeamRepository
type PostgresTeamRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresTeamRepository creates a new team repository
func NewPostgresTeamRepository(db *postgres.DB) TeamRepository {
	return &PostgresTeamRepository{
		db:     db,
		logger: logger.New("team-repository"),
	}
}

// CreateTeam creates a new team
func (r *PostgresTeamRepository) CreateTeam(ctx context.Context, team *Team) error {
	if team == nil {
		return errors.NewValidationError("team cannot be nil")
	}

	query := `
		INSERT INTO teams (id, organization_id, name, description, settings, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		team.ID, team.OrganizationID, team.Name, team.Description,
		team.Settings, now, now,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.NewValidationError("team name already exists in this organization")
		}
		r.logger.Error("Failed to create team", "error", err)
		return errors.InternalError("failed to create team")
	}

	r.logger.Info("Team created successfully", "team_id", team.ID, "name", team.Name)
	return nil
}

// GetTeamByID retrieves a team by ID
func (r *PostgresTeamRepository) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	if id == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	query := `
		SELECT t.id, t.organization_id, t.name, t.description, t.settings,
			   t.created_at, t.updated_at, t.deleted_at,
			   COUNT(tm.user_id) as member_count
		FROM teams t
		LEFT JOIN team_memberships tm ON t.id = tm.team_id
		WHERE t.id = $1 AND t.deleted_at IS NULL
		GROUP BY t.id, t.organization_id, t.name, t.description, t.settings,
				 t.created_at, t.updated_at, t.deleted_at`

	var team Team
	err := r.db.QueryRow(ctx, query, id).Scan(
		&team.ID, &team.OrganizationID, &team.Name, &team.Description, &team.Settings,
		&team.CreatedAt, &team.UpdatedAt, &team.DeletedAt, &team.MemberCount,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("team not found")
		}
		r.logger.Error("Failed to get team by ID", "error", err, "team_id", id)
		return nil, errors.InternalError("failed to retrieve team")
	}

	return &team, nil
}

// GetTeamByName retrieves a team by name within an organization
func (r *PostgresTeamRepository) GetTeamByName(ctx context.Context, organizationID, name string) (*Team, error) {
	if organizationID == "" || name == "" {
		return nil, errors.NewValidationError("organization ID and team name are required")
	}

	query := `
		SELECT t.id, t.organization_id, t.name, t.description, t.settings,
			   t.created_at, t.updated_at, t.deleted_at,
			   COUNT(tm.user_id) as member_count
		FROM teams t
		LEFT JOIN team_memberships tm ON t.id = tm.team_id
		WHERE t.organization_id = $1 AND t.name = $2 AND t.deleted_at IS NULL
		GROUP BY t.id, t.organization_id, t.name, t.description, t.settings,
				 t.created_at, t.updated_at, t.deleted_at`

	var team Team
	err := r.db.QueryRow(ctx, query, organizationID, name).Scan(
		&team.ID, &team.OrganizationID, &team.Name, &team.Description, &team.Settings,
		&team.CreatedAt, &team.UpdatedAt, &team.DeletedAt, &team.MemberCount,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("team not found")
		}
		r.logger.Error("Failed to get team by name", "error", err, "org_id", organizationID, "name", name)
		return nil, errors.InternalError("failed to retrieve team")
	}

	return &team, nil
}

// GetTeamsByOrganization retrieves teams for an organization
func (r *PostgresTeamRepository) GetTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	if orgID == "" {
		return nil, errors.NewValidationError("organization ID is required")
	}

	query := `
		SELECT t.id, t.organization_id, t.name, t.description, t.settings,
			   t.created_at, t.updated_at, t.deleted_at,
			   COUNT(tm.user_id) as member_count
		FROM teams t
		LEFT JOIN team_memberships tm ON t.id = tm.team_id
		WHERE t.organization_id = $1 AND t.deleted_at IS NULL
		GROUP BY t.id, t.organization_id, t.name, t.description, t.settings,
				 t.created_at, t.updated_at, t.deleted_at
		ORDER BY t.created_at DESC`

	rows, err := r.db.Query(ctx, query, orgID)
	if err != nil {
		r.logger.Error("Failed to get teams by organization", "error", err, "org_id", orgID)
		return nil, errors.InternalError("failed to retrieve teams")
	}
	defer rows.Close()

	var teams []*Team
	for rows.Next() {
		var team Team
		err := rows.Scan(
			&team.ID, &team.OrganizationID, &team.Name, &team.Description, &team.Settings,
			&team.CreatedAt, &team.UpdatedAt, &team.DeletedAt, &team.MemberCount,
		)
		if err != nil {
			r.logger.Error("Failed to scan team row", "error", err)
			return nil, errors.InternalError("failed to scan team data")
		}
		teams = append(teams, &team)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating team rows", "error", err)
		return nil, errors.InternalError("failed to iterate team data")
	}

	return teams, nil
}

// GetOrganizationTeams retrieves teams for an organization (alias for GetTeamsByOrganization)
func (r *PostgresTeamRepository) GetOrganizationTeams(ctx context.Context, organizationID string) ([]*Team, error) {
	return r.GetTeamsByOrganization(ctx, organizationID)
}

// UpdateTeam updates a team
func (r *PostgresTeamRepository) UpdateTeam(ctx context.Context, team *Team) error {
	if team == nil || team.ID == "" {
		return errors.NewValidationError("team and ID are required")
	}

	query := `
		UPDATE teams SET name = $2, description = $3, settings = $4, updated_at = $5
		WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.Exec(ctx, query,
		team.ID, team.Name, team.Description, team.Settings, time.Now(),
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.NewValidationError("team name already exists in this organization")
		}
		r.logger.Error("Failed to update team", "error", err, "team_id", team.ID)
		return errors.InternalError("failed to update team")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team updated successfully", "team_id", team.ID)
	return nil
}

// DeleteTeam soft deletes a team
func (r *PostgresTeamRepository) DeleteTeam(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("team ID is required")
	}

	query := `UPDATE teams SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.logger.Error("Failed to delete team", "error", err, "team_id", id)
		return errors.InternalError("failed to delete team")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team deleted successfully", "team_id", id)
	return nil
}

// AddUserToTeam adds a user to a team
func (r *PostgresTeamRepository) AddUserToTeam(ctx context.Context, membership *TeamMembership) error {
	if membership == nil {
		return errors.NewValidationError("team membership cannot be nil")
	}

	query := `
		INSERT INTO team_memberships (id, team_id, user_id, role, joined_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (team_id, user_id) DO UPDATE SET
			role = EXCLUDED.role, joined_at = EXCLUDED.joined_at`

	_, err := r.db.Exec(ctx, query,
		membership.ID, membership.TeamID, membership.UserID,
		membership.Role, membership.JoinedAt,
	)

	if err != nil {
		r.logger.Error("Failed to add user to team", "error", err)
		return errors.InternalError("failed to add user to team")
	}

	r.logger.Info("User added to team successfully",
		"team_id", membership.TeamID, "user_id", membership.UserID, "role", membership.Role)
	return nil
}

// RemoveUserFromTeam removes a user from a team
func (r *PostgresTeamRepository) RemoveUserFromTeam(ctx context.Context, teamID, userID string) error {
	if teamID == "" || userID == "" {
		return errors.NewValidationError("team ID and user ID are required")
	}

	query := `DELETE FROM team_memberships WHERE team_id = $1 AND user_id = $2`

	result, err := r.db.Exec(ctx, query, teamID, userID)
	if err != nil {
		r.logger.Error("Failed to remove user from team", "error", err)
		return errors.InternalError("failed to remove user from team")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team membership not found")
	}

	r.logger.Info("User removed from team successfully", "team_id", teamID, "user_id", userID)
	return nil
}

// UpdateUserTeamRole updates a user's role in a team
func (r *PostgresTeamRepository) UpdateUserTeamRole(ctx context.Context, teamID, userID string, role RoleType) error {
	if teamID == "" || userID == "" {
		return errors.NewValidationError("team ID and user ID are required")
	}

	query := `UPDATE team_memberships SET role = $3 WHERE team_id = $1 AND user_id = $2`

	result, err := r.db.Exec(ctx, query, teamID, userID, role)
	if err != nil {
		r.logger.Error("Failed to update user team role", "error", err)
		return errors.InternalError("failed to update user team role")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team membership not found")
	}

	r.logger.Info("User team role updated successfully",
		"team_id", teamID, "user_id", userID, "role", role)
	return nil
}

// GetTeamMemberships gets all memberships for a team
func (r *PostgresTeamRepository) GetTeamMemberships(ctx context.Context, teamID string) ([]*TeamMembership, error) {
	if teamID == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	query := `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
			   u.email, u.first_name, u.last_name, u.status
		FROM team_memberships tm
		JOIN users u ON tm.user_id = u.id
		WHERE tm.team_id = $1 AND u.deleted_at IS NULL
		ORDER BY tm.joined_at`

	rows, err := r.db.Query(ctx, query, teamID)
	if err != nil {
		r.logger.Error("Failed to get team memberships", "error", err, "team_id", teamID)
		return nil, errors.InternalError("failed to retrieve team memberships")
	}
	defer rows.Close()

	var memberships []*TeamMembership
	for rows.Next() {
		var membership TeamMembership
		var user EnhancedUser

		err := rows.Scan(
			&membership.ID, &membership.TeamID, &membership.UserID,
			&membership.Role, &membership.JoinedAt,
			&user.Email, &user.FirstName, &user.LastName, &user.Status,
		)
		if err != nil {
			r.logger.Error("Failed to scan team membership row", "error", err)
			return nil, errors.InternalError("failed to scan team membership data")
		}

		user.ID = membership.UserID
		membership.User = &user
		memberships = append(memberships, &membership)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating team membership rows", "error", err)
		return nil, errors.InternalError("failed to iterate team membership data")
	}

	return memberships, nil
}

// GetUserTeamMemberships gets all team memberships for a user
func (r *PostgresTeamRepository) GetUserTeamMemberships(ctx context.Context, userID string) ([]*TeamMembership, error) {
	if userID == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	query := `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
			   t.name, t.description, t.organization_id
		FROM team_memberships tm
		JOIN teams t ON tm.team_id = t.id
		WHERE tm.user_id = $1 AND t.deleted_at IS NULL
		ORDER BY tm.joined_at`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to get user team memberships", "error", err, "user_id", userID)
		return nil, errors.InternalError("failed to retrieve user team memberships")
	}
	defer rows.Close()

	var memberships []*TeamMembership
	for rows.Next() {
		var membership TeamMembership
		var team Team

		err := rows.Scan(
			&membership.ID, &membership.TeamID, &membership.UserID,
			&membership.Role, &membership.JoinedAt,
			&team.Name, &team.Description, &team.OrganizationID,
		)
		if err != nil {
			r.logger.Error("Failed to scan user team membership row", "error", err)
			return nil, errors.InternalError("failed to scan user team membership data")
		}

		team.ID = membership.TeamID
		membership.Team = &team
		memberships = append(memberships, &membership)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating user team membership rows", "error", err)
		return nil, errors.InternalError("failed to iterate user team membership data")
	}

	return memberships, nil
}

// GetTeamMemberCount gets the count of team members
func (r *PostgresTeamRepository) GetTeamMemberCount(ctx context.Context, teamID string) (int, error) {
	if teamID == "" {
		return 0, errors.NewValidationError("team ID is required")
	}

	query := `SELECT COUNT(*) FROM team_memberships tm JOIN users u ON tm.user_id = u.id WHERE tm.team_id = $1 AND u.deleted_at IS NULL`

	var count int
	err := r.db.QueryRow(ctx, query, teamID).Scan(&count)
	if err != nil {
		r.logger.Error("Failed to get team member count", "error", err, "team_id", teamID)
		return 0, errors.InternalError("failed to get team member count")
	}

	return count, nil
}

// GetTeamMembers gets paginated team members
func (r *PostgresTeamRepository) GetTeamMembers(ctx context.Context, teamID string, limit, offset int) ([]*TeamMembership, error) {
	if teamID == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
			   u.email, u.first_name, u.last_name, u.status
		FROM team_memberships tm
		JOIN users u ON tm.user_id = u.id
		WHERE tm.team_id = $1 AND u.deleted_at IS NULL
		ORDER BY tm.joined_at
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, teamID, limit, offset)
	if err != nil {
		r.logger.Error("Failed to get team members", "error", err, "team_id", teamID)
		return nil, errors.InternalError("failed to retrieve team members")
	}
	defer rows.Close()

	var memberships []*TeamMembership
	for rows.Next() {
		var membership TeamMembership
		var user EnhancedUser

		err := rows.Scan(
			&membership.ID, &membership.TeamID, &membership.UserID,
			&membership.Role, &membership.JoinedAt,
			&user.Email, &user.FirstName, &user.LastName, &user.Status,
		)
		if err != nil {
			r.logger.Error("Failed to scan team member row", "error", err)
			return nil, errors.InternalError("failed to scan team member data")
		}

		user.ID = membership.UserID
		membership.User = &user
		memberships = append(memberships, &membership)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating team member rows", "error", err)
		return nil, errors.InternalError("failed to iterate team member data")
	}

	return memberships, nil
}

// GetTeamOwner gets the team owner
func (r *PostgresTeamRepository) GetTeamOwner(ctx context.Context, teamID string) (*TeamMembership, error) {
	if teamID == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	query := `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
			   u.email, u.first_name, u.last_name, u.status
		FROM team_memberships tm
		JOIN users u ON tm.user_id = u.id
		WHERE tm.team_id = $1 AND tm.role = 'owner' AND u.deleted_at IS NULL
		LIMIT 1`

	var membership TeamMembership
	var user EnhancedUser

	err := r.db.QueryRow(ctx, query, teamID).Scan(
		&membership.ID, &membership.TeamID, &membership.UserID,
		&membership.Role, &membership.JoinedAt,
		&user.Email, &user.FirstName, &user.LastName, &user.Status,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("team owner not found")
		}
		r.logger.Error("Failed to get team owner", "error", err, "team_id", teamID)
		return nil, errors.InternalError("failed to retrieve team owner")
	}

	user.ID = membership.UserID
	membership.User = &user
	return &membership, nil
}

// GetTeamMembership gets a specific team membership
func (r *PostgresTeamRepository) GetTeamMembership(ctx context.Context, teamID, userID string) (*TeamMembership, error) {
	if teamID == "" || userID == "" {
		return nil, errors.NewValidationError("team ID and user ID are required")
	}

	query := `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
			   u.email, u.first_name, u.last_name, u.status
		FROM team_memberships tm
		JOIN users u ON tm.user_id = u.id
		WHERE tm.team_id = $1 AND tm.user_id = $2 AND u.deleted_at IS NULL`

	var membership TeamMembership
	var user EnhancedUser

	err := r.db.QueryRow(ctx, query, teamID, userID).Scan(
		&membership.ID, &membership.TeamID, &membership.UserID,
		&membership.Role, &membership.JoinedAt,
		&user.Email, &user.FirstName, &user.LastName, &user.Status,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("team membership not found")
		}
		r.logger.Error("Failed to get team membership", "error", err, "team_id", teamID, "user_id", userID)
		return nil, errors.InternalError("failed to retrieve team membership")
	}

	user.ID = membership.UserID
	membership.User = &user
	return &membership, nil
}

// UpdateTeamMembership updates a team membership
func (r *PostgresTeamRepository) UpdateTeamMembership(ctx context.Context, membership *TeamMembership) error {
	if membership == nil || membership.TeamID == "" || membership.UserID == "" {
		return errors.NewValidationError("membership with team ID and user ID are required")
	}

	query := `UPDATE team_memberships SET role = $3, joined_at = $4 WHERE team_id = $1 AND user_id = $2`

	result, err := r.db.Exec(ctx, query, membership.TeamID, membership.UserID, membership.Role, membership.JoinedAt)
	if err != nil {
		r.logger.Error("Failed to update team membership", "error", err)
		return errors.InternalError("failed to update team membership")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team membership not found")
	}

	r.logger.Info("Team membership updated successfully",
		"team_id", membership.TeamID, "user_id", membership.UserID, "role", membership.Role)
	return nil
}

// Hash API key for storage
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// Helper function to handle nullable timestamp scanning
func scanNullableTimestamp(src interface{}) (*time.Time, error) {
	if src == nil {
		return nil, nil
	}
	
	var pgTime pgtype.Timestamptz
	if err := pgTime.Scan(src); err != nil {
		return nil, err
	}
	
	if pgTime.Status == pgtype.Null {
		return nil, nil
	}
	
	return &pgTime.Time, nil
}

// Helper function to handle nullable string scanning  
func scanNullableString(src interface{}) (*string, error) {
	if src == nil {
		return nil, nil
	}
	
	var pgText pgtype.Text
	if err := pgText.Scan(src); err != nil {
		return nil, err
	}
	
	if pgText.Status == pgtype.Null {
		return nil, nil
	}
	
	return &pgText.String, nil
}
