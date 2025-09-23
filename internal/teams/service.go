package teams

import (
	"context"
	"time"

	"n8n-pro/internal/storage/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jackc/pgx/v5"
)

// Team represents a team/organization in the system
type Team struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	OwnerID     string    `json:"owner_id" db:"owner_id"`
	PlanType    string    `json:"plan_type" db:"plan_type"`
	Active      bool      `json:"active" db:"active"`
	Settings    string    `json:"settings" db:"settings"` // JSON
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// TeamMember represents a team member
type TeamMember struct {
	ID       string    `json:"id" db:"id"`
	TeamID   string    `json:"team_id" db:"team_id"`
	UserID   string    `json:"user_id" db:"user_id"`
	Role     string    `json:"role" db:"role"`
	JoinedAt time.Time `json:"joined_at" db:"joined_at"`
}

// Repository defines the teams data access interface
type Repository interface {
	CreateTeam(ctx context.Context, team *Team) error
	GetTeamByID(ctx context.Context, id string) (*Team, error)
	UpdateTeam(ctx context.Context, team *Team) error
	DeleteTeam(ctx context.Context, id string) error
	ListTeams(ctx context.Context, userID string) ([]*Team, error)
	AddMember(ctx context.Context, member *TeamMember) error
	RemoveMember(ctx context.Context, teamID, userID string) error
	ListMembers(ctx context.Context, teamID string) ([]*TeamMember, error)
}

// Service provides team management services
type Service struct {
	repo   Repository
	logger logger.Logger
}

// PostgresRepository implements Repository for PostgreSQL
type PostgresRepository struct {
	db     *postgres.DB
	logger logger.Logger
}

// NewPostgresRepository creates a new PostgreSQL teams repository
func NewPostgresRepository(db *postgres.DB) Repository {
	return &PostgresRepository{
		db:     db,
		logger: logger.New("teams-repository"),
	}
}

// NewService creates a new teams service
func NewService(repo Repository) *Service {
	return &Service{
		repo:   repo,
		logger: logger.New("teams-service"),
	}
}

// CreateTeam creates a new team
func (s *Service) CreateTeam(ctx context.Context, team *Team) error {
	return s.repo.CreateTeam(ctx, team)
}

// GetTeamByID retrieves a team by ID
func (s *Service) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	return s.repo.GetTeamByID(ctx, id)
}

// UpdateTeam updates a team
func (s *Service) UpdateTeam(ctx context.Context, team *Team) error {
	return s.repo.UpdateTeam(ctx, team)
}

// DeleteTeam deletes a team
func (s *Service) DeleteTeam(ctx context.Context, id string) error {
	return s.repo.DeleteTeam(ctx, id)
}

// ListTeams lists teams for a user
func (s *Service) ListTeams(ctx context.Context, userID string) ([]*Team, error) {
	return s.repo.ListTeams(ctx, userID)
}

// AddMember adds a member to a team
func (s *Service) AddMember(ctx context.Context, member *TeamMember) error {
	return s.repo.AddMember(ctx, member)
}

// RemoveMember removes a member from a team
func (s *Service) RemoveMember(ctx context.Context, teamID, userID string) error {
	return s.repo.RemoveMember(ctx, teamID, userID)
}

// ListMembers lists members of a team
func (s *Service) ListMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	return s.repo.ListMembers(ctx, teamID)
}

// Repository implementation

func (r *PostgresRepository) CreateTeam(ctx context.Context, team *Team) error {
	if team == nil {
		return errors.NewValidationError("team cannot be nil")
	}

	query := `
		INSERT INTO teams (
			id, name, description, owner_id, plan_type, active,
			settings, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		team.ID, team.Name, team.Description, team.OwnerID,
		team.PlanType, team.Active, team.Settings,
		now, now,
	)

	if err != nil {
		r.logger.Error("Failed to create team", "error", err, "team_id", team.ID)
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create team")
	}

	r.logger.Info("Team created successfully", "team_id", team.ID, "name", team.Name)
	return nil
}

func (r *PostgresRepository) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	if id == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	query := `
		SELECT id, name, description, owner_id, plan_type, active,
			   settings, created_at, updated_at
		FROM teams
		WHERE id = $1`

	var team Team
	err := r.db.QueryRow(ctx, query, id).Scan(
		&team.ID, &team.Name, &team.Description, &team.OwnerID,
		&team.PlanType, &team.Active, &team.Settings,
		&team.CreatedAt, &team.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("team not found")
		}
		r.logger.Error("Failed to get team by ID", "error", err, "team_id", id)
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to retrieve team")
	}

	return &team, nil
}

func (r *PostgresRepository) UpdateTeam(ctx context.Context, team *Team) error {
	if team == nil {
		return errors.NewValidationError("team cannot be nil")
	}
	if team.ID == "" {
		return errors.NewValidationError("team ID is required")
	}

	query := `
		UPDATE teams SET
			name = $2, description = $3, plan_type = $4, active = $5,
			settings = $6, updated_at = $7
		WHERE id = $1`

	now := time.Now()
	result, err := r.db.Exec(ctx, query,
		team.ID, team.Name, team.Description, team.PlanType,
		team.Active, team.Settings, now,
	)

	if err != nil {
		r.logger.Error("Failed to update team", "error", err, "team_id", team.ID)
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to update team")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team updated successfully", "team_id", team.ID)
	return nil
}

func (r *PostgresRepository) DeleteTeam(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("team ID is required")
	}

	// Soft delete by setting active to false
	query := `UPDATE teams SET active = false, updated_at = $2 WHERE id = $1`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.logger.Error("Failed to delete team", "error", err, "team_id", id)
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to delete team")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team deleted successfully", "team_id", id)
	return nil
}

func (r *PostgresRepository) ListTeams(ctx context.Context, userID string) ([]*Team, error) {
	if userID == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	query := `
		SELECT t.id, t.name, t.description, t.owner_id, t.plan_type,
			   t.active, t.settings, t.created_at, t.updated_at
		FROM teams t
		JOIN team_members tm ON t.id = tm.team_id
		WHERE tm.user_id = $1 AND t.active = true
		ORDER BY t.created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to list teams", "error", err, "user_id", userID)
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list teams")
	}
	defer rows.Close()

	var teams []*Team
	for rows.Next() {
		var team Team
		err := rows.Scan(
			&team.ID, &team.Name, &team.Description, &team.OwnerID,
			&team.PlanType, &team.Active, &team.Settings,
			&team.CreatedAt, &team.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan team row", "error", err)
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan team data")
		}
		teams = append(teams, &team)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating team rows", "error", err)
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate team data")
	}

	r.logger.Info("Teams listed successfully", "count", len(teams), "user_id", userID)
	return teams, nil
}

func (r *PostgresRepository) AddMember(ctx context.Context, member *TeamMember) error {
	if member == nil {
		return errors.NewValidationError("team member cannot be nil")
	}

	query := `
		INSERT INTO team_members (
			id, team_id, user_id, role, joined_at
		) VALUES (
			$1, $2, $3, $4, $5
		)`

	now := time.Now()
	_, err := r.db.Exec(ctx, query,
		member.ID, member.TeamID, member.UserID, member.Role, now,
	)

	if err != nil {
		r.logger.Error("Failed to add team member", "error", err,
			"team_id", member.TeamID, "user_id", member.UserID)
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to add team member")
	}

	r.logger.Info("Team member added successfully",
		"team_id", member.TeamID, "user_id", member.UserID, "role", member.Role)
	return nil
}

func (r *PostgresRepository) RemoveMember(ctx context.Context, teamID, userID string) error {
	if teamID == "" {
		return errors.NewValidationError("team ID is required")
	}
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	query := `DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`

	result, err := r.db.Exec(ctx, query, teamID, userID)
	if err != nil {
		r.logger.Error("Failed to remove team member", "error", err,
			"team_id", teamID, "user_id", userID)
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to remove team member")
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewNotFoundError("team member not found")
	}

	r.logger.Info("Team member removed successfully",
		"team_id", teamID, "user_id", userID)
	return nil
}

func (r *PostgresRepository) ListMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	if teamID == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	query := `
		SELECT id, team_id, user_id, role, joined_at
		FROM team_members
		WHERE team_id = $1
		ORDER BY joined_at ASC`

	rows, err := r.db.Query(ctx, query, teamID)
	if err != nil {
		r.logger.Error("Failed to list team members", "error", err, "team_id", teamID)
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list team members")
	}
	defer rows.Close()

	var members []*TeamMember
	for rows.Next() {
		var member TeamMember
		err := rows.Scan(
			&member.ID, &member.TeamID, &member.UserID,
			&member.Role, &member.JoinedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan team member row", "error", err)
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan team member data")
		}
		members = append(members, &member)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating team member rows", "error", err)
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate team member data")
	}

	r.logger.Info("Team members listed successfully", "count", len(members), "team_id", teamID)
	return members, nil
}
