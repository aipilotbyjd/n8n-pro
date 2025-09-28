package teams

import (
	"context"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"gorm.io/gorm"
)

// Team is an alias for the GORM Team model
type Team = models.Team

// TeamMember is an alias for the GORM TeamMember model
type TeamMember = models.TeamMember

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

// GORMRepository implements Repository for PostgreSQL using GORM
type GORMRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewPostgresRepository creates a new GORM-based teams repository
// This maintains compatibility with existing code while using GORM internally
func NewPostgresRepository(db *gorm.DB) Repository {
	return NewGORMRepository(db)
}

// NewGORMRepository creates a new GORM-based teams repository
func NewGORMRepository(db *gorm.DB) Repository {
	return &GORMRepository{
		db:     db,
		logger: logger.New("teams-gorm-repository"),
	}
}

// CreateTeam creates a new team using GORM
func (r *GORMRepository) CreateTeam(ctx context.Context, team *Team) error {
	if team == nil {
		return errors.NewValidationError("team cannot be nil")
	}

	// Use GORM to create the team
	result := r.db.WithContext(ctx).Create(team)
	if result.Error != nil {
		r.logger.Error("Failed to create team", "error", result.Error, "team_id", team.ID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to create team")
	}

	r.logger.Info("Team created successfully", "team_id", team.ID, "name", team.Name)
	return nil
}

// GetTeamByID retrieves a team by ID using GORM
func (r *GORMRepository) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	if id == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	var team Team
	result := r.db.WithContext(ctx).First(&team, "id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError("team not found")
		}
		r.logger.Error("Failed to get team by ID", "error", result.Error, "team_id", id)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to retrieve team")
	}

	return &team, nil
}

// UpdateTeam updates a team using GORM
func (r *GORMRepository) UpdateTeam(ctx context.Context, team *Team) error {
	if team == nil {
		return errors.NewValidationError("team cannot be nil")
	}
	if team.ID == "" {
		return errors.NewValidationError("team ID is required")
	}

	// Use GORM to save the team
	result := r.db.WithContext(ctx).Save(team)
	if result.Error != nil {
		r.logger.Error("Failed to update team", "error", result.Error, "team_id", team.ID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to update team")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team updated successfully", "team_id", team.ID)
	return nil
}

// DeleteTeam soft deletes a team using GORM
func (r *GORMRepository) DeleteTeam(ctx context.Context, id string) error {
	if id == "" {
		return errors.NewValidationError("team ID is required")
	}

	// Use GORM's Delete method for soft delete
	result := r.db.WithContext(ctx).Delete(&models.Team{}, "id = ?", id)
	if result.Error != nil {
		r.logger.Error("Failed to delete team", "error", result.Error, "team_id", id)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to delete team")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("team not found")
	}

	r.logger.Info("Team deleted successfully", "team_id", id)
	return nil
}

// ListTeams lists teams for a user using GORM with joins
func (r *GORMRepository) ListTeams(ctx context.Context, userID string) ([]*Team, error) {
	if userID == "" {
		return nil, errors.NewValidationError("user ID is required")
	}

	var teams []*Team
	
	// Use GORM to perform the join and retrieve teams
	result := r.db.WithContext(ctx).
		Table("teams t").
		Select("t.*").
		Joins("JOIN team_members tm ON t.id = tm.team_id").
		Where("tm.user_id = ?", userID).
		Order("t.created_at DESC").
		Find(&teams)

	if result.Error != nil {
		r.logger.Error("Failed to list teams", "error", result.Error, "user_id", userID)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to list teams")
	}

	r.logger.Info("Teams listed successfully", "count", len(teams), "user_id", userID)
	return teams, nil
}

// AddMember adds a member to a team using GORM
func (r *GORMRepository) AddMember(ctx context.Context, member *TeamMember) error {
	if member == nil {
		return errors.NewValidationError("team member cannot be nil")
	}

	// Use GORM to create the team member
	result := r.db.WithContext(ctx).Create(member)
	if result.Error != nil {
		r.logger.Error("Failed to add team member", "error", result.Error,
			"team_id", member.TeamID, "user_id", member.UserID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to add team member")
	}

	r.logger.Info("Team member added successfully",
		"team_id", member.TeamID, "user_id", member.UserID, "role", member.Role)
	return nil
}

// RemoveMember removes a member from a team using GORM
func (r *GORMRepository) RemoveMember(ctx context.Context, teamID, userID string) error {
	if teamID == "" {
		return errors.NewValidationError("team ID is required")
	}
	if userID == "" {
		return errors.NewValidationError("user ID is required")
	}

	// Use GORM to delete the team member
	result := r.db.WithContext(ctx).Delete(&models.TeamMember{}, "team_id = ? AND user_id = ?", teamID, userID)
	if result.Error != nil {
		r.logger.Error("Failed to remove team member", "error", result.Error,
			"team_id", teamID, "user_id", userID)
		return errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to remove team member")
	}

	if result.RowsAffected == 0 {
		return errors.NewNotFoundError("team member not found")
	}

	r.logger.Info("Team member removed successfully",
		"team_id", teamID, "user_id", userID)
	return nil
}

// ListMembers lists members of a team using GORM
func (r *GORMRepository) ListMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	if teamID == "" {
		return nil, errors.NewValidationError("team ID is required")
	}

	var members []*TeamMember
	result := r.db.WithContext(ctx).Where("team_id = ?", teamID).Order("joined_at ASC").Find(&members)
	if result.Error != nil {
		r.logger.Error("Failed to list team members", "error", result.Error, "team_id", teamID)
		return nil, errors.New(errors.ErrorTypeInternal, errors.CodeInternal, "failed to list team members")
	}

	r.logger.Info("Team members listed successfully", "count", len(members), "team_id", teamID)
	return members, nil
}