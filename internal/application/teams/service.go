package teams

import (
	"context"
	"time"

	"n8n-pro/pkg/logger"
)

// Service handles team operations
type Service struct {
	repo   Repository
	logger logger.Logger
}

// Repository defines the team data access interface
type Repository interface {
	Create(ctx context.Context, team *Team) error
	GetByID(ctx context.Context, id string) (*Team, error)
	GetByName(ctx context.Context, name string) (*Team, error)
	GetByOrganization(ctx context.Context, orgID string) ([]*Team, error)
	GetByUser(ctx context.Context, userID string) ([]*Team, error)
	Update(ctx context.Context, team *Team) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *ListFilter) ([]*Team, int64, error)
	AddUser(ctx context.Context, teamID, userID, role string) error
	RemoveUser(ctx context.Context, teamID, userID string) error
	GetTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error)
}

// Team represents a team entity
type Team struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	OrgID       string                 `json:"organization_id"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// TeamMember represents a team member
type TeamMember struct {
	ID     string    `json:"id"`
	TeamID string    `json:"team_id"`
	UserID string    `json:"user_id"`
	Role   string    `json:"role"`
	Joined time.Time `json:"joined_at"`
}

// ListFilter represents filters for listing teams
type ListFilter struct {
	OrgID  string
	UserID string
	Limit  int
	Offset int
}

// NewService creates a new team service
func NewService(repo Repository, logger logger.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// CreateTeam creates a new team
func (s *Service) CreateTeam(ctx context.Context, team *Team, creatorID string) error {
	s.logger.Info("Creating team", "name", team.Name, "org_id", team.OrgID)

	// Validate team
	if err := s.validateTeam(team); err != nil {
		return err
	}

	// Set defaults
	team.ID = "team_" + team.OrgID // In reality, use proper UUID
	team.CreatedBy = creatorID
	team.CreatedAt = time.Now()
	team.UpdatedAt = time.Now()

	if team.Settings == nil {
		team.Settings = make(map[string]interface{})
	}

	// Create the team
	if err := s.repo.Create(ctx, team); err != nil {
		s.logger.Error("Failed to create team", "name", team.Name, "error", err)
		return err
	}

	// Add creator as team owner
	if err := s.repo.AddUser(ctx, team.ID, creatorID, "owner"); err != nil {
		s.logger.Error("Failed to add creator to team", "team_id", team.ID, "user_id", creatorID, "error", err)
		// Don't return error here as team was created successfully
	}

	s.logger.Info("Team created successfully", "team_id", team.ID)
	return nil
}

// GetTeam retrieves a team by ID
func (s *Service) GetTeam(ctx context.Context, id string) (*Team, error) {
	team, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get team", "team_id", id, "error", err)
		return nil, err
	}
	return team, nil
}

// GetTeamByName retrieves a team by name
func (s *Service) GetTeamByName(ctx context.Context, name string) (*Team, error) {
	team, err := s.repo.GetByName(ctx, name)
	if err != nil {
		s.logger.Error("Failed to get team by name", "name", name, "error", err)
		return nil, err
	}
	return team, nil
}

// GetTeamsByOrganization retrieves teams for an organization
func (s *Service) GetTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	teams, _, err := s.repo.GetByOrganization(ctx, orgID)
	if err != nil {
		s.logger.Error("Failed to get teams by organization", "org_id", orgID, "error", err)
		return nil, err
	}
	return teams, nil
}

// GetTeamsByUser retrieves teams that a user belongs to
func (s *Service) GetTeamsByUser(ctx context.Context, userID string) ([]*Team, error) {
	teams, err := s.repo.GetByUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get teams by user", "user_id", userID, "error", err)
		return nil, err
	}
	return teams, nil
}

// UpdateTeam updates an existing team
func (s *Service) UpdateTeam(ctx context.Context, team *Team) error {
	team.UpdatedAt = time.Now()
	
	if err := s.repo.Update(ctx, team); err != nil {
		s.logger.Error("Failed to update team", "team_id", team.ID, "error", err)
		return err
	}
	
	return nil
}

// DeleteTeam deletes a team by ID
func (s *Service) DeleteTeam(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete team", "team_id", id, "error", err)
		return err
	}
	
	return nil
}

// ListTeams retrieves teams based on filters
func (s *Service) ListTeams(ctx context.Context, filter *ListFilter) ([]*Team, int64, error) {
	return s.repo.List(ctx, filter)
}

// AddUserToTeam adds a user to a team
func (s *Service) AddUserToTeam(ctx context.Context, teamID, userID, role string) error {
	if err := s.repo.AddUser(ctx, teamID, userID, role); err != nil {
		s.logger.Error("Failed to add user to team", "team_id", teamID, "user_id", userID, "error", err)
		return err
	}
	
	return nil
}

// RemoveUserFromTeam removes a user from a team
func (s *Service) RemoveUserFromTeam(ctx context.Context, teamID, userID string) error {
	if err := s.repo.RemoveUser(ctx, teamID, userID); err != nil {
		s.logger.Error("Failed to remove user from team", "team_id", teamID, "user_id", userID, "error", err)
		return err
	}
	
	return nil
}

// GetTeamMembers retrieves members of a team
func (s *Service) GetTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	members, err := s.repo.GetTeamMembers(ctx, teamID)
	if err != nil {
		s.logger.Error("Failed to get team members", "team_id", teamID, "error", err)
		return nil, err
	}
	
	return members, nil
}

// validateTeam validates team data
func (s *Service) validateTeam(team *Team) error {
	if team.Name == "" {
		return ValidationError("team name is required")
	}

	if team.OrgID == "" {
		return ValidationError("organization ID is required")
	}

	if len(team.Name) > 255 {
		return ValidationError("team name cannot exceed 255 characters")
	}

	return nil
}

// ValidationError represents a validation error
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}