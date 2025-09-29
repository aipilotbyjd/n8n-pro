package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserService interface for user-related operations
type UserService interface {
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

// User represents a user in the system
type User struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	TeamID string `json:"team_id"`
	Active bool   `json:"active"`
}

// Validator interface for workflow validation
type Validator interface {
	Validate(ctx context.Context, workflow *Workflow) error
}

// Executor interface for workflow execution
type Executor interface {
	Execute(ctx context.Context, workflow *Workflow, inputData map[string]interface{}) (*WorkflowExecution, error)
}

// TemplateService interface for workflow templates
type TemplateService interface {
	GetTemplate(ctx context.Context, templateID string) (*Workflow, error)
	GetPublicTemplates(ctx context.Context) ([]*Workflow, error)
}

// CredentialService interface for credential management
type CredentialService interface {
	ValidateCredentials(ctx context.Context, workflow *Workflow) error
}

// Service represents the workflow domain service
type Service struct {
	repo             Repository
	userService      UserService
	validator        Validator
	executor         Executor
	templateSvc      TemplateService
	credSvc          CredentialService
	defaultValidator *DefaultValidator
}

// NewService creates a new workflow service
func NewService(
	repo Repository,
	userService UserService,
	validator Validator,
	executor Executor,
	templateSvc TemplateService,
	credSvc CredentialService,
) *Service {
	return &Service{
		repo:             repo,
		userService:      userService,
		validator:        validator,
		executor:         executor,
		templateSvc:      templateSvc,
		credSvc:          credSvc,
		defaultValidator: NewDefaultValidator(userService),
	}
}

// Create creates a new workflow
func (s *Service) Create(ctx context.Context, workflow *Workflow) error {
	if workflow == nil {
		return ValidationError("workflow cannot be nil")
	}

	// Set timestamps
	now := time.Now()
	workflow.CreatedAt = now
	workflow.UpdatedAt = now

	// Set default values if not provided
	if workflow.ID == "" {
		workflow.ID = uuid.New().String()
	}

	// Validate workflow
	validator := s.validator
	if validator == nil {
		validator = s.defaultValidator
	}
	
	if err := validator.Validate(ctx, workflow); err != nil {
		return err
	}

	// Validate credentials if credential service is available
	if s.credSvc != nil {
		if err := s.credSvc.ValidateCredentials(ctx, workflow); err != nil {
			return fmt.Errorf("credential validation failed: %w", err)
		}
	}

	// Create the workflow
	return s.repo.Create(ctx, workflow)
}

// GetByID retrieves a workflow by ID
func (s *Service) GetByID(ctx context.Context, id string) (*Workflow, error) {
	if id == "" {
		return nil, ValidationError("workflow ID cannot be empty")
	}

	workflow, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if user has permission to access this workflow
	// This could involve checking team membership, roles, etc.
	// For now, we'll return the workflow as-is

	return workflow, nil
}

// Update updates an existing workflow
func (s *Service) Update(ctx context.Context, workflow *Workflow) error {
	if workflow == nil {
		return ValidationError("workflow cannot be nil")
	}

	if workflow.ID == "" {
		return ValidationError("workflow ID cannot be empty")
	}

	// Get the existing workflow to validate ownership/permissions
	existing, err := s.repo.GetByID(ctx, workflow.ID)
	if err != nil {
		return err
	}

	// Only update allowed fields
	existing.Name = workflow.Name
	existing.Description = workflow.Description
	existing.Definition = workflow.Definition
	existing.Config = workflow.Config
	existing.Tags = workflow.Tags
	existing.IsTemplate = workflow.IsTemplate
	existing.TemplateID = workflow.TemplateID

	// Update timestamp
	existing.UpdatedAt = time.Now()

	// Validate updated workflow
	validator := s.validator
	if validator == nil {
		validator = s.defaultValidator
	}

	if err := validator.Validate(ctx, existing); err != nil {
		return err
	}

	// Validate credentials if credential service is available
	if s.credSvc != nil {
		if err := s.credSvc.ValidateCredentials(ctx, existing); err != nil {
			return fmt.Errorf("credential validation failed: %w", err)
		}
	}

	return s.repo.Update(ctx, existing)
}

// Delete deletes a workflow by ID
func (s *Service) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ValidationError("workflow ID cannot be empty")
	}

	// Verify workflow exists and user has permission to delete
	_, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Here you could add permission checks based on user roles, team membership, etc.
	// For now, we'll assume the caller has permission

	return s.repo.Delete(ctx, id)
}

// List retrieves workflows based on filters
func (s *Service) List(ctx context.Context, filters map[string]interface{}) ([]*Workflow, error) {
	// Apply additional permission checks based on the user context
	// This could filter workflows based on user's team membership, role, etc.

	return s.repo.List(ctx, filters)
}

// ListByTeam retrieves workflows for a specific team
func (s *Service) ListByTeam(ctx context.Context, teamID string) ([]*Workflow, error) {
	if teamID == "" {
		return nil, ValidationError("team ID cannot be empty")
	}

	filters := map[string]interface{}{"team_id": teamID}
	return s.repo.List(ctx, filters)
}

// ListByOwner retrieves workflows owned by a specific user
func (s *Service) ListByOwner(ctx context.Context, ownerID string) ([]*Workflow, error) {
	if ownerID == "" {
		return nil, ValidationError("owner ID cannot be empty")
	}

	return s.repo.GetByOwner(ctx, ownerID)
}

// Execute executes a workflow with given input data
func (s *Service) Execute(ctx context.Context, workflowID string, inputData map[string]interface{}) (*WorkflowExecution, error) {
	if workflowID == "" {
		return nil, ValidationError("workflow ID cannot be empty")
	}

	workflow, err := s.GetByID(ctx, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow: %w", err)
	}

	// Check if workflow is active
	if workflow.Status != "active" {
		return nil, ValidationError("workflow is not active and cannot be executed")
	}

	// Check if user has permission to execute this workflow
	// This could involve checking team membership, roles, etc.

	// Validate credentials before execution
	if s.credSvc != nil {
		if err := s.credSvc.ValidateCredentials(ctx, workflow); err != nil {
			return nil, fmt.Errorf("credential validation failed: %w", err)
		}
	}

	// Execute the workflow
	if s.executor == nil {
		return nil, errors.New("executor not configured")
	}

	return s.executor.Execute(ctx, workflow, inputData)
}

// Activate activates a workflow
func (s *Service) Activate(ctx context.Context, workflowID string) error {
	workflow, err := s.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	// Validate credentials before activation
	if s.credSvc != nil {
		if err := s.credSvc.ValidateCredentials(ctx, workflow); err != nil {
			return fmt.Errorf("credential validation failed: %w", err)
		}
	}

	workflow.Activate()
	return s.repo.Update(ctx, workflow)
}

// Deactivate deactivates a workflow
func (s *Service) Deactivate(ctx context.Context, workflowID string) error {
	workflow, err := s.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	workflow.Deactivate()
	return s.repo.Update(ctx, workflow)
}

// CreateFromTemplate creates a new workflow from a template
func (s *Service) CreateFromTemplate(ctx context.Context, templateID, ownerID, teamID string, name string) (*Workflow, error) {
	if templateID == "" {
		return nil, ValidationError("template ID cannot be empty")
	}

	if ownerID == "" {
		return nil, ValidationError("owner ID cannot be empty")
	}

	if teamID == "" {
		return nil, ValidationError("team ID cannot be empty")
	}

	// Get the template
	template, err := s.templateSvc.GetTemplate(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Create a new workflow from the template
	newWorkflow := &Workflow{
		ID:          uuid.New().String(),
		Name:        name,
		Description: template.Description,
		Status:      "draft",
		TeamID:      teamID,
		OwnerID:     ownerID,
		Version:     1,
		IsTemplate:  false,
		TemplateID:  templateID,
		Definition:  template.Definition,
		Config:      make(map[string]interface{}),
		Tags:        template.Tags,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   ownerID,
		UpdatedBy:   ownerID,
	}

	// Validate the new workflow
	validator := s.validator
	if validator == nil {
		validator = s.defaultValidator
	}

	if err := validator.Validate(ctx, newWorkflow); err != nil {
		return nil, err
	}

	// Create the workflow
	if err := s.Create(ctx, newWorkflow); err != nil {
		return nil, err
	}

	return newWorkflow, nil
}

// DefaultValidator implements basic workflow validation
type DefaultValidator struct {
	userService UserService
}

// NewDefaultValidator creates a new default validator
func NewDefaultValidator(userService UserService) *DefaultValidator {
	return &DefaultValidator{
		userService: userService,
	}
}

// Validate performs default validation on a workflow
func (v *DefaultValidator) Validate(ctx context.Context, workflow *Workflow) error {
	if workflow == nil {
		return ValidationError("workflow cannot be nil")
	}

	// Basic validation
	if workflow.Name == "" {
		return ValidationError("workflow name is required")
	}

	if len(workflow.Name) > 255 {
		return ValidationError("workflow name cannot exceed 255 characters")
	}

	if workflow.TeamID == "" {
		return ValidationError("team ID is required")
	}

	// Validate UUID format for team ID
	if _, err := uuid.Parse(workflow.TeamID); err != nil {
		return ValidationError("invalid team ID format")
	}

	if workflow.OwnerID == "" {
		return ValidationError("owner ID is required")
	}

	// Validate UUID format for owner ID
	if _, err := uuid.Parse(workflow.OwnerID); err != nil {
		return ValidationError("invalid owner ID format")
	}

	// Validate status
	switch workflow.Status {
	case "draft", "active", "inactive":
		// Valid statuses
	default:
		return ValidationError("invalid status, must be one of: draft, active, inactive")
	}

	// Validate definition exists (even if empty)
	if workflow.Definition == nil {
		workflow.Definition = make(map[string]interface{})
	}

	// Validate config exists (even if empty)
	if workflow.Config == nil {
		workflow.Config = make(map[string]interface{})
	}

	// Validate tags
	if workflow.Tags == nil {
		workflow.Tags = []string{}
	}

	// Validate metadata exists (even if empty)
	if workflow.Metadata == nil {
		workflow.Metadata = make(map[string]interface{})
	}

	// Check if owner belongs to the specified team
	if v.userService != nil {
		user, err := v.userService.GetUserByID(ctx, workflow.OwnerID)
		if err != nil {
			return fmt.Errorf("failed to verify workflow owner: %w", err)
		}

		if user == nil {
			return ValidationError("workflow owner does not exist")
		}

		// Check if user is active
		if !user.Active {
			return ValidationError("workflow owner is not active")
		}
	}

	return nil
}