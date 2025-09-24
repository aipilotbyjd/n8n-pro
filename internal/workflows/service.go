package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/credentials"
	"n8n-pro/internal/storage/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"
	"n8n-pro/pkg/utils"

	"github.com/jackc/pgx/v5"
)

// Service represents the workflow service
type Service struct {
	Repo        Repository
	DB          *postgres.DB
	Config      *config.Config
	Logger      logger.Logger
	Metrics     *metrics.Metrics
	Validator   Validator
	Executor    Executor
	TemplateSvc TemplateService
	CredSvc     CredentialService
}

// Repository defines the workflow data access interface
type Repository interface {
	// Workflow CRUD
	Create(ctx context.Context, workflow *Workflow) error
	GetByID(ctx context.Context, id string) (*Workflow, error)
	GetByIDWithDetails(ctx context.Context, id string) (*Workflow, error)
	Update(ctx context.Context, workflow *Workflow) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *WorkflowListFilter) ([]*Workflow, int64, error)

	// Execution CRUD
	CreateExecution(ctx context.Context, execution *WorkflowExecution) error
	GetExecutionByID(ctx context.Context, id string) (*WorkflowExecution, error)
	UpdateExecution(ctx context.Context, execution *WorkflowExecution) error
	ListExecutions(ctx context.Context, filter *ExecutionListFilter) ([]*WorkflowExecution, int64, error)
	DeleteExecution(ctx context.Context, id string) error

	// Version management
	CreateVersion(ctx context.Context, version *WorkflowVersion) error
	GetVersions(ctx context.Context, workflowID string) ([]*WorkflowVersion, error)
	GetVersionByNumber(ctx context.Context, workflowID string, version int) (*WorkflowVersion, error)

	// Templates
	CreateTemplate(ctx context.Context, template *WorkflowTemplate) error
	GetTemplateByID(ctx context.Context, id string) (*WorkflowTemplate, error)
	ListTemplates(ctx context.Context, filter *TemplateListFilter) ([]*WorkflowTemplate, int64, error)

	// Sharing
	CreateShare(ctx context.Context, share *WorkflowShare) error
	GetShares(ctx context.Context, workflowID string) ([]*WorkflowShare, error)
	DeleteShare(ctx context.Context, id string) error

	// Analytics
	GetExecutionSummary(ctx context.Context, workflowID string, period string) (*ExecutionSummary, error)
	GetWorkflowMetrics(ctx context.Context, workflowID string, period string) (*WorkflowMetrics, error)
	GetTeamMetrics(ctx context.Context, teamID string, period string) (*TeamMetrics, error)

	// Tags
	CreateTag(ctx context.Context, tag *Tag) error
	GetTagsByWorkflow(ctx context.Context, workflowID string) ([]*Tag, error)
	ListTags(ctx context.Context, teamID string) ([]*Tag, error)
}

// Validator defines the workflow validation interface
type Validator interface {
	ValidateWorkflow(ctx context.Context, workflow *Workflow) error
	ValidateExecution(ctx context.Context, execution *WorkflowExecution) error
	ValidatePermissions(ctx context.Context, userID, teamID, workflowID string, action string) error
}

// Executor defines the workflow execution interface
type Executor interface {
	Execute(ctx context.Context, execution *WorkflowExecution) error
	Cancel(ctx context.Context, executionID string) error
	Pause(ctx context.Context, executionID string) error
	Resume(ctx context.Context, executionID string) error
	Retry(ctx context.Context, executionID string) (*WorkflowExecution, error)
}

// TemplateService defines the template service interface
type TemplateService interface {
	CreateFromWorkflow(ctx context.Context, workflowID string, template *WorkflowTemplate) (*WorkflowTemplate, error)
	InstantiateTemplate(ctx context.Context, templateID, teamID, ownerID string) (*Workflow, error)
}

// DefaultTemplateService implements the TemplateService interface
type DefaultTemplateService struct {
	repo   Repository
	logger logger.Logger
}

// NewDefaultTemplateService creates a new default template service
func NewDefaultTemplateService(repo Repository, logger logger.Logger) TemplateService {
	return &DefaultTemplateService{
		repo:   repo,
		logger: logger,
	}
}

func (s *DefaultTemplateService) CreateFromWorkflow(ctx context.Context, workflowID string, template *WorkflowTemplate) (*WorkflowTemplate, error) {
	// Get the workflow to use as template source
	workflow, err := s.repo.GetByIDWithDetails(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	
	if workflow == nil {
		return nil, errors.NotFoundError("workflow")
	}

	// Set template fields if not provided
	if template.ID == "" {
		template.ID = GenerateID()
	}
	if template.Name == "" {
		template.Name = workflow.Name + " Template"
	}
	if template.Description == "" {
		template.Description = workflow.Description
	}

	// Serialize workflow as template definition
	definition, err := json.Marshal(workflow)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize workflow as template")
	}
	template.Definition = string(definition)

	now := time.Now()
	template.CreatedAt = now
	template.UpdatedAt = now

	// Save the template
	err = s.repo.CreateTemplate(ctx, template)
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "Template created from workflow", 
		"template_id", template.ID, 
		"workflow_id", workflowID)

	return template, nil
}

func (s *DefaultTemplateService) InstantiateTemplate(ctx context.Context, templateID, teamID, ownerID string) (*Workflow, error) {
	template, err := s.repo.GetTemplateByID(ctx, templateID)
	if err != nil {
		return nil, err
	}
	
	if template == nil {
		return nil, errors.NotFoundError("template")
	}

	// Parse definition to create new workflow
	var workflow Workflow
	if err := json.Unmarshal([]byte(template.Definition), &workflow); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize template definition")
	}

	// Set new workflow fields
	newWorkflow := &Workflow{
		ID:          GenerateID(),
		Name:        workflow.Name,
		Description: workflow.Description,
		Status:      WorkflowStatusDraft,
		TeamID:      teamID,
		OwnerID:     ownerID,
		Version:     1,
		IsTemplate:  false,
		TemplateID:  &templateID,
		Nodes:       workflow.Nodes,
		Connections: workflow.Connections,
		Variables:   workflow.Variables,
		Triggers:    workflow.Triggers,
		Config:      workflow.Config,
		Tags:        workflow.Tags,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   ownerID,
		UpdatedBy:   ownerID,
	}
	
	// Update node IDs to avoid conflicts
	for i := range newWorkflow.Nodes {
		newWorkflow.Nodes[i].ID = GenerateID()
	}

	err = s.repo.Create(ctx, newWorkflow)
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "Workflow created from template", 
		"new_workflow_id", newWorkflow.ID, 
		"template_id", templateID)

	return newWorkflow, nil
}

// CredentialService defines the credential service interface
type CredentialService interface {
	ValidateCredentials(ctx context.Context, credentialIDs []string, teamID string) error
	GetCredentialsByIDs(ctx context.Context, credentialIDs []string) (map[string]interface{}, error)
}

// DefaultCredentialService implements the CredentialService interface
type DefaultCredentialService struct {
	manager *credentials.Manager
}

// NewDefaultCredentialService creates a new default credential service
func NewDefaultCredentialService(manager *credentials.Manager) CredentialService {
	return &DefaultCredentialService{
		manager: manager,
	}
}

func (s *DefaultCredentialService) ValidateCredentials(ctx context.Context, credentialIDs []string, teamID string) error {
	// For each credential ID, check if it exists and belongs to the team
	for _, credID := range credentialIDs {
		cred, err := s.manager.GetByID(ctx, "temp_user_id", teamID, credID) // Use a placeholder user ID since we only need to validate team access
		if err != nil {
			return err
		}
		if cred == nil {
			return errors.NotFoundError("credential " + credID)
		}
	}
	return nil
}

func (s *DefaultCredentialService) GetCredentialsByIDs(ctx context.Context, credentialIDs []string) (map[string]interface{}, error) {
	credentialsMap := make(map[string]interface{})
	
	for _, credID := range credentialIDs {
		credData, err := s.manager.GetDecryptedData(ctx, credID, "temp_user_id", "temp_team_id") // Placeholder IDs
		if err != nil {
			return nil, err
		}
		credentialsMap[credID] = credData
	}
	
	return credentialsMap, nil
}

// Additional filter types
type TemplateListFilter struct {
	Category  *string  `json:"category,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	IsPublic  *bool    `json:"is_public,omitempty"`
	AuthorID  *string  `json:"author_id,omitempty"`
	Search    *string  `json:"search,omitempty"`
	Limit     int      `json:"limit"`
	Offset    int      `json:"offset"`
	SortBy    string   `json:"sort_by"`
	SortOrder string   `json:"sort_order"`
}

type TeamMetrics struct {
	TeamID              string          `json:"team_id"`
	TotalWorkflows      int64           `json:"total_workflows"`
	ActiveWorkflows     int64           `json:"active_workflows"`
	TotalExecutions     int64           `json:"total_executions"`
	SuccessfulRuns      int64           `json:"successful_runs"`
	FailedRuns          int64           `json:"failed_runs"`
	AverageRuntime      float64         `json:"average_runtime"`
	SuccessRate         float64         `json:"success_rate"`
	ExecutionsToday     int64           `json:"executions_today"`
	ExecutionsThisWeek  int64           `json:"executions_this_week"`
	ExecutionsThisMonth int64           `json:"executions_this_month"`
	TopWorkflows        []WorkflowStats `json:"top_workflows"`
	LastActivity        *time.Time      `json:"last_activity,omitempty"`
}

type WorkflowStats struct {
	WorkflowID   string  `json:"workflow_id"`
	WorkflowName string  `json:"workflow_name"`
	Executions   int64   `json:"executions"`
	SuccessRate  float64 `json:"success_rate"`
}

// NewService creates a new workflow service instance
func NewService(
	repo Repository,
	db *postgres.DB,
	config *config.Config,
	validator Validator,
	executor Executor,
	templateSvc TemplateService,
	credSvc CredentialService,
) *Service {
	return &Service{
		Repo:        repo,
		DB:          db,
		Config:      config,
		Logger:      logger.New("workflow-service"),
		Metrics:     metrics.GetGlobal(),
		Validator:   validator,
		Executor:    executor,
		TemplateSvc: templateSvc,
		CredSvc:     credSvc,
	}
}

// CreateWorkflow creates a new workflow
func (s *Service) Create(ctx context.Context, workflow *Workflow, userID string) (*Workflow, error) {
	s.Logger.InfoContext(ctx, "Creating new workflow",
		"workflow_name", workflow.Name,
		"team_id", workflow.TeamID,
		"user_id", userID,
	)

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, "", "create"); err != nil {
		return nil, err
	}

	// Validate workflow
	if err := s.Validator.ValidateWorkflow(ctx, workflow); err != nil {
		return nil, err
	}

	// Validate credentials
	var credentialIDs []string
	for _, node := range workflow.Nodes {
		for _, cred := range node.Credentials {
			credentialIDs = append(credentialIDs, cred.ID)
		}
	}
	if len(credentialIDs) > 0 {
		if err := s.CredSvc.ValidateCredentials(ctx, credentialIDs, workflow.TeamID); err != nil {
			return nil, err
		}
	}

	// Set audit fields
	now := time.Now()
	if workflow.ID == "" {
		workflow.ID = GenerateID()
	}
	workflow.CreatedAt = now
	workflow.UpdatedAt = now
	workflow.CreatedBy = userID
	workflow.UpdatedBy = userID

	// Create in transaction
	err := s.DB.RunInTransaction(ctx, func(tx pgx.Tx) error {
		if err := s.Repo.Create(ctx, workflow); err != nil {
			return err
		}

		// Create initial version
		version := &WorkflowVersion{
			ID:          GenerateID(),
			WorkflowID:  workflow.ID,
			Version:     1,
			Name:        workflow.Name,
			Description: workflow.Description,
			IsActive:    true,
			CreatedAt:   now,
			CreatedBy:   userID,
		}

		// Serialize definition
		definition, err := json.Marshal(workflow)
		if err != nil {
			return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
				"failed to serialize workflow definition")
		}
		version.Definition = string(definition)
		version.Hash = utils.GenerateHash(string(definition))

		return s.Repo.CreateVersion(ctx, version)
	})

	if err != nil {
		s.Logger.ErrorContext(ctx, "Failed to create workflow",
			"error", err,
			"workflow_name", workflow.Name,
		)
		return nil, err
	}

	s.Metrics.RecordDBQuery("create", "workflows", "success", time.Since(now))
	s.Logger.InfoContext(ctx, "Workflow created successfully",
		"workflow_id", workflow.ID,
		"workflow_name", workflow.Name,
	)

	return workflow, nil
}

// GetByID retrieves a workflow by ID
func (s *Service) GetByID(ctx context.Context, id string, userID string) (*Workflow, error) {
	start := time.Now()

	workflow, err := s.Repo.GetByIDWithDetails(ctx, id)
	if err != nil {
		s.Metrics.RecordDBQuery("get", "workflows", "error", time.Since(start))
		return nil, err
	}

	if workflow == nil {
		return nil, errors.NotFoundError("workflow")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, id, "read"); err != nil {
		return nil, err
	}

	s.Metrics.RecordDBQuery("get", "workflows", "success", time.Since(start))
	return workflow, nil
}

// Update updates an existing workflow
func (s *Service) Update(ctx context.Context, workflow *Workflow, userID string) (*Workflow, error) {
	s.Logger.InfoContext(ctx, "Updating workflow",
		"workflow_id", workflow.ID,
		"workflow_name", workflow.Name,
		"user_id", userID,
	)

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, workflow.ID, "update"); err != nil {
		return nil, err
	}

	// Get existing workflow
	existing, err := s.Repo.GetByID(ctx, workflow.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.NotFoundError("workflow")
	}

	// Validate workflow
	if err := s.Validator.ValidateWorkflow(ctx, workflow); err != nil {
		return nil, err
	}

	// Check if definition changed
	definitionChanged := s.hasDefinitionChanged(existing, workflow)

	// Set audit fields
	now := time.Now()
	workflow.UpdatedAt = now
	workflow.UpdatedBy = userID
	workflow.Version = existing.Version

	// If definition changed, create new version
	if definitionChanged {
		workflow.Version++
	}

	// Update in transaction
	err = s.DB.RunInTransaction(ctx, func(tx pgx.Tx) error {
		if err := s.Repo.Update(ctx, workflow); err != nil {
			return err
		}

		if definitionChanged {
			// Create new version
			version := &WorkflowVersion{
				ID:          GenerateID(),
				WorkflowID:  workflow.ID,
				Version:     workflow.Version,
				Name:        workflow.Name,
				Description: workflow.Description,
				IsActive:    true,
				CreatedAt:   now,
				CreatedBy:   userID,
			}

			// Serialize definition
			definition, err := json.Marshal(workflow)
			if err != nil {
				return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
					"failed to serialize workflow definition")
			}
			version.Definition = string(definition)
			version.Hash = utils.GenerateHash(string(definition))

			// Deactivate previous versions
			versions, err := s.Repo.GetVersions(ctx, workflow.ID)
			if err != nil {
				return err
			}
			for _, v := range versions {
				if v.IsActive && v.Version != workflow.Version {
					v.IsActive = false
					// Update version (would need repository method)
				}
			}

			return s.Repo.CreateVersion(ctx, version)
		}

		return nil
	})

	if err != nil {
		s.Logger.ErrorContext(ctx, "Failed to update workflow",
			"error", err,
			"workflow_id", workflow.ID,
		)
		return nil, err
	}

	s.Logger.InfoContext(ctx, "Workflow updated successfully",
		"workflow_id", workflow.ID,
		"version", workflow.Version,
		"definition_changed", definitionChanged,
	)

	return workflow, nil
}

// Delete deletes a workflow
func (s *Service) Delete(ctx context.Context, id string, userID string) error {
	s.Logger.InfoContext(ctx, "Deleting workflow",
		"workflow_id", id,
		"user_id", userID,
	)

	// Get workflow to validate permissions
	workflow, err := s.Repo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if workflow == nil {
		return errors.NotFoundError("workflow")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, id, "delete"); err != nil {
		return err
	}

	// Check for active executions
	filter := &ExecutionListFilter{
		WorkflowID: &id,
		Status:     &[]ExecutionStatus{ExecutionStatusRunning, ExecutionStatusPending}[0],
		Limit:      1,
	}
	executions, _, err := s.Repo.ListExecutions(ctx, filter)
	if err != nil {
		return err
	}
	if len(executions) > 0 {
		return errors.ConflictError("workflow has active executions")
	}

	// Soft delete
	if err := s.Repo.Delete(ctx, id); err != nil {
		s.Logger.ErrorContext(ctx, "Failed to delete workflow",
			"error", err,
			"workflow_id", id,
		)
		return err
	}

	s.Logger.InfoContext(ctx, "Workflow deleted successfully",
		"workflow_id", id,
	)

	return nil
}

// List retrieves workflows with filtering and pagination
func (s *Service) List(ctx context.Context, filter *WorkflowListFilter, userID string) ([]*Workflow, int64, error) {
	start := time.Now()

	// Validate permissions for team access
	if filter.TeamID != nil {
		if err := s.Validator.ValidatePermissions(ctx, userID, *filter.TeamID, "", "list"); err != nil {
			return nil, 0, err
		}
	}

	workflows, total, err := s.Repo.List(ctx, filter)
	if err != nil {
		s.Metrics.RecordDBQuery("list", "workflows", "error", time.Since(start))
		return nil, 0, err
	}

	s.Metrics.RecordDBQuery("list", "workflows", "success", time.Since(start))
	s.Logger.InfoContext(ctx, "Listed workflows",
		"count", len(workflows),
		"total", total,
		"filter", filter,
	)

	return workflows, total, nil
}

// Execute starts a new workflow execution
func (s *Service) Execute(ctx context.Context, workflowID string, triggerData map[string]interface{}, userID string, mode string) (*WorkflowExecution, error) {
	s.Logger.InfoContext(ctx, "Starting workflow execution",
		"workflow_id", workflowID,
		"mode", mode,
		"user_id", userID,
	)

	// Get workflow
	workflow, err := s.Repo.GetByIDWithDetails(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if workflow == nil {
		return nil, errors.NotFoundError("workflow")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, workflowID, "execute"); err != nil {
		return nil, err
	}

	// Check if workflow is executable
	if !workflow.IsExecutable() {
		return nil, errors.ValidationError(errors.CodeInvalidInput, "workflow is not executable")
	}

	// Check concurrent execution limits
	if err := s.checkConcurrentExecutionLimits(ctx, workflowID, workflow.Config.MaxConcurrentRuns); err != nil {
		return nil, err
	}

	// Create execution
	execution := NewWorkflowExecution(workflowID, workflow.Name, workflow.TeamID, triggerData)
	execution.Mode = mode
	execution.NodesTotal = len(workflow.Nodes)

	// Validate execution
	if err := s.Validator.ValidateExecution(ctx, execution); err != nil {
		return nil, err
	}

	// Save execution
	if err := s.Repo.CreateExecution(ctx, execution); err != nil {
		return nil, err
	}

	// Start execution asynchronously
	go func() {
		execCtx := context.Background() // Use background context for async execution
		if err := s.Executor.Execute(execCtx, execution); err != nil {
			s.Logger.ErrorContext(execCtx, "Execution failed",
				"execution_id", execution.ID,
				"workflow_id", workflowID,
				"error", err,
			)
		}
	}()

	// Update workflow statistics
	go s.updateWorkflowStats(context.Background(), workflowID)

	s.Metrics.RecordWorkflowExecution(workflowID, workflow.Name, string(execution.Status), workflow.TeamID, 0)
	s.Logger.InfoContext(ctx, "Workflow execution started",
		"execution_id", execution.ID,
		"workflow_id", workflowID,
	)

	return execution, nil
}

// GetExecution retrieves a workflow execution
func (s *Service) GetExecution(ctx context.Context, executionID string, userID string) (*WorkflowExecution, error) {
		execution, err := s.Repo.GetExecutionByID(ctx, executionID)
	if err != nil {
		s.Logger.ErrorContext(ctx, "Failed to get execution",
			"execution_id", executionID,
			"error", err,
		)
		return nil, err
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, execution.TeamID, execution.WorkflowID, "read"); err != nil {
		return nil, err
	}

	return execution, nil
}

// CancelExecution cancels a running workflow execution
func (s *Service) CancelExecution(ctx context.Context, executionID string, userID string) error {
	execution, err := s.Repo.GetExecutionByID(ctx, executionID)
	if err != nil {
		return err
	}
	if execution == nil {
		return errors.NotFoundError("execution")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, execution.TeamID, execution.WorkflowID, "execute"); err != nil {
		return err
	}

	if !execution.IsRunning() {
		return errors.ValidationError(errors.CodeInvalidInput, "execution is not running")
	}

	return s.Executor.Cancel(ctx, executionID)
}

// RetryExecution retries a failed workflow execution
func (s *Service) RetryExecution(ctx context.Context, executionID string, userID string) (*WorkflowExecution, error) {
	execution, err := s.Repo.GetExecutionByID(ctx, executionID)
	if err != nil {
		return nil, err
	}
	if execution == nil {
		return nil, errors.NotFoundError("execution")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, execution.TeamID, execution.WorkflowID, "execute"); err != nil {
		return nil, err
	}

	if execution.Status != ExecutionStatusFailed {
		return nil, errors.ValidationError(errors.CodeInvalidInput, "can only retry failed executions")
	}

	return s.Executor.Retry(ctx, executionID)
}

// ListExecutions retrieves executions with filtering and pagination
func (s *Service) ListExecutions(ctx context.Context, filter *ExecutionListFilter, userID string) ([]*WorkflowExecution, int64, error) {
	start := time.Now()

	// Validate permissions
	if filter.TeamID != nil {
		if err := s.Validator.ValidatePermissions(ctx, userID, *filter.TeamID, "", "list"); err != nil {
			return nil, 0, err
		}
	}
	if filter.WorkflowID != nil {
		// Get workflow to check team permissions
		workflow, err := s.Repo.GetByID(ctx, *filter.WorkflowID)
		if err != nil {
			return nil, 0, err
		}
		if workflow != nil {
			if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, *filter.WorkflowID, "read"); err != nil {
				return nil, 0, err
			}
		}
	}

	executions, total, err := s.Repo.ListExecutions(ctx, filter)
	if err != nil {
		s.Metrics.RecordDBQuery("list", "executions", "error", time.Since(start))
		return nil, 0, err
	}

	s.Metrics.RecordDBQuery("list", "executions", "success", time.Since(start))
	return executions, total, nil
}

// GetWorkflowMetrics retrieves workflow execution metrics
func (s *Service) GetWorkflowMetrics(ctx context.Context, workflowID string, period string, userID string) (*WorkflowMetrics, error) {
	// Get workflow to validate permissions
	workflow, err := s.Repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if workflow == nil {
		return nil, errors.NotFoundError("workflow")
	}

	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, workflowID, "read"); err != nil {
		return nil, err
	}

	return s.Repo.GetWorkflowMetrics(ctx, workflowID, period)
}

// GetTeamMetrics retrieves team-level workflow metrics
func (s *Service) GetTeamMetrics(ctx context.Context, teamID string, period string, userID string) (*TeamMetrics, error) {
	// Validate permissions
	if err := s.Validator.ValidatePermissions(ctx, userID, teamID, "", "read"); err != nil {
		return nil, err
	}

	return s.Repo.GetTeamMetrics(ctx, teamID, period)
}

// Helper methods

// hasDefinitionChanged checks if the workflow definition has changed
func (s *Service) hasDefinitionChanged(old, new *Workflow) bool {
	oldDef, _ := json.Marshal(struct {
		Nodes       []Node         `json:"nodes"`
		Connections []Connection   `json:"connections"`
		Variables   []Variable     `json:"variables"`
		Triggers    []Trigger      `json:"triggers"`
		Config      WorkflowConfig `json:"config"`
	}{
		Nodes:       old.Nodes,
		Connections: old.Connections,
		Variables:   old.Variables,
		Triggers:    old.Triggers,
		Config:      old.Config,
	})

	newDef, _ := json.Marshal(struct {
		Nodes       []Node         `json:"nodes"`
		Connections []Connection   `json:"connections"`
		Variables   []Variable     `json:"variables"`
		Triggers    []Trigger      `json:"triggers"`
		Config      WorkflowConfig `json:"config"`
	}{
		Nodes:       new.Nodes,
		Connections: new.Connections,
		Variables:   new.Variables,
		Triggers:    new.Triggers,
		Config:      new.Config,
	})

	return utils.GenerateHash(string(oldDef)) != utils.GenerateHash(string(newDef))
}

// checkConcurrentExecutionLimits verifies concurrent execution limits
func (s *Service) checkConcurrentExecutionLimits(ctx context.Context, workflowID string, maxConcurrent int) error {
	filter := &ExecutionListFilter{
		WorkflowID: &workflowID,
		Status:     &[]ExecutionStatus{ExecutionStatusRunning, ExecutionStatusPending}[0],
		Limit:      maxConcurrent + 1,
	}

	executions, _, err := s.Repo.ListExecutions(ctx, filter)
	if err != nil {
		return err
	}

	if len(executions) >= maxConcurrent {
		return errors.ValidationError(errors.CodeRateLimit,
			fmt.Sprintf("maximum concurrent executions reached (%d)", maxConcurrent))
	}

	return nil
}

// updateWorkflowStats updates workflow execution statistics
func (s *Service) updateWorkflowStats(ctx context.Context, workflowID string) {
	summary, err := s.Repo.GetExecutionSummary(ctx, workflowID, "all")
	if err != nil {
		s.Logger.ErrorContext(ctx, "Failed to get execution summary",
			"workflow_id", workflowID,
			"error", err,
		)
		return
	}

	// Update workflow with latest stats
	workflow, err := s.Repo.GetByID(ctx, workflowID)
	if err != nil {
		return
	}

	workflow.ExecutionCount = summary.TotalCount
	workflow.SuccessRate = summary.SuccessRate
	workflow.AverageRuntime = summary.AverageRuntime
	if summary.LastExecution != nil {
		workflow.LastExecutedAt = summary.LastExecution
	}

	s.Repo.Update(ctx, workflow)
}

// ValidateWorkflowAccess validates if user has access to workflow
func (s *Service) ValidateWorkflowAccess(ctx context.Context, workflowID, userID, action string) error {
	workflow, err := s.Repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}
	if workflow == nil {
		return errors.NotFoundError("workflow")
	}

	return s.Validator.ValidatePermissions(ctx, userID, workflow.TeamID, workflowID, action)
}

// GetWorkflowVersions retrieves all versions of a workflow
func (s *Service) GetWorkflowVersions(ctx context.Context, workflowID string, userID string) ([]*WorkflowVersion, error) {
	// Validate access
	if err := s.ValidateWorkflowAccess(ctx, workflowID, userID, "read"); err != nil {
		return nil, err
	}

	return s.Repo.GetVersions(ctx, workflowID)
}

// GetWorkflowVersion retrieves a specific version of a workflow
func (s *Service) GetWorkflowVersion(ctx context.Context, workflowID string, version int, userID string) (*WorkflowVersion, error) {
	// Validate access
	if err := s.ValidateWorkflowAccess(ctx, workflowID, userID, "read"); err != nil {
		return nil, err
	}

	return s.Repo.GetVersionByNumber(ctx, workflowID, version)
}
