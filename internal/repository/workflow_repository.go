package repository

import (
	"context"
	"errors"
	"fmt"

	"n8n-pro/internal/domain/workflow"
	"n8n-pro/internal/models"

	"gorm.io/gorm"
)

// WorkflowRepository implements the workflow.Repository interface
type WorkflowRepository struct {
	db *gorm.DB
}

// NewWorkflowRepository creates a new workflow repository
func NewWorkflowRepository(db *gorm.DB) *WorkflowRepository {
	return &WorkflowRepository{
		db: db,
	}
}

// Create creates a new workflow in the database
func (r *WorkflowRepository) Create(ctx context.Context, workflow *workflow.Workflow) error {
	if workflow == nil {
		return errors.New("workflow cannot be nil")
	}

	// Convert domain model to GORM model
	workflowModel := &models.Workflow{
		BaseModel: models.BaseModel{
			ID:        workflow.ID,
			CreatedAt: workflow.CreatedAt,
			UpdatedAt: workflow.UpdatedAt,
		},
		AuditableModel: models.AuditableModel{
			BaseModel: models.BaseModel{
				ID:        workflow.ID,
				CreatedAt: workflow.CreatedAt,
				UpdatedAt: workflow.UpdatedAt,
			},
			CreatedBy: workflow.CreatedBy,
			UpdatedBy: workflow.UpdatedBy,
		},
		Name:           workflow.Name,
		Description:    workflow.Description,
		Status:         workflow.Status,
		TeamID:         workflow.TeamID,
		OwnerID:        workflow.OwnerID,
		Version:        workflow.Version,
		IsTemplate:     workflow.IsTemplate,
		TemplateID:     workflow.TemplateID,
		Definition:     models.JSONB(workflow.Definition),
		Config:         models.JSONB(workflow.Config),
		Tags:           models.StringSlice(workflow.Tags),
		Metadata:       models.JSONB(workflow.Metadata),
		ExecutionCount: workflow.ExecutionCount,
		SuccessRate:    workflow.SuccessRate,
		AverageRuntime: workflow.AverageRuntime,
	}

	// If LastExecutedAt is not nil, set it
	if workflow.LastExecutedAt != nil {
		workflowModel.LastExecutedAt = workflow.LastExecutedAt
	}
	workflowModel.LastExecutionID = workflow.LastExecutionID

	// Create the workflow in the database
	result := r.db.WithContext(ctx).Create(workflowModel)
	if result.Error != nil {
		return fmt.Errorf("failed to create workflow: %w", result.Error)
	}

	// Update the domain model with the created ID if it was auto-generated
	if workflow.ID == "" {
		workflow.ID = workflowModel.ID
	}

	return nil
}

// Update updates an existing workflow in the database
func (r *WorkflowRepository) Update(ctx context.Context, workflow *workflow.Workflow) error {
	if workflow == nil {
		return errors.New("workflow cannot be nil")
	}

	if workflow.ID == "" {
		return errors.New("workflow ID cannot be empty")
	}

	// Convert domain model to GORM model
	workflowModel := &models.Workflow{
		AuditableModel: models.AuditableModel{
			BaseModel: models.BaseModel{
				ID:        workflow.ID,
				CreatedAt: workflow.CreatedAt,
				UpdatedAt: workflow.UpdatedAt,
			},
			CreatedBy: workflow.CreatedBy,
			UpdatedBy: workflow.UpdatedBy,
		},
		Name:           workflow.Name,
		Description:    workflow.Description,
		Status:         workflow.Status,
		TeamID:         workflow.TeamID,
		OwnerID:        workflow.OwnerID,
		Version:        workflow.Version,
		IsTemplate:     workflow.IsTemplate,
		TemplateID:     workflow.TemplateID,
		Definition:     models.JSONB(workflow.Definition),
		Config:         models.JSONB(workflow.Config),
		Tags:           models.StringSlice(workflow.Tags),
		Metadata:       models.JSONB(workflow.Metadata),
		ExecutionCount: workflow.ExecutionCount,
		SuccessRate:    workflow.SuccessRate,
		AverageRuntime: workflow.AverageRuntime,
	}

	// If LastExecutedAt is not nil, set it
	if workflow.LastExecutedAt != nil {
		workflowModel.LastExecutedAt = workflow.LastExecutedAt
	}
	workflowModel.LastExecutionID = workflow.LastExecutionID

	// Update the workflow in the database
	result := r.db.WithContext(ctx).Model(&models.Workflow{}).Where("id = ?", workflow.ID).Updates(workflowModel)
	if result.Error != nil {
		return fmt.Errorf("failed to update workflow: %w", result.Error)
	}

	// Check if any rows were affected
	if result.RowsAffected == 0 {
		return errors.New("workflow not found")
	}

	return nil
}

// Delete removes a workflow from the database
func (r *WorkflowRepository) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("workflow ID cannot be empty")
	}

	// Delete the workflow (soft delete)
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.Workflow{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete workflow: %w", result.Error)
	}

	// Check if any rows were affected
	if result.RowsAffected == 0 {
		return errors.New("workflow not found")
	}

	return nil
}

// GetByID retrieves a workflow by ID
func (r *WorkflowRepository) GetByID(ctx context.Context, id string) (*workflow.Workflow, error) {
	if id == "" {
		return nil, errors.New("workflow ID cannot be empty")
	}

	var workflowModel models.Workflow
	result := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", id).First(&workflowModel)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("workflow not found")
		}
		return nil, fmt.Errorf("failed to get workflow: %w", result.Error)
	}

	// Convert GORM model to domain model
	domainWorkflow := &workflow.Workflow{
		ID:             workflowModel.ID,
		Name:           workflowModel.Name,
		Description:    workflowModel.Description,
		Status:         workflowModel.Status,
		TeamID:         workflowModel.TeamID,
		OwnerID:        workflowModel.OwnerID,
		Version:        workflowModel.Version,
		IsTemplate:     workflowModel.IsTemplate,
		TemplateID:     workflowModel.TemplateID,
		Definition:     map[string]interface{}(workflowModel.Definition),
		Config:         map[string]interface{}(workflowModel.Config),
		Tags:           []string(workflowModel.Tags),
		Metadata:       map[string]interface{}(workflowModel.Metadata),
		ExecutionCount: workflowModel.ExecutionCount,
		SuccessRate:    workflowModel.SuccessRate,
		AverageRuntime: workflowModel.AverageRuntime,
		CreatedAt:      workflowModel.CreatedAt,
		UpdatedAt:      workflowModel.UpdatedAt,
		CreatedBy:      workflowModel.CreatedBy,
		UpdatedBy:      workflowModel.UpdatedBy,
	}

	// Set optional fields
	if workflowModel.LastExecutedAt != nil {
		domainWorkflow.LastExecutedAt = workflowModel.LastExecutedAt
	}
	domainWorkflow.LastExecutionID = workflowModel.LastExecutionID

	return domainWorkflow, nil
}

// GetByOwner retrieves workflows by owner ID
func (r *WorkflowRepository) GetByOwner(ctx context.Context, ownerID string) ([]*workflow.Workflow, error) {
	if ownerID == "" {
		return nil, errors.New("owner ID cannot be empty")
	}

	var workflowModels []models.Workflow
	result := r.db.WithContext(ctx).
		Where("owner_id = ? AND deleted_at IS NULL", ownerID).
		Order("created_at DESC").
		Find(&workflowModels)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to get workflows by owner: %w", result.Error)
	}

	return r.convertModelsToDomain(workflowModels), nil
}

// GetByTeam retrieves workflows by team ID
func (r *WorkflowRepository) GetByTeam(ctx context.Context, teamID string) ([]*workflow.Workflow, error) {
	if teamID == "" {
		return nil, errors.New("team ID cannot be empty")
	}

	var workflowModels []models.Workflow
	result := r.db.WithContext(ctx).
		Where("team_id = ? AND deleted_at IS NULL", teamID).
		Order("created_at DESC").
		Find(&workflowModels)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to get workflows by team: %w", result.Error)
	}

	return r.convertModelsToDomain(workflowModels), nil
}

// List retrieves workflows based on filters
func (r *WorkflowRepository) List(ctx context.Context, filters map[string]interface{}) ([]*workflow.Workflow, error) {
	var workflowModels []models.Workflow

	// Start building the query
	query := r.db.WithContext(ctx).Where("deleted_at IS NULL").Order("created_at DESC")

	// Apply filters
	if status, ok := filters["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}

	if teamID, ok := filters["team_id"].(string); ok && teamID != "" {
		query = query.Where("team_id = ?", teamID)
	}

	if ownerID, ok := filters["owner_id"].(string); ok && ownerID != "" {
		query = query.Where("owner_id = ?", ownerID)
	}

	if name, ok := filters["name"].(string); ok && name != "" {
		query = query.Where("name ILIKE ?", "%"+name+"%")
	}

	if isTemplate, ok := filters["is_template"].(bool); ok {
		query = query.Where("is_template = ?", isTemplate)
	}

	// Execute the query
	result := query.Find(&workflowModels)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to list workflows: %w", result.Error)
	}

	return r.convertModelsToDomain(workflowModels), nil
}

// convertModelsToDomain converts GORM models to domain models
func (r *WorkflowRepository) convertModelsToDomain(workflowModels []models.Workflow) []*workflow.Workflow {
	workflows := make([]*workflow.Workflow, 0, len(workflowModels))

	for _, workflowModel := range workflowModels {
		domainWorkflow := &workflow.Workflow{
			ID:             workflowModel.ID,
			Name:           workflowModel.Name,
			Description:    workflowModel.Description,
			Status:         workflowModel.Status,
			TeamID:         workflowModel.TeamID,
			OwnerID:        workflowModel.OwnerID,
			Version:        workflowModel.Version,
			IsTemplate:     workflowModel.IsTemplate,
			TemplateID:     workflowModel.TemplateID,
			Definition:     map[string]interface{}(workflowModel.Definition),
			Config:         map[string]interface{}(workflowModel.Config),
			Tags:           []string(workflowModel.Tags),
			Metadata:       map[string]interface{}(workflowModel.Metadata),
			ExecutionCount: workflowModel.ExecutionCount,
			SuccessRate:    workflowModel.SuccessRate,
			AverageRuntime: workflowModel.AverageRuntime,
			CreatedAt:      workflowModel.CreatedAt,
			UpdatedAt:      workflowModel.UpdatedAt,
			CreatedBy:      workflowModel.CreatedBy,
			UpdatedBy:      workflowModel.UpdatedBy,
		}

		// Set optional fields
		if workflowModel.LastExecutedAt != nil {
			domainWorkflow.LastExecutedAt = workflowModel.LastExecutedAt
		}
		domainWorkflow.LastExecutionID = workflowModel.LastExecutionID

		workflows = append(workflows, domainWorkflow)
	}

	return workflows
}