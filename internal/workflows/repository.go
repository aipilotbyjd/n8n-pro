package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/storage/postgres"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// PostgresRepository implements the Repository interface using PostgreSQL
type PostgresRepository struct {
	db      *postgres.DB
	logger  logger.Logger
	metrics *metrics.Metrics
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *postgres.DB) Repository {
	return &PostgresRepository{
		db:      db,
		logger:  logger.New("workflow-repository"),
		metrics: metrics.GetGlobal(),
	}
}

// Create creates a new workflow
func (r *PostgresRepository) Create(ctx context.Context, workflow *Workflow) error {
	start := time.Now()

	query := `
		INSERT INTO workflows (
			id, name, description, status, team_id, owner_id, version,
			is_template, template_id, nodes, connections, variables,
			triggers, config, tags, metadata, execution_count,
			success_rate, average_runtime, created_at, updated_at,
			created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)`

	// Serialize complex fields to JSON
	nodesJSON, err := json.Marshal(workflow.Nodes)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize nodes")
	}

	connectionsJSON, err := json.Marshal(workflow.Connections)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize connections")
	}

	variablesJSON, err := json.Marshal(workflow.Variables)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize variables")
	}

	triggersJSON, err := json.Marshal(workflow.Triggers)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize triggers")
	}

	configJSON, err := json.Marshal(workflow.Config)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize config")
	}

	tagsJSON, err := json.Marshal(workflow.Tags)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize tags")
	}

	metadataJSON, err := json.Marshal(workflow.Metadata)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize metadata")
	}

	_, err = r.db.Exec(ctx, query,
		workflow.ID, workflow.Name, workflow.Description, workflow.Status,
		workflow.TeamID, workflow.OwnerID, workflow.Version, workflow.IsTemplate,
		workflow.TemplateID, nodesJSON, connectionsJSON, variablesJSON,
		triggersJSON, configJSON, tagsJSON, metadataJSON,
		workflow.ExecutionCount, workflow.SuccessRate, workflow.AverageRuntime,
		workflow.CreatedAt, workflow.UpdatedAt, workflow.CreatedBy, workflow.UpdatedBy,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "workflows", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create workflow")
	}

	r.metrics.RecordDBQuery("create", "workflows", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow created", "workflow_id", workflow.ID)
	return nil
}

// GetByID retrieves a workflow by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id string) (*Workflow, error) {
	start := time.Now()

	query := `
		SELECT id, name, description, status, team_id, owner_id, version,
			   is_template, template_id, nodes, connections, variables,
			   triggers, config, tags, metadata, execution_count,
			   last_executed_at, last_execution_id, success_rate, average_runtime,
			   created_at, updated_at, deleted_at, created_by, updated_by
		FROM workflows
		WHERE id = $1 AND deleted_at IS NULL`

	var workflow Workflow
	var nodesJSON, connectionsJSON, variablesJSON, triggersJSON []byte
	var configJSON, tagsJSON, metadataJSON []byte
	var lastExecutedAt pgtype.Timestamptz
	var templateID, lastExecutionID *string
	var deletedAt pgtype.Timestamptz

	err := r.db.QueryRow(ctx, query, id).Scan(
		&workflow.ID, &workflow.Name, &workflow.Description, &workflow.Status,
		&workflow.TeamID, &workflow.OwnerID, &workflow.Version,
		&workflow.IsTemplate, &templateID, &nodesJSON, &connectionsJSON,
		&variablesJSON, &triggersJSON, &configJSON, &tagsJSON, &metadataJSON,
		&workflow.ExecutionCount, &lastExecutedAt, &lastExecutionID,
		&workflow.SuccessRate, &workflow.AverageRuntime,
		&workflow.CreatedAt, &workflow.UpdatedAt, &deletedAt,
		&workflow.CreatedBy, &workflow.UpdatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.metrics.RecordDBQuery("get", "workflows", "not_found", time.Since(start))
			return nil, nil
		}
		r.metrics.RecordDBQuery("get", "workflows", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow")
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(nodesJSON, &workflow.Nodes); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize nodes")
	}

	if err := json.Unmarshal(connectionsJSON, &workflow.Connections); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize connections")
	}

	if err := json.Unmarshal(variablesJSON, &workflow.Variables); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize variables")
	}

	if err := json.Unmarshal(triggersJSON, &workflow.Triggers); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize triggers")
	}

	if err := json.Unmarshal(configJSON, &workflow.Config); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize config")
	}

	if err := json.Unmarshal(tagsJSON, &workflow.Tags); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize tags")
	}

	if err := json.Unmarshal(metadataJSON, &workflow.Metadata); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize metadata")
	}

	// Handle nullable fields
	workflow.TemplateID = templateID
	workflow.LastExecutionID = lastExecutionID

	if lastExecutedAt.Valid {
		t := lastExecutedAt.Time
		workflow.LastExecutedAt = &t
	}

	if deletedAt.Valid {
		t := deletedAt.Time
		workflow.DeletedAt = &t
	}

	r.metrics.RecordDBQuery("get", "workflows", "success", time.Since(start))
	return &workflow, nil
}

// GetByIDWithDetails retrieves a workflow by ID with all related data
func (r *PostgresRepository) GetByIDWithDetails(ctx context.Context, id string) (*Workflow, error) {
	// For now, this is the same as GetByID
	// In the future, this could include additional joins for related data
	return r.GetByID(ctx, id)
}

// Update updates an existing workflow
func (r *PostgresRepository) Update(ctx context.Context, workflow *Workflow) error {
	start := time.Now()

	query := `
		UPDATE workflows SET
			name = $2, description = $3, status = $4, version = $5,
			nodes = $6, connections = $7, variables = $8, triggers = $9,
			config = $10, tags = $11, metadata = $12, execution_count = $13,
			last_executed_at = $14, last_execution_id = $15, success_rate = $16,
			average_runtime = $17, updated_at = $18, updated_by = $19
		WHERE id = $1 AND deleted_at IS NULL`

	// Serialize complex fields to JSON
	nodesJSON, err := json.Marshal(workflow.Nodes)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize nodes")
	}

	connectionsJSON, err := json.Marshal(workflow.Connections)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize connections")
	}

	variablesJSON, err := json.Marshal(workflow.Variables)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize variables")
	}

	triggersJSON, err := json.Marshal(workflow.Triggers)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize triggers")
	}

	configJSON, err := json.Marshal(workflow.Config)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize config")
	}

	tagsJSON, err := json.Marshal(workflow.Tags)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize tags")
	}

	metadataJSON, err := json.Marshal(workflow.Metadata)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize metadata")
	}

	result, err := r.db.Exec(ctx, query,
		workflow.ID, workflow.Name, workflow.Description, workflow.Status, workflow.Version,
		nodesJSON, connectionsJSON, variablesJSON, triggersJSON, configJSON,
		tagsJSON, metadataJSON, workflow.ExecutionCount, workflow.LastExecutedAt,
		workflow.LastExecutionID, workflow.SuccessRate, workflow.AverageRuntime,
		workflow.UpdatedAt, workflow.UpdatedBy,
	)

	if err != nil {
		r.metrics.RecordDBQuery("update", "workflows", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to update workflow")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFoundError("workflow")
	}

	r.metrics.RecordDBQuery("update", "workflows", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow updated", "workflow_id", workflow.ID)
	return nil
}

// Delete soft-deletes a workflow
func (r *PostgresRepository) Delete(ctx context.Context, id string) error {
	start := time.Now()

	query := `
		UPDATE workflows
		SET deleted_at = $2, updated_at = $2
		WHERE id = $1 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, id, now)
	if err != nil {
		r.metrics.RecordDBQuery("delete", "workflows", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to delete workflow")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFoundError("workflow")
	}

	r.metrics.RecordDBQuery("delete", "workflows", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow deleted", "workflow_id", id)
	return nil
}

// List retrieves workflows with filtering and pagination
func (r *PostgresRepository) List(ctx context.Context, filter *WorkflowListFilter) ([]*Workflow, int64, error) {
	start := time.Now()

	// Build query conditions
	conditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIndex := 1

	if filter.TeamID != nil {
		conditions = append(conditions, fmt.Sprintf("team_id = $%d", argIndex))
		args = append(args, *filter.TeamID)
		argIndex++
	}

	if filter.OwnerID != nil {
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", argIndex))
		args = append(args, *filter.OwnerID)
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.IsTemplate != nil {
		conditions = append(conditions, fmt.Sprintf("is_template = $%d", argIndex))
		args = append(args, *filter.IsTemplate)
		argIndex++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+*filter.Search+"%")
		argIndex++
	}

	if filter.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *filter.CreatedAfter)
		argIndex++
	}

	if filter.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *filter.CreatedBefore)
		argIndex++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM workflows %s", whereClause)
	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.metrics.RecordDBQuery("count", "workflows", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to count workflows")
	}

	// Data query
	sortBy := filter.SortBy
	if sortBy == "" {
		sortBy = "created_at"
	}

	sortOrder := strings.ToUpper(filter.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, name, description, status, team_id, owner_id, version,
			   is_template, template_id, execution_count, last_executed_at,
			   last_execution_id, success_rate, average_runtime,
			   created_at, updated_at, created_by, updated_by
		FROM workflows %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortBy, sortOrder, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflows", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list workflows")
	}
	defer rows.Close()

	var workflows []*Workflow
	for rows.Next() {
		var workflow Workflow
		var lastExecutedAt pgtype.Timestamptz
		var templateID, lastExecutionID *string

		err := rows.Scan(
			&workflow.ID, &workflow.Name, &workflow.Description, &workflow.Status,
			&workflow.TeamID, &workflow.OwnerID, &workflow.Version,
			&workflow.IsTemplate, &templateID, &workflow.ExecutionCount,
			&lastExecutedAt, &lastExecutionID, &workflow.SuccessRate,
			&workflow.AverageRuntime, &workflow.CreatedAt, &workflow.UpdatedAt,
			&workflow.CreatedBy, &workflow.UpdatedBy,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow")
		}

		workflow.TemplateID = templateID
		workflow.LastExecutionID = lastExecutionID

		if lastExecutedAt.Valid {
			t := lastExecutedAt.Time
			workflow.LastExecutedAt = &t
		}

		workflows = append(workflows, &workflow)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflows")
	}

	r.metrics.RecordDBQuery("list", "workflows", "success", time.Since(start))
	return workflows, total, nil
}

// Execution-related methods

// CreateExecution creates a new workflow execution
func (r *PostgresRepository) CreateExecution(ctx context.Context, execution *WorkflowExecution) error {
	start := time.Now()

	query := `
		INSERT INTO workflow_executions (
			id, workflow_id, workflow_name, team_id, trigger_id, status, mode,
			trigger_data, input_data, output_data, error_message, error_stack,
			error_node_id, start_time, end_time, duration, nodes_executed,
			nodes_total, retry_count, max_retries, parent_execution_id,
			memory_usage, cpu_time, user_agent, ip_address, metadata,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
			$27, $28
		)`

	// Serialize JSON fields
	triggerDataJSON, _ := json.Marshal(execution.TriggerData)
	inputDataJSON, _ := json.Marshal(execution.InputData)
	outputDataJSON, _ := json.Marshal(execution.OutputData)
	metadataJSON, _ := json.Marshal(execution.Metadata)

	_, err := r.db.Exec(ctx, query,
		execution.ID, execution.WorkflowID, execution.WorkflowName, execution.TeamID,
		execution.TriggerID, execution.Status, execution.Mode, triggerDataJSON,
		inputDataJSON, outputDataJSON, execution.ErrorMessage, execution.ErrorStack,
		execution.ErrorNodeID, execution.StartTime, execution.EndTime, execution.Duration,
		execution.NodesExecuted, execution.NodesTotal, execution.RetryCount,
		execution.MaxRetries, execution.ParentExecutionID, execution.MemoryUsage,
		execution.CPUTime, execution.UserAgent, execution.IPAddress, metadataJSON,
		execution.CreatedAt, execution.UpdatedAt,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "executions", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create execution")
	}

	r.metrics.RecordDBQuery("create", "executions", "success", time.Since(start))
	return nil
}

// GetExecutionByID retrieves an execution by ID
func (r *PostgresRepository) GetExecutionByID(ctx context.Context, id string) (*WorkflowExecution, error) {
	start := time.Now()

	query := `
		SELECT id, workflow_id, workflow_name, team_id, trigger_id, status, mode,
			   trigger_data, input_data, output_data, error_message, error_stack,
			   error_node_id, start_time, end_time, duration, nodes_executed,
			   nodes_total, retry_count, max_retries, parent_execution_id,
			   memory_usage, cpu_time, user_agent, ip_address, metadata,
			   created_at, updated_at
		FROM workflow_executions
		WHERE id = $1 AND deleted_at IS NULL`

	var execution WorkflowExecution
	var triggerDataJSON, inputDataJSON, outputDataJSON, metadataJSON []byte
	var endTime pgtype.Timestamptz
	var triggerID, errorMessage, errorStack, errorNodeID, parentExecutionID *string

	err := r.db.QueryRow(ctx, query, id).Scan(
		&execution.ID, &execution.WorkflowID, &execution.WorkflowName, &execution.TeamID,
		&triggerID, &execution.Status, &execution.Mode, &triggerDataJSON,
		&inputDataJSON, &outputDataJSON, &errorMessage, &errorStack,
		&errorNodeID, &execution.StartTime, &endTime, &execution.Duration,
		&execution.NodesExecuted, &execution.NodesTotal, &execution.RetryCount,
		&execution.MaxRetries, &parentExecutionID, &execution.MemoryUsage,
		&execution.CPUTime, &execution.UserAgent, &execution.IPAddress,
		&metadataJSON, &execution.CreatedAt, &execution.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.metrics.RecordDBQuery("get", "executions", "not_found", time.Since(start))
			return nil, nil
		}
		r.metrics.RecordDBQuery("get", "executions", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get execution")
	}

	// Deserialize JSON fields
	json.Unmarshal(triggerDataJSON, &execution.TriggerData)
	json.Unmarshal(inputDataJSON, &execution.InputData)
	json.Unmarshal(outputDataJSON, &execution.OutputData)
	json.Unmarshal(metadataJSON, &execution.Metadata)

	// Handle nullable fields
	execution.TriggerID = triggerID
	execution.ErrorMessage = errorMessage
	execution.ErrorStack = errorStack
	execution.ErrorNodeID = errorNodeID
	execution.ParentExecutionID = parentExecutionID

	if endTime.Valid {
		t := endTime.Time
		execution.EndTime = &t
	}

	r.metrics.RecordDBQuery("get", "executions", "success", time.Since(start))
	return &execution, nil
}

// UpdateExecution updates an existing execution
func (r *PostgresRepository) UpdateExecution(ctx context.Context, execution *WorkflowExecution) error {
	start := time.Now()

	query := `
		UPDATE workflow_executions SET
			status = $2, output_data = $3, error_message = $4, error_stack = $5,
			error_node_id = $6, end_time = $7, duration = $8, nodes_executed = $9,
			memory_usage = $10, cpu_time = $11, metadata = $12, updated_at = $13
		WHERE id = $1`

	outputDataJSON, _ := json.Marshal(execution.OutputData)
	metadataJSON, _ := json.Marshal(execution.Metadata)

	_, err := r.db.Exec(ctx, query,
		execution.ID, execution.Status, outputDataJSON, execution.ErrorMessage,
		execution.ErrorStack, execution.ErrorNodeID, execution.EndTime,
		execution.Duration, execution.NodesExecuted, execution.MemoryUsage,
		execution.CPUTime, metadataJSON, execution.UpdatedAt,
	)

	if err != nil {
		r.metrics.RecordDBQuery("update", "executions", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to update execution")
	}

	r.metrics.RecordDBQuery("update", "executions", "success", time.Since(start))
	return nil
}

// ListExecutions retrieves executions with filtering and pagination
func (r *PostgresRepository) ListExecutions(ctx context.Context, filter *ExecutionListFilter) ([]*WorkflowExecution, int64, error) {
	start := time.Now()

	// Build query conditions
	conditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIndex := 1

	if filter.WorkflowID != nil {
		conditions = append(conditions, fmt.Sprintf("workflow_id = $%d", argIndex))
		args = append(args, *filter.WorkflowID)
		argIndex++
	}

	if filter.TeamID != nil {
		conditions = append(conditions, fmt.Sprintf("team_id = $%d", argIndex))
		args = append(args, *filter.TeamID)
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.Mode != nil {
		conditions = append(conditions, fmt.Sprintf("mode = $%d", argIndex))
		args = append(args, *filter.Mode)
		argIndex++
	}

	if filter.StartAfter != nil {
		conditions = append(conditions, fmt.Sprintf("start_time >= $%d", argIndex))
		args = append(args, *filter.StartAfter)
		argIndex++
	}

	if filter.StartBefore != nil {
		conditions = append(conditions, fmt.Sprintf("start_time <= $%d", argIndex))
		args = append(args, *filter.StartBefore)
		argIndex++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM workflow_executions %s", whereClause)
	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.metrics.RecordDBQuery("count", "workflow_executions", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to count workflow executions")
	}

	// Data query
	sortBy := filter.SortBy
	if sortBy == "" {
		sortBy = "start_time"
	}

	sortOrder := strings.ToUpper(filter.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, workflow_id, workflow_name, team_id, trigger_id, status, mode,
			   start_time, end_time, duration, nodes_executed, nodes_total,
			   retry_count, max_retries, parent_execution_id, error_message,
			   memory_usage, cpu_time, created_at, updated_at
		FROM workflow_executions %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortBy, sortOrder, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_executions", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list workflow executions")
	}
	defer rows.Close()

	var executions []*WorkflowExecution
	for rows.Next() {
		var execution WorkflowExecution
		var endTime pgtype.Timestamptz
		var triggerID, parentExecutionID, errorMessage *string

		err := rows.Scan(
			&execution.ID, &execution.WorkflowID, &execution.WorkflowName,
			&execution.TeamID, &triggerID, &execution.Status, &execution.Mode,
			&execution.StartTime, &endTime, &execution.Duration,
			&execution.NodesExecuted, &execution.NodesTotal, &execution.RetryCount,
			&execution.MaxRetries, &parentExecutionID, &errorMessage,
			&execution.MemoryUsage, &execution.CPUTime,
			&execution.CreatedAt, &execution.UpdatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow execution")
		}

		// Handle nullable fields
		execution.TriggerID = triggerID
		execution.ParentExecutionID = parentExecutionID
		execution.ErrorMessage = errorMessage

		if endTime.Valid {
			t := endTime.Time
			execution.EndTime = &t
		}

		// Initialize maps to avoid nil pointer errors
		execution.TriggerData = make(map[string]interface{})
		execution.InputData = make(map[string]interface{})
		execution.OutputData = make(map[string]interface{})
		execution.Metadata = make(map[string]interface{})

		executions = append(executions, &execution)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow executions")
	}

	r.metrics.RecordDBQuery("list", "workflow_executions", "success", time.Since(start))
	return executions, total, nil
}

// DeleteExecution deletes an execution
func (r *PostgresRepository) DeleteExecution(ctx context.Context, id string) error {
	start := time.Now()

	query := `UPDATE workflow_executions SET deleted_at = $2 WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id, time.Now())

	if err != nil {
		r.metrics.RecordDBQuery("delete", "executions", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to delete execution")
	}

	r.metrics.RecordDBQuery("delete", "executions", "success", time.Since(start))
	return nil
}

// Workflow version management implementations

func (r *PostgresRepository) CreateVersion(ctx context.Context, version *WorkflowVersion) error {
	start := time.Now()

	query := `
		INSERT INTO workflow_versions (
			id, workflow_id, version, name, description, definition, hash, change_log, is_active,
			created_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	_, err := r.db.Exec(ctx, query,
		version.ID, version.WorkflowID, version.Version, version.Name,
		version.Description, version.Definition, version.Hash, version.ChangeLog,
		version.IsActive, version.CreatedAt, version.CreatedBy,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_versions", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create workflow version")
	}

	r.metrics.RecordDBQuery("create", "workflow_versions", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow version created", "version_id", version.ID, "workflow_id", version.WorkflowID, "version", version.Version)
	return nil
}

func (r *PostgresRepository) GetVersions(ctx context.Context, workflowID string) ([]*WorkflowVersion, error) {
	start := time.Now()

	query := `
		SELECT id, workflow_id, version, name, description, definition, hash, change_log, is_active,
		       created_at, created_by
		FROM workflow_versions
		WHERE workflow_id = $1
		ORDER BY version DESC`

	rows, err := r.db.Query(ctx, query, workflowID)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_versions", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow versions")
	}
	defer rows.Close()

	var versions []*WorkflowVersion
	for rows.Next() {
		version := &WorkflowVersion{}
		err := rows.Scan(
			&version.ID, &version.WorkflowID, &version.Version, &version.Name,
			&version.Description, &version.Definition, &version.Hash, &version.ChangeLog,
			&version.IsActive, &version.CreatedAt, &version.CreatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow version")
		}
		versions = append(versions, version)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow versions")
	}

	r.metrics.RecordDBQuery("list", "workflow_versions", "success", time.Since(start))
	return versions, nil
}

func (r *PostgresRepository) GetVersionByNumber(ctx context.Context, workflowID string, versionNum int) (*WorkflowVersion, error) {
	start := time.Now()

	query := `
		SELECT id, workflow_id, version, name, description, definition, hash, change_log, is_active,
		       created_at, created_by
		FROM workflow_versions
		WHERE workflow_id = $1 AND version = $2`

	version := &WorkflowVersion{}
	err := r.db.QueryRow(ctx, query, workflowID, versionNum).Scan(
		&version.ID, &version.WorkflowID, &version.Version, &version.Name,
		&version.Description, &version.Definition, &version.Hash, &version.ChangeLog,
		&version.IsActive, &version.CreatedAt, &version.CreatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.metrics.RecordDBQuery("get", "workflow_versions", "not_found", time.Since(start))
			return nil, nil
		}
		r.metrics.RecordDBQuery("get", "workflow_versions", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow version")
	}

	r.metrics.RecordDBQuery("get", "workflow_versions", "success", time.Since(start))
	return version, nil
}

// Workflow template management implementations

func (r *PostgresRepository) CreateTemplate(ctx context.Context, template *WorkflowTemplate) error {
	start := time.Now()

	// Serialize complex fields to JSON
	tagsJSON, err := json.Marshal(template.Tags)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize tags")
	}

	requirementsJSON, err := json.Marshal(template.Requirements)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize requirements")
	}

	metadataJSON, err := json.Marshal(template.Metadata)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to serialize metadata")
	}

	query := `
		INSERT INTO workflow_templates (
			id, name, description, category, tags, definition, preview, usage_count,
			rating, is_public, author_id, author_name, team_id, requirements, metadata,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err = r.db.Exec(ctx, query,
		template.ID, template.Name, template.Description, template.Category,
		tagsJSON, template.Definition, template.Preview, template.UsageCount,
		template.Rating, template.IsPublic, template.AuthorID, template.AuthorName,
		template.TeamID, requirementsJSON, metadataJSON, template.CreatedAt, template.UpdatedAt,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_templates", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create workflow template")
	}

	r.metrics.RecordDBQuery("create", "workflow_templates", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow template created", "template_id", template.ID, "name", template.Name)
	return nil
}

func (r *PostgresRepository) GetTemplateByID(ctx context.Context, id string) (*WorkflowTemplate, error) {
	start := time.Now()

	query := `
		SELECT id, name, description, category, tags, definition, preview, usage_count,
		       rating, is_public, author_id, author_name, team_id, requirements, metadata,
		       created_at, updated_at, deleted_at
		FROM workflow_templates
		WHERE id = $1 AND deleted_at IS NULL`

	var template WorkflowTemplate
	var tagsJSON, requirementsJSON, metadataJSON []byte
	var teamID, deletedAt *string

	err := r.db.QueryRow(ctx, query, id).Scan(
		&template.ID, &template.Name, &template.Description, &template.Category,
		&tagsJSON, &template.Definition, &template.Preview, &template.UsageCount,
		&template.Rating, &template.IsPublic, &template.AuthorID, &template.AuthorName,
		&teamID, &requirementsJSON, &metadataJSON,
		&template.CreatedAt, &template.UpdatedAt, &deletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.metrics.RecordDBQuery("get", "workflow_templates", "not_found", time.Since(start))
			return nil, nil
		}
		r.metrics.RecordDBQuery("get", "workflow_templates", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow template")
	}

	// Deserialize JSON fields
	if err := json.Unmarshal(tagsJSON, &template.Tags); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize tags")
	}

	if err := json.Unmarshal(requirementsJSON, &template.Requirements); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize requirements")
	}

	if err := json.Unmarshal(metadataJSON, &template.Metadata); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal,
			"failed to deserialize metadata")
	}

	// Handle nullable fields
	template.TeamID = teamID

	if deletedAt != nil && *deletedAt != "" {
		deletedTime, err := time.Parse(time.RFC3339, *deletedAt)
		if err == nil {
			template.DeletedAt = &deletedTime
		}
	}

	r.metrics.RecordDBQuery("get", "workflow_templates", "success", time.Since(start))
	return &template, nil
}

func (r *PostgresRepository) ListTemplates(ctx context.Context, filter *TemplateListFilter) ([]*WorkflowTemplate, int64, error) {
	start := time.Now()

	// Build query conditions
	conditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argIndex := 1

	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, *filter.Category)
		argIndex++
	}

	if filter.IsPublic != nil {
		conditions = append(conditions, fmt.Sprintf("is_public = $%d", argIndex))
		args = append(args, *filter.IsPublic)
		argIndex++
	}

	if filter.AuthorID != nil {
		conditions = append(conditions, fmt.Sprintf("author_id = $%d", argIndex))
		args = append(args, *filter.AuthorID)
		argIndex++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+*filter.Search+"%")
		argIndex++
	}

	if len(filter.Tags) > 0 {
		// Add condition for templates that have at least one of the specified tags
		for _, tag := range filter.Tags {
			conditions = append(conditions, fmt.Sprintf("$%d = ANY(tags)", argIndex))
			args = append(args, tag)
			argIndex++
		}
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM workflow_templates %s", whereClause)
	var total int64
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.metrics.RecordDBQuery("count", "workflow_templates", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to count workflow templates")
	}

	// Sort by
	sortBy := filter.SortBy
	if sortBy == "" {
		sortBy = "usage_count"
	}
	sortOrder := strings.ToUpper(filter.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT id, name, description, category, tags, definition, preview, usage_count,
		       rating, is_public, author_id, author_name, team_id, requirements, metadata,
		       created_at, updated_at
		FROM workflow_templates %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`, whereClause, sortBy, sortOrder, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_templates", "error", time.Since(start))
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list workflow templates")
	}
	defer rows.Close()

	var templates []*WorkflowTemplate
	for rows.Next() {
		template := &WorkflowTemplate{}
		var tagsJSON, requirementsJSON, metadataJSON []byte
		var teamID *string

		err := rows.Scan(
			&template.ID, &template.Name, &template.Description, &template.Category,
			&tagsJSON, &template.Definition, &template.Preview, &template.UsageCount,
			&template.Rating, &template.IsPublic, &template.AuthorID, &template.AuthorName,
			&teamID, &requirementsJSON, &metadataJSON,
			&template.CreatedAt, &template.UpdatedAt,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow template")
		}

		// Deserialize JSON fields
		json.Unmarshal(tagsJSON, &template.Tags)
		json.Unmarshal(requirementsJSON, &template.Requirements)
		json.Unmarshal(metadataJSON, &template.Metadata)

		// Handle nullable fields
		template.TeamID = teamID

		templates = append(templates, template)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow templates")
	}

	r.metrics.RecordDBQuery("list", "workflow_templates", "success", time.Since(start))
	return templates, total, nil
}

// Workflow sharing implementations

func (r *PostgresRepository) CreateShare(ctx context.Context, share *WorkflowShare) error {
	start := time.Now()

	query := `
		INSERT INTO workflow_shares (
			id, workflow_id, share_type, share_with, permission, expires_at,
			created_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)`

	_, err := r.db.Exec(ctx, query,
		share.ID, share.WorkflowID, share.ShareType, share.ShareWith,
		share.Permission, share.ExpiresAt, share.CreatedAt, share.CreatedBy,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_shares", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create workflow share")
	}

	r.metrics.RecordDBQuery("create", "workflow_shares", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow share created", "share_id", share.ID, "workflow_id", share.WorkflowID)
	return nil
}

func (r *PostgresRepository) GetShares(ctx context.Context, workflowID string) ([]*WorkflowShare, error) {
	start := time.Now()

	query := `
		SELECT id, workflow_id, share_type, share_with, permission, expires_at,
		       created_at, created_by
		FROM workflow_shares
		WHERE workflow_id = $1`

	rows, err := r.db.Query(ctx, query, workflowID)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_shares", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow shares")
	}
	defer rows.Close()

	var shares []*WorkflowShare
	for rows.Next() {
		share := &WorkflowShare{}
		var shareWith, expiresAt *string

		err := rows.Scan(
			&share.ID, &share.WorkflowID, &share.ShareType, &shareWith,
			&share.Permission, &expiresAt, &share.CreatedAt, &share.CreatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow share")
		}

		// Handle nullable fields
		share.ShareWith = shareWith

		if expiresAt != nil && *expiresAt != "" {
			expiresTime, err := time.Parse(time.RFC3339, *expiresAt)
			if err == nil {
				share.ExpiresAt = &expiresTime
			}
		}

		shares = append(shares, share)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow shares")
	}

	r.metrics.RecordDBQuery("list", "workflow_shares", "success", time.Since(start))
	return shares, nil
}

func (r *PostgresRepository) DeleteShare(ctx context.Context, id string) error {
	start := time.Now()

	query := "DELETE FROM workflow_shares WHERE id = $1"
	result, err := r.db.Exec(ctx, query, id)

	if err != nil {
		r.metrics.RecordDBQuery("delete", "workflow_shares", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to delete workflow share")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFoundError("workflow share")
	}

	r.metrics.RecordDBQuery("delete", "workflow_shares", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow share deleted", "share_id", id)
	return nil
}

// Analytics and metrics implementations

func (r *PostgresRepository) GetExecutionSummary(ctx context.Context, workflowID string, period string) (*ExecutionSummary, error) {
	start := time.Now()

	// Build time filter based on period
	timeFilter := r.buildTimeFilter(period)

	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total_count,
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as success_count,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failure_count,
			AVG(CASE WHEN duration IS NOT NULL THEN duration END) as avg_runtime,
			MAX(start_time) as last_execution
		FROM workflow_executions 
		WHERE workflow_id = $1 AND deleted_at IS NULL %s`, timeFilter)

	var summary ExecutionSummary
	var lastExecution pgtype.Timestamptz
	var avgRuntime pgtype.Float8

	err := r.db.QueryRow(ctx, query, workflowID).Scan(
		&summary.TotalCount, &summary.SuccessCount, &summary.FailureCount,
		&avgRuntime, &lastExecution,
	)

	if err != nil {
		r.metrics.RecordDBQuery("analytics", "execution_summary", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get execution summary")
	}

	summary.WorkflowID = workflowID
	summary.SuccessRate = summary.GetSuccessRate()

	if avgRuntime.Valid {
		summary.AverageRuntime = int64(avgRuntime.Float64)
	}

	if lastExecution.Valid {
		t := lastExecution.Time
		summary.LastExecution = &t
	}

	r.metrics.RecordDBQuery("analytics", "execution_summary", "success", time.Since(start))
	return &summary, nil
}

func (r *PostgresRepository) GetWorkflowMetrics(ctx context.Context, workflowID string, period string) (*WorkflowMetrics, error) {
	start := time.Now()

	timeFilter := r.buildTimeFilter(period)

	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total_executions,
			COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_runs,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_runs,
			AVG(CASE WHEN duration IS NOT NULL THEN duration/1000.0 END) as avg_runtime,
			MIN(CASE WHEN duration IS NOT NULL THEN duration/1000.0 END) as min_runtime,
			MAX(CASE WHEN duration IS NOT NULL THEN duration/1000.0 END) as max_runtime,
			COUNT(CASE WHEN DATE(start_time) = CURRENT_DATE THEN 1 END) as executions_today,
			COUNT(CASE WHEN start_time >= DATE_TRUNC('week', CURRENT_DATE) THEN 1 END) as executions_this_week,
			MAX(start_time) as last_execution
		FROM workflow_executions 
		WHERE workflow_id = $1 AND deleted_at IS NULL %s`, timeFilter)

	var metrics WorkflowMetrics
	var avgRuntime, minRuntime, maxRuntime pgtype.Float8
	var lastExecution pgtype.Timestamptz

	err := r.db.QueryRow(ctx, query, workflowID).Scan(
		&metrics.TotalExecutions, &metrics.SuccessfulRuns, &metrics.FailedRuns,
		&avgRuntime, &minRuntime, &maxRuntime,
		&metrics.ExecutionsToday, &metrics.ExecutionsThisWeek, &lastExecution,
	)

	if err != nil {
		r.metrics.RecordDBQuery("analytics", "workflow_metrics", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow metrics")
	}

	metrics.WorkflowID = workflowID

	if metrics.TotalExecutions > 0 {
		metrics.SuccessRate = float64(metrics.SuccessfulRuns) / float64(metrics.TotalExecutions) * 100
	}

	if avgRuntime.Valid {
		metrics.AverageRuntime = avgRuntime.Float64
	}
	if minRuntime.Valid {
		metrics.MinRuntime = minRuntime.Float64
	}
	if maxRuntime.Valid {
		metrics.MaxRuntime = maxRuntime.Float64
	}

	if lastExecution.Valid {
		t := lastExecution.Time
		metrics.LastExecution = &t
	}

	r.metrics.RecordDBQuery("analytics", "workflow_metrics", "success", time.Since(start))
	return &metrics, nil
}

func (r *PostgresRepository) GetTeamMetrics(ctx context.Context, teamID string, period string) (*TeamMetrics, error) {
	start := time.Now()

	timeFilter := r.buildTimeFilter(period)

	// Get basic team metrics
	query := fmt.Sprintf(`
		SELECT 
			(SELECT COUNT(*) FROM workflows WHERE team_id = $1 AND deleted_at IS NULL) as total_workflows,
			(SELECT COUNT(*) FROM workflows WHERE team_id = $1 AND status = 'active' AND deleted_at IS NULL) as active_workflows,
			COUNT(*) as total_executions,
			COUNT(CASE WHEN we.status = 'completed' THEN 1 END) as successful_runs,
			COUNT(CASE WHEN we.status = 'failed' THEN 1 END) as failed_runs,
			AVG(CASE WHEN we.duration IS NOT NULL THEN we.duration/1000.0 END) as avg_runtime,
			COUNT(CASE WHEN DATE(we.start_time) = CURRENT_DATE THEN 1 END) as executions_today,
			COUNT(CASE WHEN we.start_time >= DATE_TRUNC('week', CURRENT_DATE) THEN 1 END) as executions_this_week,
			COUNT(CASE WHEN we.start_time >= DATE_TRUNC('month', CURRENT_DATE) THEN 1 END) as executions_this_month,
			MAX(we.start_time) as last_activity
		FROM workflow_executions we
		WHERE we.team_id = $1 AND we.deleted_at IS NULL %s`, timeFilter)

	var metrics TeamMetrics
	var avgRuntime pgtype.Float8
	var lastActivity pgtype.Timestamptz

	err := r.db.QueryRow(ctx, query, teamID).Scan(
		&metrics.TotalWorkflows, &metrics.ActiveWorkflows, &metrics.TotalExecutions,
		&metrics.SuccessfulRuns, &metrics.FailedRuns, &avgRuntime,
		&metrics.ExecutionsToday, &metrics.ExecutionsThisWeek, &metrics.ExecutionsThisMonth,
		&lastActivity,
	)

	if err != nil {
		r.metrics.RecordDBQuery("analytics", "team_metrics", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get team metrics")
	}

	metrics.TeamID = teamID

	if metrics.TotalExecutions > 0 {
		metrics.SuccessRate = float64(metrics.SuccessfulRuns) / float64(metrics.TotalExecutions) * 100
	}

	if avgRuntime.Valid {
		metrics.AverageRuntime = avgRuntime.Float64
	}

	if lastActivity.Valid {
		t := lastActivity.Time
		metrics.LastActivity = &t
	}

	// Get top workflows
	topWorkflowsQuery := fmt.Sprintf(`
		SELECT 
			w.id, w.name,
			COUNT(we.id) as executions,
			COUNT(CASE WHEN we.status = 'completed' THEN 1 END) * 100.0 / COUNT(we.id) as success_rate
		FROM workflows w
		LEFT JOIN workflow_executions we ON w.id = we.workflow_id AND we.deleted_at IS NULL %s
		WHERE w.team_id = $1 AND w.deleted_at IS NULL
		GROUP BY w.id, w.name
		HAVING COUNT(we.id) > 0
		ORDER BY executions DESC
		LIMIT 10`, timeFilter)

	topRows, err := r.db.Query(ctx, topWorkflowsQuery, teamID)
	if err != nil {
		r.logger.Warn("Failed to get top workflows", "team_id", teamID, "error", err)
	} else {
		defer topRows.Close()
		for topRows.Next() {
			var ws WorkflowStats
			var successRate pgtype.Float8
			err := topRows.Scan(&ws.WorkflowID, &ws.WorkflowName, &ws.Executions, &successRate)
			if err != nil {
				r.logger.Warn("Failed to scan top workflow", "error", err)
				continue
			}
			if successRate.Valid {
				ws.SuccessRate = successRate.Float64
			}
			metrics.TopWorkflows = append(metrics.TopWorkflows, ws)
		}
	}

	r.metrics.RecordDBQuery("analytics", "team_metrics", "success", time.Since(start))
	return &metrics, nil
}

// Helper method to build time filters
func (r *PostgresRepository) buildTimeFilter(period string) string {
	switch period {
	case "1d":
		return " AND start_time >= NOW() - INTERVAL '1 day'"
	case "7d":
		return " AND start_time >= NOW() - INTERVAL '7 days'"
	case "30d":
		return " AND start_time >= NOW() - INTERVAL '30 days'"
	case "90d":
		return " AND start_time >= NOW() - INTERVAL '90 days'"
	case "1y":
		return " AND start_time >= NOW() - INTERVAL '1 year'"
	default:
		return "" // "all" - no time filter
	}
}

// Tag management implementations

func (r *PostgresRepository) CreateTag(ctx context.Context, tag *Tag) error {
	start := time.Now()

	query := `
		INSERT INTO workflow_tags (
			id, name, color, description, team_id, created_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`

	_, err := r.db.Exec(ctx, query,
		tag.ID, tag.Name, tag.Color, tag.Description,
		tag.TeamID, tag.CreatedAt, tag.CreatedBy,
	)

	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_tags", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to create workflow tag")
	}

	r.metrics.RecordDBQuery("create", "workflow_tags", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Workflow tag created", "tag_id", tag.ID, "name", tag.Name)
	return nil
}

func (r *PostgresRepository) GetTagsByWorkflow(ctx context.Context, workflowID string) ([]*Tag, error) {
	start := time.Now()

	query := `
		SELECT t.id, t.name, t.color, t.description, t.team_id, t.created_at, t.created_by
		FROM workflow_tags t
		JOIN workflow_tag_associations wta ON t.id = wta.tag_id
		WHERE wta.workflow_id = $1
		ORDER BY t.name`

	rows, err := r.db.Query(ctx, query, workflowID)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_tags", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get tags by workflow")
	}
	defer rows.Close()

	var tags []*Tag
	for rows.Next() {
		var tag Tag
		err := rows.Scan(
			&tag.ID, &tag.Name, &tag.Color, &tag.Description,
			&tag.TeamID, &tag.CreatedAt, &tag.CreatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow tag")
		}
		tags = append(tags, &tag)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow tags")
	}

	r.metrics.RecordDBQuery("list", "workflow_tags", "success", time.Since(start))
	return tags, nil
}

func (r *PostgresRepository) ListTags(ctx context.Context, teamID string) ([]*Tag, error) {
	start := time.Now()

	query := `
		SELECT id, name, color, description, team_id, created_at, created_by
		FROM workflow_tags
		WHERE team_id = $1
		ORDER BY name`

	rows, err := r.db.Query(ctx, query, teamID)
	if err != nil {
		r.metrics.RecordDBQuery("list", "workflow_tags", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to list workflow tags")
	}
	defer rows.Close()

	var tags []*Tag
	for rows.Next() {
		var tag Tag
		err := rows.Scan(
			&tag.ID, &tag.Name, &tag.Color, &tag.Description,
			&tag.TeamID, &tag.CreatedAt, &tag.CreatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
				"failed to scan workflow tag")
		}
		tags = append(tags, &tag)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to iterate workflow tags")
	}

	r.metrics.RecordDBQuery("list", "workflow_tags", "success", time.Since(start))
	return tags, nil
}

// AddTagToWorkflow adds a tag to a workflow
func (r *PostgresRepository) AddTagToWorkflow(ctx context.Context, workflowID, tagID, userID string) error {
	start := time.Now()

	query := `
		INSERT INTO workflow_tag_associations (workflow_id, tag_id, created_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (workflow_id, tag_id) DO NOTHING`

	_, err := r.db.Exec(ctx, query, workflowID, tagID, userID)
	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_tag_associations", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to add tag to workflow")
	}

	r.metrics.RecordDBQuery("create", "workflow_tag_associations", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Tag added to workflow", "workflow_id", workflowID, "tag_id", tagID)
	return nil
}

// RemoveTagFromWorkflow removes a tag from a workflow
func (r *PostgresRepository) RemoveTagFromWorkflow(ctx context.Context, workflowID, tagID string) error {
	start := time.Now()

	query := "DELETE FROM workflow_tag_associations WHERE workflow_id = $1 AND tag_id = $2"

	result, err := r.db.Exec(ctx, query, workflowID, tagID)
	if err != nil {
		r.metrics.RecordDBQuery("delete", "workflow_tag_associations", "error", time.Since(start))
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to remove tag from workflow")
	}

	if result.RowsAffected() == 0 {
		return errors.NotFoundError("tag association")
	}

	r.metrics.RecordDBQuery("delete", "workflow_tag_associations", "success", time.Since(start))
	r.logger.InfoContext(ctx, "Tag removed from workflow", "workflow_id", workflowID, "tag_id", tagID)
	return nil
}

// CreateTagIfNotExists creates a tag if it doesn't exist and returns the tag
func (r *PostgresRepository) CreateTagIfNotExists(ctx context.Context, name, color, description, teamID, userID string) (*Tag, error) {
	start := time.Now()

	// First, try to get the existing tag
	query := `
		SELECT id, name, color, description, team_id, created_at, created_by
		FROM workflow_tags
		WHERE name = $1 AND team_id = $2`

	var tag Tag
	err := r.db.QueryRow(ctx, query, name, teamID).Scan(
		&tag.ID, &tag.Name, &tag.Color, &tag.Description,
		&tag.TeamID, &tag.CreatedAt, &tag.CreatedBy,
	)

	if err == nil {
		// Tag already exists, return it
		r.metrics.RecordDBQuery("get", "workflow_tags", "success", time.Since(start))
		return &tag, nil
	} else if err != pgx.ErrNoRows {
		// Some other error occurred
		r.metrics.RecordDBQuery("get", "workflow_tags", "error", time.Since(start))
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to get workflow tag")
	}

	// Tag doesn't exist, create it
	newTag := &Tag{
		ID:          GenerateID(),
		Name:        name,
		Color:       color,
		Description: description,
		TeamID:      teamID,
		CreatedAt:   time.Now(),
		CreatedBy:   userID,
	}

	err = r.CreateTag(ctx, newTag)
	if err != nil {
		r.metrics.RecordDBQuery("create", "workflow_tags", "error", time.Since(start))
		return nil, err
	}

	r.metrics.RecordDBQuery("create", "workflow_tags", "success", time.Since(start))
	return newTag, nil
}
