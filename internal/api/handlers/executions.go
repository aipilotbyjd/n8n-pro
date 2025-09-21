package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/common"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

type ExecutionHandler struct {
	workflowService *workflows.Service
	logger          logger.Logger
}

func NewExecutionHandler(workflowService *workflows.Service, logger logger.Logger) *ExecutionHandler {
	return &ExecutionHandler{
		workflowService: workflowService,
		logger:          logger,
	}
}

type ExecutionResponse struct {
	ID         string                 `json:"id"`
	WorkflowID string                 `json:"workflow_id"`
	Status     string                 `json:"status"`
	Mode       string                 `json:"mode"`
	StartedAt  string                 `json:"started_at"`
	FinishedAt *string                `json:"finished_at,omitempty"`
	Duration   *int64                 `json:"duration,omitempty"`
	InputData  map[string]interface{} `json:"input_data,omitempty"`
	OutputData map[string]interface{} `json:"output_data,omitempty"`
	ErrorData  *string                `json:"error_data,omitempty"`
}

type ExecuteWorkflowRequest struct {
	InputData map[string]interface{} `json:"input_data"`
	Mode      string                 `json:"mode,omitempty"` // manual, webhook, schedule, etc.
}

func (h *ExecutionHandler) ExecuteWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	workflowID := chi.URLParam(r, "id")
	if workflowID == "" {
		writeError(w, errors.NewValidationError("Workflow ID is required"))
		return
	}

	var req ExecuteWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Verify user has access to workflow
	workflow, err := h.workflowService.GetByID(r.Context(), workflowID, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Check if workflow is active
	if workflow.Status != workflows.WorkflowStatusActive {
		writeError(w, errors.NewValidationError("Workflow must be active to execute"))
		return
	}

	// Set default mode if not provided
	mode := req.Mode
	if mode == "" {
		mode = "manual"
	}

	// Execute workflow
	execution, err := h.workflowService.Execute(
		r.Context(),
		workflowID,
		req.InputData,
		user.ID,
		mode,
	)
	if err != nil {
		h.logger.Error("Failed to execute workflow",
			"workflow_id", workflowID,
			"user_id", user.ID,
			"error", err,
		)
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"execution_id": execution.ID,
		"workflow_id":  workflowID,
		"status":       execution.Status,
		"mode":         execution.Mode,
		"started_at":   execution.StartTime,
		"message":      "Workflow execution started successfully",
	}

	h.logger.Info("Workflow execution started",
		"execution_id", execution.ID,
		"workflow_id", workflowID,
		"user_id", user.ID,
		"mode", mode,
	)

	writeSuccess(w, http.StatusAccepted, response)
}

func (h *ExecutionHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Parse query parameters
	workflowID := r.URL.Query().Get("workflow_id")
	status := r.URL.Query().Get("status")
	mode := r.URL.Query().Get("mode")

	// Parse pagination
	page := 1
	pageSize := 50

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 1000 {
			pageSize = parsed
		}
	}

	// Create filter
	filter := &workflows.ExecutionListFilter{
		TeamID: &user.TeamID,
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}

	if workflowID != "" {
		filter.WorkflowID = &workflowID
	}

	if status != "" {
		executionStatus := workflows.ExecutionStatus(status)
		filter.Status = &executionStatus
	}

	if mode != "" {
		filter.Mode = &mode
	}

	// List executions
	executions, total, err := h.workflowService.ListExecutions(r.Context(), filter, user.ID)
	if err != nil {
		h.logger.Error("Failed to list executions", "user_id", user.ID, "error", err)
		writeError(w, err)
		return
	}

	// Convert to response format
	executionResponses := make([]ExecutionResponse, len(executions))
	for i, exec := range executions {
		executionResponses[i] = convertExecutionToResponse(exec)
	}

	response := map[string]interface{}{
		"executions": executionResponses,
		"pagination": common.NewPaginationResponse(page, pageSize, total),
	}

	writeSuccess(w, http.StatusOK, response)
}

func (h *ExecutionHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	executionID := chi.URLParam(r, "id")
	if executionID == "" {
		writeError(w, errors.NewValidationError("Execution ID is required"))
		return
	}

	execution, err := h.workflowService.GetExecution(r.Context(), executionID, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	response := convertExecutionToResponse(execution)
	writeSuccess(w, http.StatusOK, response)
}

func (h *ExecutionHandler) CancelExecution(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	executionID := chi.URLParam(r, "id")
	if executionID == "" {
		writeError(w, errors.NewValidationError("Execution ID is required"))
		return
	}

	// Get execution first to verify access
	execution, err := h.workflowService.GetExecution(r.Context(), executionID, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Check if execution can be cancelled
	if execution.Status != workflows.ExecutionStatusRunning {
		writeError(w, errors.NewValidationError("Only running executions can be cancelled"))
		return
	}

	// Cancel execution
	if err := h.workflowService.CancelExecution(r.Context(), executionID, user.ID); err != nil {
		h.logger.Error("Failed to cancel execution",
			"execution_id", executionID,
			"user_id", user.ID,
			"error", err,
		)
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"execution_id": executionID,
		"status":       "cancelled",
		"message":      "Execution cancelled successfully",
	}

	h.logger.Info("Execution cancelled",
		"execution_id", executionID,
		"user_id", user.ID,
	)

	writeSuccess(w, http.StatusOK, response)
}

func (h *ExecutionHandler) RetryExecution(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	executionID := chi.URLParam(r, "id")
	if executionID == "" {
		writeError(w, errors.NewValidationError("Execution ID is required"))
		return
	}

	// Get original execution
	originalExecution, err := h.workflowService.GetExecution(r.Context(), executionID, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Check if execution can be retried
	if originalExecution.Status != workflows.ExecutionStatusFailed {
		writeError(w, errors.NewValidationError("Only failed executions can be retried"))
		return
	}

	// Retry execution
	newExecution, err := h.workflowService.RetryExecution(r.Context(), executionID, user.ID)
	if err != nil {
		h.logger.Error("Failed to retry execution",
			"original_execution_id", executionID,
			"user_id", user.ID,
			"error", err,
		)
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"new_execution_id":      newExecution.ID,
		"original_execution_id": executionID,
		"status":                newExecution.Status,
		"message":               "Execution retry started successfully",
	}

	h.logger.Info("Execution retried",
		"original_execution_id", executionID,
		"new_execution_id", newExecution.ID,
		"user_id", user.ID,
	)

	writeSuccess(w, http.StatusCreated, response)
}

// Helper function to convert execution to response format
func convertExecutionToResponse(exec *workflows.WorkflowExecution) ExecutionResponse {
	response := ExecutionResponse{
		ID:         exec.ID,
		WorkflowID: exec.WorkflowID,
		Status:     string(exec.Status),
		Mode:       exec.Mode,
		StartedAt:  exec.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		InputData:  exec.InputData,
		OutputData: exec.OutputData,
	}

	if exec.EndTime != nil {
		finishedAt := exec.EndTime.Format("2006-01-02T15:04:05Z07:00")
		response.FinishedAt = &finishedAt
	}

	if exec.Duration != nil {
		response.Duration = exec.Duration
	}

	if exec.ErrorMessage != nil {
		response.ErrorData = exec.ErrorMessage
	}

	return response
}
