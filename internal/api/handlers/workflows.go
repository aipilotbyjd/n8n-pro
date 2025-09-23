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
)

type WorkflowHandler struct {
	service *workflows.Service
}

func NewWorkflowHandler(service *workflows.Service) *WorkflowHandler {
	return &WorkflowHandler{service: service}
}

type CreateWorkflowRequest struct {
	Name        string                   `json:"name" validate:"required,min=1,max=255"`
	Description string                   `json:"description"`
	Nodes       []workflows.Node         `json:"nodes"`
	Connections []workflows.Connection   `json:"connections"`
	Tags        []workflows.Tag          `json:"tags"`
	Config      workflows.WorkflowConfig `json:"config"`
}

type UpdateWorkflowRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=255"`
	Description string                    `json:"description"`
	Nodes       []workflows.Node          `json:"nodes"`
	Connections []workflows.Connection    `json:"connections"`
	Tags        []workflows.Tag           `json:"tags"`
	Config      workflows.WorkflowConfig  `json:"config"`
	Status      *workflows.WorkflowStatus `json:"status"`
}

func (h *WorkflowHandler) CreateWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Create workflow object
	workflow := &workflows.Workflow{
		ID:          common.GenerateID(),
		Name:        req.Name,
		Description: req.Description,
		Status:      workflows.WorkflowStatusDraft,
		TeamID:      user.TeamID,
		OwnerID:     user.ID,
		Version:     1,
		IsTemplate:  false,
		Nodes:       req.Nodes,
		Connections: req.Connections,
		Tags:        req.Tags,
		Config:      req.Config,
	}

	createdWorkflow, err := h.service.Create(r.Context(), workflow, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusCreated, createdWorkflow)
}

func (h *WorkflowHandler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, errors.NewValidationError("Workflow ID is required"))
		return
	}

	workflow, err := h.service.GetByID(r.Context(), id, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusOK, workflow)
}

func (h *WorkflowHandler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Parse query parameters for filtering
	filter := &workflows.WorkflowListFilter{
		TeamID: &user.TeamID,
	}

	// Parse optional query parameters
	if status := r.URL.Query().Get("status"); status != "" {
		workflowStatus := workflows.WorkflowStatus(status)
		filter.Status = &workflowStatus
	}

	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}

	if ownerID := r.URL.Query().Get("owner_id"); ownerID != "" {
		filter.OwnerID = &ownerID
	}

	if isTemplate := r.URL.Query().Get("is_template"); isTemplate != "" {
		template := isTemplate == "true"
		filter.IsTemplate = &template
	}

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

	// Set pagination fields
	filter.Limit = pageSize
	filter.Offset = (page - 1) * pageSize

	workflows, total, err := h.service.List(r.Context(), filter, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	response := map[string]interface{}{
		"workflows":  workflows,
		"pagination": common.NewPaginationResponse(page, pageSize, total),
	}

	writeSuccess(w, http.StatusOK, response)
}

func (h *WorkflowHandler) UpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, errors.NewValidationError("Workflow ID is required"))
		return
	}

	var req UpdateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.NewValidationError("Invalid request body: "+err.Error()))
		return
	}

	// Get existing workflow first
	existing, err := h.service.GetByID(r.Context(), id, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Update fields
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Nodes = req.Nodes
	existing.Connections = req.Connections
	existing.Tags = req.Tags
	existing.Config = req.Config

	if req.Status != nil {
		existing.Status = *req.Status
	}

	updatedWorkflow, err := h.service.Update(r.Context(), existing, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeSuccess(w, http.StatusOK, updatedWorkflow)
}

func (h *WorkflowHandler) DeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, errors.NewValidationError("Workflow ID is required"))
		return
	}

	if err := h.service.Delete(r.Context(), id, user.ID); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}


