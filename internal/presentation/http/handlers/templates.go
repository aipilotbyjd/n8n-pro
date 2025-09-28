package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"n8n-pro/internal/presentation/http/middleware"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TemplatesHandler handles template-related HTTP requests
type TemplatesHandler struct {
	logger logger.Logger
}

// NewTemplatesHandler creates a new templates handler
func NewTemplatesHandler(logger logger.Logger) *TemplatesHandler {
	return &TemplatesHandler{
		logger: logger,
	}
}

// TemplateResponse represents a workflow template in API responses
type TemplateResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Tags        []string               `json:"tags"`
	Author      TemplateAuthor         `json:"author"`
	Version     string                 `json:"version"`
	Rating      float64                `json:"rating"`
	Downloads   int                    `json:"downloads"`
	IsOfficial  bool                   `json:"is_official"`
	IsFeatured  bool                   `json:"is_featured"`
	Screenshot  string                 `json:"screenshot,omitempty"`
	Preview     string                 `json:"preview,omitempty"`
	Workflow    map[string]interface{} `json:"workflow,omitempty"`
	NodeTypes   []string               `json:"node_types"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
}

// TemplateAuthor represents a template author
type TemplateAuthor struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Avatar string `json:"avatar,omitempty"`
	URL    string `json:"url,omitempty"`
}

// TemplateCategoryResponse represents a template category
type TemplateCategoryResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DisplayName  string `json:"display_name"`
	Description  string `json:"description"`
	Icon         string `json:"icon"`
	TemplateCount int   `json:"template_count"`
}

// CreateTemplateRequest represents the request to create a template
type CreateTemplateRequest struct {
	Name        string                 `json:"name" validate:"required,min=1,max=100"`
	Description string                 `json:"description" validate:"required,min=1,max=500"`
	Category    string                 `json:"category" validate:"required"`
	Tags        []string               `json:"tags,omitempty"`
	WorkflowID  string                 `json:"workflow_id" validate:"required,uuid"`
	IsPublic    bool                   `json:"is_public"`
	Screenshot  string                 `json:"screenshot,omitempty"`
}

// UpdateTemplateRequest represents the request to update a template
type UpdateTemplateRequest struct {
	Name        *string  `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string  `json:"description,omitempty" validate:"omitempty,min=1,max=500"`
	Category    *string  `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	IsPublic    *bool    `json:"is_public,omitempty"`
	Screenshot  *string  `json:"screenshot,omitempty"`
}

// ListTemplates lists available workflow templates
func (h *TemplatesHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	category := r.URL.Query().Get("category")
	tag := r.URL.Query().Get("tag")
	search := r.URL.Query().Get("search")
	featured := r.URL.Query().Get("featured") == "true"
	official := r.URL.Query().Get("official") == "true"
	
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	
	limit := 20 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}
	
	offset := 0 // default
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Mock templates data (in a real implementation, this would come from the database)
	templates := h.getMockTemplates()

	// Filter templates based on query parameters
	filtered := h.filterTemplates(templates, category, tag, search, featured, official)

	// Apply pagination
	start := offset
	end := offset + limit
	if start > len(filtered) {
		start = len(filtered)
	}
	if end > len(filtered) {
		end = len(filtered)
	}

	paginatedTemplates := filtered[start:end]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": paginatedTemplates,
		"count":     len(paginatedTemplates),
		"total":     len(filtered),
		"limit":     limit,
		"offset":    offset,
		"filters": map[string]interface{}{
			"category": category,
			"tag":      tag,
			"search":   search,
			"featured": featured,
			"official": official,
		},
	})
}

// GetTemplate retrieves a specific template by ID
func (h *TemplatesHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	if templateID == "" {
		writeError(w, errors.NewValidationError("Template ID is required"))
		return
	}

	// Mock template data (in a real implementation, this would come from the database)
	template := h.getMockTemplate(templateID)
	if template == nil {
		writeError(w, errors.NewNotFoundError("Template not found"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"template": template,
	})
}

// CreateTemplate creates a new template from a workflow
func (h *TemplatesHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in create template request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Create template (in a real implementation, this would save to database)
	template := &TemplateResponse{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Category:    req.Category,
		Tags:        req.Tags,
		Author: TemplateAuthor{
			ID:   userCtx.ID,
			Name: userCtx.Email, // Use email as name for now
		},
		Version:    "1.0.0",
		Rating:     0.0,
		Downloads:  0,
		IsOfficial: false,
		IsFeatured: false,
		Screenshot: req.Screenshot,
		NodeTypes:  []string{}, // Would be extracted from workflow
		CreatedAt:  time.Now().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:  time.Now().Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"template": template,
	})

	h.logger.Info("Template created successfully", "template_id", template.ID, "user_id", userCtx.ID)
}

// UpdateTemplate updates an existing template
func (h *TemplatesHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	if templateID == "" {
		writeError(w, errors.NewValidationError("Template ID is required"))
		return
	}

	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid JSON in update template request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get existing template (mock)
	template := h.getMockTemplate(templateID)
	if template == nil {
		writeError(w, errors.NewNotFoundError("Template not found"))
		return
	}

	// Update fields
	if req.Name != nil {
		template.Name = *req.Name
	}
	if req.Description != nil {
		template.Description = *req.Description
	}
	if req.Category != nil {
		template.Category = *req.Category
	}
	if req.Tags != nil {
		template.Tags = req.Tags
	}
	if req.Screenshot != nil {
		template.Screenshot = *req.Screenshot
	}

	template.UpdatedAt = time.Now().Format("2006-01-02T15:04:05Z07:00")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"template": template,
	})

	h.logger.Info("Template updated successfully", "template_id", templateID, "user_id", userCtx.ID)
}

// DeleteTemplate deletes a template
func (h *TemplatesHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	if templateID == "" {
		writeError(w, errors.NewValidationError("Template ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// In a real implementation, you would delete from database
	w.WriteHeader(http.StatusNoContent)
	h.logger.Info("Template deleted successfully", "template_id", templateID, "user_id", userCtx.ID)
}

// UseTemplate creates a workflow from a template
func (h *TemplatesHandler) UseTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	if templateID == "" {
		writeError(w, errors.NewValidationError("Template ID is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	// Get template
	template := h.getMockTemplate(templateID)
	if template == nil {
		writeError(w, errors.NewNotFoundError("Template not found"))
		return
	}

	// Create workflow from template (mock response)
	workflowID := uuid.New().String()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"workflow_id": workflowID,
		"name":        template.Name + " (Copy)",
		"template_id": templateID,
		"message":     "Workflow created from template successfully",
	})

	h.logger.Info("Workflow created from template", "template_id", templateID, "workflow_id", workflowID, "user_id", userCtx.ID)
}

// ListCategories lists template categories
func (h *TemplatesHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	categories := []TemplateCategoryResponse{
		{
			ID:           "integration",
			Name:         "integration",
			DisplayName:  "Integration",
			Description:  "Connect different services and applications",
			Icon:         "🔗",
			TemplateCount: 25,
		},
		{
			ID:           "automation",
			Name:         "automation",
			DisplayName:  "Automation",
			Description:  "Automate repetitive tasks and processes",
			Icon:         "⚡",
			TemplateCount: 18,
		},
		{
			ID:           "communication",
			Name:         "communication",
			DisplayName:  "Communication",
			Description:  "Email, chat, and notification workflows",
			Icon:         "💬",
			TemplateCount: 12,
		},
		{
			ID:           "productivity",
			Name:         "productivity",
			DisplayName:  "Productivity",
			Description:  "Boost productivity with smart workflows",
			Icon:         "📊",
			TemplateCount: 15,
		},
		{
			ID:           "marketing",
			Name:         "marketing",
			DisplayName:  "Marketing",
			Description:  "Marketing automation and campaigns",
			Icon:         "📢",
			TemplateCount: 10,
		},
		{
			ID:           "analytics",
			Name:         "analytics",
			DisplayName:  "Analytics",
			Description:  "Data analysis and reporting workflows",
			Icon:         "📈",
			TemplateCount: 8,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"categories": categories,
		"count":      len(categories),
	})
}

// GetTemplateStats retrieves template statistics
func (h *TemplatesHandler) GetTemplateStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_templates": 88,
		"featured_templates": 12,
		"official_templates": 25,
		"categories": 6,
		"total_downloads": 15420,
		"recent_templates": []map[string]interface{}{
			{
				"id":   "recent-1",
				"name": "Slack to Discord Bridge",
				"downloads": 45,
				"created_at": time.Now().AddDate(0, 0, -2).Format("2006-01-02T15:04:05Z07:00"),
			},
			{
				"id":   "recent-2",
				"name": "Google Sheets Data Sync",
				"downloads": 32,
				"created_at": time.Now().AddDate(0, 0, -5).Format("2006-01-02T15:04:05Z07:00"),
			},
		},
		"popular_templates": []map[string]interface{}{
			{
				"id":   "popular-1",
				"name": "Email Newsletter Automation",
				"downloads": 1250,
				"rating": 4.8,
			},
			{
				"id":   "popular-2",
				"name": "Social Media Publishing",
				"downloads": 980,
				"rating": 4.6,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats": stats,
	})
}

// Helper methods

func (h *TemplatesHandler) getMockTemplates() []TemplateResponse {
	return []TemplateResponse{
		{
			ID:          "template-1",
			Name:        "Email Newsletter Automation",
			Description: "Automatically send newsletters to subscribers with content from RSS feeds",
			Category:    "marketing",
			Tags:        []string{"email", "newsletter", "rss", "automation"},
			Author: TemplateAuthor{
				ID:   "author-1",
				Name: "n8n Team",
			},
			Version:    "1.2.0",
			Rating:     4.8,
			Downloads:  1250,
			IsOfficial: true,
			IsFeatured: true,
			NodeTypes:  []string{"rss", "email", "scheduler"},
			CreatedAt:  "2024-01-15T10:00:00Z",
			UpdatedAt:  "2024-02-20T14:30:00Z",
		},
		{
			ID:          "template-2",
			Name:        "Slack to Discord Bridge",
			Description: "Forward messages from Slack channels to Discord webhooks",
			Category:    "communication",
			Tags:        []string{"slack", "discord", "bridge", "communication"},
			Author: TemplateAuthor{
				ID:   "author-2",
				Name: "Community",
			},
			Version:    "1.0.0",
			Rating:     4.5,
			Downloads:  890,
			IsOfficial: false,
			IsFeatured: false,
			NodeTypes:  []string{"slack", "webhook", "transform"},
			CreatedAt:  "2024-02-01T09:15:00Z",
			UpdatedAt:  "2024-02-15T16:45:00Z",
		},
		{
			ID:          "template-3",
			Name:        "Google Sheets Data Sync",
			Description: "Sync data between different Google Sheets automatically",
			Category:    "productivity",
			Tags:        []string{"google-sheets", "sync", "data", "automation"},
			Author: TemplateAuthor{
				ID:   "author-1",
				Name: "n8n Team",
			},
			Version:    "1.1.0",
			Rating:     4.7,
			Downloads:  675,
			IsOfficial: true,
			IsFeatured: true,
			NodeTypes:  []string{"google-sheets", "scheduler", "transform"},
			CreatedAt:  "2024-01-28T11:20:00Z",
			UpdatedAt:  "2024-02-18T13:10:00Z",
		},
	}
}

func (h *TemplatesHandler) getMockTemplate(id string) *TemplateResponse {
	templates := h.getMockTemplates()
	for _, template := range templates {
		if template.ID == id {
			return &template
		}
	}
	return nil
}

func (h *TemplatesHandler) filterTemplates(templates []TemplateResponse, category, tag, search string, featured, official bool) []TemplateResponse {
	filtered := make([]TemplateResponse, 0)

	for _, template := range templates {
		// Filter by category
		if category != "" && template.Category != category {
			continue
		}

		// Filter by tag
		if tag != "" {
			hasTag := false
			for _, t := range template.Tags {
				if t == tag {
					hasTag = true
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Filter by search
		if search != "" {
			searchLower := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(template.Name), searchLower) &&
				!strings.Contains(strings.ToLower(template.Description), searchLower) {
				continue
			}
		}

		// Filter by featured
		if featured && !template.IsFeatured {
			continue
		}

		// Filter by official
		if official && !template.IsOfficial {
			continue
		}

		filtered = append(filtered, template)
	}

	return filtered
}