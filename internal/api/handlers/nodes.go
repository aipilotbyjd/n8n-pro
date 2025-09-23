package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"n8n-pro/internal/api/middleware"
	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/go-chi/chi/v5"
)

// NodesHandler handles node-related HTTP requests
type NodesHandler struct {
	registry *nodes.Registry
	logger   logger.Logger
}

// NewNodesHandler creates a new nodes handler
func NewNodesHandler(registry *nodes.Registry, logger logger.Logger) *NodesHandler {
	return &NodesHandler{
		registry: registry,
		logger:   logger,
	}
}

// NodeResponse represents a node in API responses
type NodeResponse struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Category    string                 `json:"category"`
	Icon        string                 `json:"icon"`
	Properties  []NodePropertyResponse `json:"properties"`
	Inputs      []NodePortResponse     `json:"inputs"`
	Outputs     []NodePortResponse     `json:"outputs"`
	Credentials []string               `json:"credentials"`
	DocURL      string                 `json:"doc_url,omitempty"`
}

// NodePropertyResponse represents a node property in API responses
type NodePropertyResponse struct {
	Name         string                 `json:"name"`
	DisplayName  string                 `json:"display_name"`
	Type         string                 `json:"type"`
	Required     bool                   `json:"required"`
	Default      interface{}            `json:"default,omitempty"`
	Description  string                 `json:"description"`
	Options      []NodeOptionResponse   `json:"options,omitempty"`
	Placeholder  string                 `json:"placeholder,omitempty"`
	Validation   map[string]interface{} `json:"validation,omitempty"`
}

// NodeOptionResponse represents a node property option in API responses
type NodeOptionResponse struct {
	Label string      `json:"label"`
	Value interface{} `json:"value"`
}

// NodePortResponse represents a node input/output port in API responses
type NodePortResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
}

// NodeCategoryResponse represents a node category in API responses
type NodeCategoryResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Icon        string `json:"icon"`
	NodeCount   int    `json:"node_count"`
}

// NodeStatsResponse represents node usage statistics
type NodeStatsResponse struct {
	TotalNodes      int                        `json:"total_nodes"`
	Categories      []NodeCategoryResponse     `json:"categories"`
	PopularNodes    []NodeUsageResponse        `json:"popular_nodes"`
	RecentlyAdded   []NodeResponse             `json:"recently_added"`
}

// NodeUsageResponse represents node usage statistics
type NodeUsageResponse struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	UsageCount int   `json:"usage_count"`
}

// ListNodes lists all available nodes
func (h *NodesHandler) ListNodes(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	search := r.URL.Query().Get("search")

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	nodeTypes, err := h.registry.GetDefinitions(nil)
	if err != nil {
		writeError(w, err)
		return
	}
	responses := make([]NodeResponse, 0, len(nodeTypes))

	for _, nodeType := range nodeTypes {
		// Filter by category if specified
		if category != "" && nodeType.Category != nodes.NodeCategory(category) {
			continue
		}

		// Filter by search term if specified
		if search != "" {
			if !h.matchesSearch(nodeType, search) {
				continue
			}
		}

		responses = append(responses, h.nodeTypeToResponse(nodeType))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": responses,
		"count": len(responses),
		"filters": map[string]interface{}{
			"category": category,
			"search":   search,
		},
	})
}

// GetNode retrieves a specific node by type
func (h *NodesHandler) GetNode(w http.ResponseWriter, r *http.Request) {
	nodeType := chi.URLParam(r, "type")
	if nodeType == "" {
		writeError(w, errors.NewValidationError("Node type is required"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	nodeTypeInfo, err := h.registry.GetDefinition(nodeType)
	if err != nil {
		writeError(w, err)
		return
	}

	response := h.nodeTypeToResponse(nodeTypeInfo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"node": response,
	})
}

// ListCategories lists all node categories
func (h *NodesHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	nodeTypes, err := h.registry.GetDefinitions(nil)
	if err != nil {
		writeError(w, err)
		return
	}
	categories := make(map[string]*NodeCategoryResponse)

	// Count nodes by category
	for _, nodeType := range nodeTypes {
		if category, exists := categories[string(nodeType.Category)]; exists {
			category.NodeCount++
		} else {
			categories[string(nodeType.Category)] = &NodeCategoryResponse{
				Name:        string(nodeType.Category),
				DisplayName: h.getCategoryDisplayName(string(nodeType.Category)),
				Icon:        h.getCategoryIcon(string(nodeType.Category)),
				NodeCount:   1,
			}
		}
	}

	// Convert to slice
	responses := make([]NodeCategoryResponse, 0, len(categories))
	for _, category := range categories {
		responses = append(responses, *category)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"categories": responses,
		"count":      len(responses),
	})
}

// GetNodeStats retrieves node usage statistics
func (h *NodesHandler) GetNodeStats(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	nodeTypes, err := h.registry.GetDefinitions(nil)
	if err != nil {
		writeError(w, err)
		return
	}
	
	// Build categories
	categories := make(map[string]*NodeCategoryResponse)
	for _, nodeType := range nodeTypes {
		if category, exists := categories[string(nodeType.Category)]; exists {
			category.NodeCount++
		} else {
			categories[string(nodeType.Category)] = &NodeCategoryResponse{
				Name:        string(nodeType.Category),
				DisplayName: h.getCategoryDisplayName(string(nodeType.Category)),
				Icon:        h.getCategoryIcon(string(nodeType.Category)),
				NodeCount:   1,
			}
		}
	}

	categoryResponses := make([]NodeCategoryResponse, 0, len(categories))
	for _, category := range categories {
		categoryResponses = append(categoryResponses, *category)
	}

	// Mock popular nodes (in a real implementation, this would come from usage analytics)
	popularNodes := []NodeUsageResponse{
		{Type: "http", Name: "HTTP Request", UsageCount: 1250},
		{Type: "slack", Name: "Slack", UsageCount: 890},
		{Type: "google-sheets", Name: "Google Sheets", UsageCount: 675},
		{Type: "database", Name: "Database", UsageCount: 432},
	}

	// Mock recently added nodes
	recentlyAdded := make([]NodeResponse, 0)
	if len(nodeTypes) > 0 {
		// Take first few nodes as "recently added"
		for i, nodeType := range nodeTypes {
			if i >= 3 { // Limit to 3 recent nodes
				break
			}
			recentlyAdded = append(recentlyAdded, h.nodeTypeToResponse(nodeType))
		}
	}

	stats := NodeStatsResponse{
		TotalNodes:    len(nodeTypes),
		Categories:    categoryResponses,
		PopularNodes:  popularNodes,
		RecentlyAdded: recentlyAdded,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats": stats,
	})
}

// TestNode tests a node with provided configuration
func (h *NodesHandler) TestNode(w http.ResponseWriter, r *http.Request) {
	nodeType := chi.URLParam(r, "type")
	if nodeType == "" {
		writeError(w, errors.NewValidationError("Node type is required"))
		return
	}

	var testRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&testRequest); err != nil {
		h.logger.Warn("Invalid JSON in test node request", "error", err)
		writeError(w, errors.NewValidationError("Invalid JSON format"))
		return
	}

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeError(w, errors.NewUnauthorizedError("User not authenticated"))
		return
	}

	_, err := h.registry.GetDefinition(nodeType)
	if err != nil {
		writeError(w, err)
		return
	}

	// In a real implementation, you would execute the node with test data
	// For now, we'll return a mock response
	testResult := map[string]interface{}{
		"success": true,
		"message": "Node test completed successfully",
		"output": map[string]interface{}{
			"status":    "success",
			"timestamp": time.Now().Unix(),
			"data":      "Test execution completed",
		},
		"execution_time": 125, // milliseconds
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"test_result": testResult,
		"node_type":   nodeType,
	})

	h.logger.Info("Node test completed", "node_type", nodeType, "user_id", userCtx.ID)
}

// Helper methods

func (h *NodesHandler) nodeTypeToResponse(nodeType *nodes.NodeDefinition) NodeResponse {
	properties := make([]NodePropertyResponse, len(nodeType.Parameters))
	for i, prop := range nodeType.Parameters {
		properties[i] = NodePropertyResponse{
			Name:        prop.Name,
			DisplayName: prop.DisplayName,
			Type:        string(prop.Type),
			Required:    prop.Required,
			Default:     prop.Default,
			Description: prop.Description,
			Placeholder: prop.Placeholder,
		}

		// Convert options
		if len(prop.Options) > 0 {
			options := make([]NodeOptionResponse, len(prop.Options))
			for j, opt := range prop.Options {
				options[j] = NodeOptionResponse{
					Label: opt.Label,
					Value: opt.Value,
				}
			}
			properties[i].Options = options
		}
	}

	inputs := make([]NodePortResponse, len(nodeType.Inputs))
	for i, input := range nodeType.Inputs {
		inputs[i] = NodePortResponse{
			Name:        input.Name,
			DisplayName: input.DisplayName,
			Type:        input.Type,
			Required:    input.Required,
		}
	}

	outputs := make([]NodePortResponse, len(nodeType.Outputs))
	for i, output := range nodeType.Outputs {
		outputs[i] = NodePortResponse{
			Name:        output.Name,
			DisplayName: output.DisplayName,
			Type:        output.Type,
		}
	}

	return NodeResponse{
		Type:        string(nodeType.Type),
		Name:        nodeType.Name,
		DisplayName: nodeType.DisplayName,
		Description: nodeType.Description,
		Version:     nodeType.Version,
		Category:    string(nodeType.Category),
		Icon:        nodeType.Icon,
		Properties:  properties,
		Inputs:      inputs,
		Outputs:     outputs,
		Credentials: nodeType.Credentials,
		DocURL:      nodeType.DocumentationURL,
	}
}

func (h *NodesHandler) matchesSearch(nodeType *nodes.NodeDefinition, search string) bool {
	search = strings.ToLower(search)
	return strings.Contains(strings.ToLower(nodeType.Name), search) ||
		strings.Contains(strings.ToLower(nodeType.DisplayName), search) ||
		strings.Contains(strings.ToLower(nodeType.Description), search) ||
		strings.Contains(strings.ToLower(string(nodeType.Category)), search)
}

func (h *NodesHandler) getCategoryDisplayName(category string) string {
	displayNames := map[string]string{
		"trigger":       "Triggers",
		"action":        "Actions",
		"transform":     "Data Transform",
		"communication": "Communication",
		"productivity":  "Productivity",
		"analytics":     "Analytics",
		"database":      "Database",
		"storage":       "Storage",
		"utility":       "Utilities",
		"finance":       "Finance",
		"marketing":     "Marketing",
		"development":   "Development",
		"ai":           "Artificial Intelligence",
	}

	if displayName, exists := displayNames[category]; exists {
		return displayName
	}
	return strings.Title(category)
}

func (h *NodesHandler) getCategoryIcon(category string) string {
	icons := map[string]string{
		"trigger":       "⚡",
		"action":        "🎯",
		"transform":     "🔄",
		"communication": "💬",
		"productivity":  "📊",
		"analytics":     "📈",
		"database":      "🗄️",
		"storage":       "💾",
		"utility":       "🔧",
		"finance":       "💰",
		"marketing":     "📢",
		"development":   "⚙️",
		"ai":           "🤖",
	}

	if icon, exists := icons[category]; exists {
		return icon
	}
	return "📦"
}
