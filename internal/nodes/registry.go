package nodes

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"n8n-pro/internal/nodes/db"
	"n8n-pro/internal/nodes/gsheet"
	"n8n-pro/internal/nodes/http"
	"n8n-pro/internal/nodes/slack"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// NodeType represents different types of nodes
type NodeType string

const (
	NodeTypeTrigger   NodeType = "trigger"
	NodeTypeAction    NodeType = "action"
	NodeTypeTransform NodeType = "transform"
	NodeTypeCondition NodeType = "condition"
	NodeTypeLoop      NodeType = "loop"
	NodeTypeWait      NodeType = "wait"
	NodeTypeWebhook   NodeType = "webhook"
	NodeTypeSchedule  NodeType = "schedule"
	NodeTypeDatabase  NodeType = "database"
	NodeTypeHTTP      NodeType = "http"
	NodeTypeFile      NodeType = "file"
	NodeTypeEmail     NodeType = "email"
	NodeTypeCustom    NodeType = "custom"
)

// NodeCategory represents node categories for organization
type NodeCategory string

const (
	CategoryCore          NodeCategory = "core"
	CategoryIntegration   NodeCategory = "integration"
	CategoryUtility       NodeCategory = "utility"
	CategoryDatabase      NodeCategory = "database"
	CategoryCommunication NodeCategory = "communication"
	CategoryFile          NodeCategory = "file"
	CategoryAnalytics     NodeCategory = "analytics"
	CategorySecurity      NodeCategory = "security"
	CategoryCustom        NodeCategory = "custom"
)

// NodeStatus represents the status of a node type
type NodeStatus string

const (
	NodeStatusStable       NodeStatus = "stable"
	NodeStatusBeta         NodeStatus = "beta"
	NodeStatusExperimental NodeStatus = "experimental"
	NodeStatusDeprecated   NodeStatus = "deprecated"
)

// ParameterType represents different types of node parameters
type ParameterType string

const (
	ParameterTypeString     ParameterType = "string"
	ParameterTypeNumber     ParameterType = "number"
	ParameterTypeBoolean    ParameterType = "boolean"
	ParameterTypeArray      ParameterType = "array"
	ParameterTypeObject     ParameterType = "object"
	ParameterTypeCredential ParameterType = "credential"
	ParameterTypeOptions    ParameterType = "options"
	ParameterTypeFile       ParameterType = "file"
	ParameterTypeCode       ParameterType = "code"
	ParameterTypeExpression ParameterType = "expression"
)

// Parameter represents a node parameter definition
type Parameter struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name"`
	Type        ParameterType `json:"type"`
	Description string        `json:"description"`
	Required    bool          `json:"required"`
	Default     interface{}   `json:"default,omitempty"`
	Options     []Option      `json:"options,omitempty"`
	Placeholder string        `json:"placeholder,omitempty"`
	Validation  *Validation   `json:"validation,omitempty"`
	DependsOn   string        `json:"depends_on,omitempty"`
	ShowIf      string        `json:"show_if,omitempty"`
	Credentials []string      `json:"credentials,omitempty"`
	Multiple    bool          `json:"multiple,omitempty"`
}

// Option represents an option for parameter types that have predefined values
type Option struct {
	Value       interface{} `json:"value"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
	Icon        string      `json:"icon,omitempty"`
}

// Validation represents parameter validation rules
type Validation struct {
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	Min       *float64 `json:"min,omitempty"`
	Max       *float64 `json:"max,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	Format    string   `json:"format,omitempty"` // email, url, etc.
}

// NodeInput represents an input connection point
type NodeInput struct {
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	Type           string `json:"type"`
	Required       bool   `json:"required"`
	Description    string `json:"description"`
	MaxConnections int    `json:"max_connections"`
}

// NodeOutput represents an output connection point
type NodeOutput struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// NodeDefinition represents the complete definition of a node type
type NodeDefinition struct {
	Name        string       `json:"name"`
	DisplayName string       `json:"display_name"`
	Description string       `json:"description"`
	Version     string       `json:"version"`
	Type        NodeType     `json:"type"`
	Category    NodeCategory `json:"category"`
	Status      NodeStatus   `json:"status"`
	Icon        string       `json:"icon,omitempty"`
	Color       string       `json:"color,omitempty"`
	Subtitle    string       `json:"subtitle,omitempty"`
	Group       []string     `json:"group,omitempty"`
	Tags        []string     `json:"tags,omitempty"`

	// Node behavior
	Parameters  []Parameter  `json:"parameters"`
	Inputs      []NodeInput  `json:"inputs"`
	Outputs     []NodeOutput `json:"outputs"`
	Credentials []string     `json:"credentials,omitempty"`

	// Execution settings
	RetryOnFail      int           `json:"retry_on_fail"`
	ContinueOnFail   bool          `json:"continue_on_fail"`
	AlwaysOutputData bool          `json:"always_output_data"`
	ExecutionOrder   string        `json:"execution_order,omitempty"`
	MaxExecutionTime time.Duration `json:"max_execution_time,omitempty"`

	// Documentation and examples
	DocumentationURL string        `json:"documentation_url,omitempty"`
	Examples         []NodeExample `json:"examples,omitempty"`

	// Versioning and dependencies
	Dependencies []string `json:"dependencies,omitempty"`
	MinVersion   string   `json:"min_version,omitempty"`
	Deprecated   bool     `json:"deprecated"`

	// Registration metadata
	Author       string    `json:"author,omitempty"`
	License      string    `json:"license,omitempty"`
	Repository   string    `json:"repository,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NodeExample represents an example usage of a node
type NodeExample struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	InputData   interface{}            `json:"input_data,omitempty"`
	OutputData  interface{}            `json:"output_data,omitempty"`
}

// NodeExecutor defines the interface that all node executors must implement
type NodeExecutor interface {
	Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error)
	Validate(parameters map[string]interface{}) error
	GetDefinition() *NodeDefinition
}

// NodeFactory is a function that creates a new instance of a node executor
type NodeFactory func() NodeExecutor



// RegistryFilter represents filters for node search
type RegistryFilter struct {
	Type     NodeType
	Category NodeCategory
	Status   NodeStatus
	Search   string
	Tags     []string
	Author   string
	Version  string
	Limit    int
	Offset   int
}

// Registry manages all available node types and their definitions
type Registry struct {
	nodes     map[string]*NodeDefinition
	factories map[string]NodeFactory
	mutex     sync.RWMutex
	logger    logger.Logger
}

// NewRegistry creates a new node registry
func NewRegistry(log logger.Logger) *Registry {
	registry := &Registry{
		nodes:     make(map[string]*NodeDefinition),
		factories: make(map[string]NodeFactory),
		logger:    log,
	}

	// Register core nodes
	registry.registerCoreNodes()

	return registry
}

// Register registers a new node type with its definition and factory
func (r *Registry) Register(definition *NodeDefinition, factory NodeFactory) error {
	if definition == nil {
		return errors.NewValidationError("node definition cannot be nil")
	}
	if factory == nil {
		return errors.NewValidationError("node factory cannot be nil")
	}

	// Validate definition
	if err := r.validateDefinition(definition); err != nil {
		return fmt.Errorf("invalid node definition: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if node already exists
	if _, exists := r.nodes[definition.Name]; exists {
		return errors.NewValidationError(fmt.Sprintf("node '%s' already registered", definition.Name))
	}

	// Set registration metadata
	now := time.Now()
	definition.RegisteredAt = now
	definition.UpdatedAt = now

	// Store definition and factory
	r.nodes[definition.Name] = definition
	r.factories[definition.Name] = factory

	r.logger.Info("Node registered",
		"name", definition.Name,
		"type", string(definition.Type),
		"category", string(definition.Category),
		"version", definition.Version,
	)

	return nil
}

// Unregister removes a node type from the registry
func (r *Registry) Unregister(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.nodes[name]; !exists {
		return errors.NewNotFoundError(fmt.Sprintf("node '%s' not found", name))
	}

	delete(r.nodes, name)
	delete(r.factories, name)

	r.logger.Info("Node unregistered", "name", name)
	return nil
}

// GetDefinition retrieves a node definition by name
func (r *Registry) GetDefinition(name string) (*NodeDefinition, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	definition, exists := r.nodes[name]
	if !exists {
		return nil, errors.NewNotFoundError(fmt.Sprintf("node '%s' not found", name))
	}

	// Return a copy to prevent external modifications
	definitionCopy := *definition
	return &definitionCopy, nil
}

// GetDefinitions retrieves all node definitions, optionally filtered
func (r *Registry) GetDefinitions(filter *RegistryFilter) ([]*NodeDefinition, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var definitions []*NodeDefinition

	for _, definition := range r.nodes {
		if r.matchesFilter(definition, filter) {
			// Create copy
			definitionCopy := *definition
			definitions = append(definitions, &definitionCopy)
		}
	}

	// Sort by name
	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].Name < definitions[j].Name
	})

	// Apply pagination
	if filter != nil {
		start := filter.Offset
		end := start + filter.Limit

		if start > len(definitions) {
			return []*NodeDefinition{}, nil
		}
		if filter.Limit > 0 && end < len(definitions) {
			definitions = definitions[start:end]
		} else if start > 0 {
			definitions = definitions[start:]
		}
	}

	return definitions, nil
}

// CreateExecutor creates a new executor instance for a node type
func (r *Registry) CreateExecutor(name string) (NodeExecutor, error) {
	r.mutex.RLock()
	factory, exists := r.factories[name]
	r.mutex.RUnlock()

	if !exists {
		return nil, errors.NewNotFoundError(fmt.Sprintf("node '%s' not found", name))
	}

	return factory(), nil
}

// GetCategories returns all available node categories
func (r *Registry) GetCategories() []NodeCategory {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	categorySet := make(map[NodeCategory]bool)
	for _, definition := range r.nodes {
		categorySet[definition.Category] = true
	}

	var categories []NodeCategory
	for category := range categorySet {
		categories = append(categories, category)
	}

	sort.Slice(categories, func(i, j int) bool {
		return string(categories[i]) < string(categories[j])
	})

	return categories
}

// GetTypes returns all available node types
func (r *Registry) GetTypes() []NodeType {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	typeSet := make(map[NodeType]bool)
	for _, definition := range r.nodes {
		typeSet[definition.Type] = true
	}

	var types []NodeType
	for nodeType := range typeSet {
		types = append(types, nodeType)
	}

	sort.Slice(types, func(i, j int) bool {
		return string(types[i]) < string(types[j])
	})

	return types
}

// Search searches for nodes based on query string
func (r *Registry) Search(query string) ([]*NodeDefinition, error) {
	filter := &RegistryFilter{
		Search: query,
		Limit:  50,
	}
	return r.GetDefinitions(filter)
}

// ValidateNodeParameters validates node parameters against definition
func (r *Registry) ValidateNodeParameters(nodeName string, parameters map[string]interface{}) error {
	definition, err := r.GetDefinition(nodeName)
	if err != nil {
		return err
	}

	return r.validateParameters(definition.Parameters, parameters)
}

// GetNodeStats returns statistics about registered nodes
func (r *Registry) GetNodeStats() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_nodes"] = len(r.nodes)

	// Count by category
	categoryCount := make(map[string]int)
	typeCount := make(map[string]int)
	statusCount := make(map[string]int)

	for _, definition := range r.nodes {
		categoryCount[string(definition.Category)]++
		typeCount[string(definition.Type)]++
		statusCount[string(definition.Status)]++
	}

	stats["by_category"] = categoryCount
	stats["by_type"] = typeCount
	stats["by_status"] = statusCount

	return stats
}

// Helper methods

func (r *Registry) validateDefinition(definition *NodeDefinition) error {
	if definition.Name == "" {
		return errors.NewValidationError("node name is required")
	}
	if definition.DisplayName == "" {
		return errors.NewValidationError("node display name is required")
	}
	if definition.Version == "" {
		return errors.NewValidationError("node version is required")
	}
	if definition.Type == "" {
		return errors.NewValidationError("node type is required")
	}
	if definition.Category == "" {
		return errors.NewValidationError("node category is required")
	}

	// Validate parameters
	for i, param := range definition.Parameters {
		if err := r.validateParameterDefinition(&param); err != nil {
			return fmt.Errorf("parameter %d validation failed: %w", i, err)
		}
	}

	return nil
}

func (r *Registry) validateParameterDefinition(param *Parameter) error {
	if param.Name == "" {
		return errors.NewValidationError("parameter name is required")
	}
	if param.Type == "" {
		return errors.NewValidationError("parameter type is required")
	}

	// Validate parameter type specific rules
	switch param.Type {
	case ParameterTypeOptions:
		if len(param.Options) == 0 {
			return errors.NewValidationError("options parameter must have at least one option")
		}
	case ParameterTypeCredential:
		if len(param.Credentials) == 0 {
			return errors.NewValidationError("credential parameter must specify credential types")
		}
	}

	return nil
}

func (r *Registry) matchesFilter(definition *NodeDefinition, filter *RegistryFilter) bool {
	if filter == nil {
		return true
	}

	// Filter by type
	if filter.Type != "" && definition.Type != filter.Type {
		return false
	}

	// Filter by category
	if filter.Category != "" && definition.Category != filter.Category {
		return false
	}

	// Filter by status
	if filter.Status != "" && definition.Status != filter.Status {
		return false
	}

	// Filter by author
	if filter.Author != "" && definition.Author != filter.Author {
		return false
	}

	// Filter by version
	if filter.Version != "" && definition.Version != filter.Version {
		return false
	}

	// Filter by search query
	if filter.Search != "" {
		searchLower := strings.ToLower(filter.Search)
		if !strings.Contains(strings.ToLower(definition.Name), searchLower) &&
			!strings.Contains(strings.ToLower(definition.DisplayName), searchLower) &&
			!strings.Contains(strings.ToLower(definition.Description), searchLower) {

			// Check tags
			tagMatch := false
			for _, tag := range definition.Tags {
				if strings.Contains(strings.ToLower(tag), searchLower) {
					tagMatch = true
					break
				}
			}
			if !tagMatch {
				return false
			}
		}
	}

	// Filter by tags
	if len(filter.Tags) > 0 {
		tagMatch := false
		for _, filterTag := range filter.Tags {
			for _, nodeTag := range definition.Tags {
				if strings.EqualFold(filterTag, nodeTag) {
					tagMatch = true
					break
				}
			}
			if tagMatch {
				break
			}
		}
		if !tagMatch {
			return false
		}
	}

	return true
}

func (r *Registry) validateParameters(paramDefs []Parameter, parameters map[string]interface{}) error {
	// Check required parameters
	for _, paramDef := range paramDefs {
		value, exists := parameters[paramDef.Name]

		if paramDef.Required && !exists {
			return errors.NewValidationError(fmt.Sprintf("required parameter '%s' is missing", paramDef.Name))
		}

		if exists {
			if err := r.validateParameterValue(&paramDef, value); err != nil {
				return fmt.Errorf("parameter '%s' validation failed: %w", paramDef.Name, err)
			}
		}
	}

	return nil
}

func (r *Registry) validateParameterValue(paramDef *Parameter, value interface{}) error {
	if value == nil {
		return nil
	}

	switch paramDef.Type {
	case ParameterTypeString:
		if _, ok := value.(string); !ok {
			return errors.NewValidationError("value must be a string")
		}
	case ParameterTypeNumber:
		switch value.(type) {
		case int, int64, float64:
			// Valid numeric types
		default:
			return errors.NewValidationError("value must be a number")
		}
	case ParameterTypeBoolean:
		if _, ok := value.(bool); !ok {
			return errors.NewValidationError("value must be a boolean")
		}
	case ParameterTypeArray:
		rv := reflect.ValueOf(value)
		if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
			return errors.NewValidationError("value must be an array")
		}
	case ParameterTypeObject:
		if _, ok := value.(map[string]interface{}); !ok {
			return errors.NewValidationError("value must be an object")
		}
	}

	return nil
}

func (r *Registry) registerCoreNodes() {
	// Register HTTP Request node
	if err := r.Register(&NodeDefinition{
		Name:        "n8n-nodes-base.httpRequest",
		DisplayName: "HTTP Request",
		Description: "Makes HTTP requests and returns the response data",
		Version:     "2.0.0",
		Type:        NodeTypeHTTP,
		Category:    CategoryCore,
		Status:      NodeStatusStable,
		Icon:        "fa:globe",
		Color:       "#2196F3",
		Subtitle:    "={{$parameter[\"method\"]}} {{$parameter[\"url\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"http", "api", "request", "web", "rest", "webhook"},
	}, func() NodeExecutor {
		return http.New(r.logger)
	}); err != nil {
		r.logger.Error("Failed to register HTTP node", "error", err)
	}

	// Register Slack node
	if err := r.Register(&NodeDefinition{
		Name:        "n8n-nodes-base.slack",
		DisplayName: "Slack",
		Description: "Send messages and interact with Slack",
		Version:     "2.0.0",
		Type:        NodeTypeAction,
		Category:    CategoryCommunication,
		Status:      NodeStatusStable,
		Icon:        "file:slack.svg",
		Color:       "#4A154B",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"channel\"]}}",
		Group:       []string{"output"},
		Tags:        []string{"slack", "messaging", "communication", "chat", "notifications"},
	}, func() NodeExecutor {
		return slack.New(r.logger)
	}); err != nil {
		r.logger.Error("Failed to register Slack node", "error", err)
	}

	// Register Google Sheets node
	if err := r.Register(&NodeDefinition{
		Name:        "n8n-nodes-base.googleSheets",
		DisplayName: "Google Sheets",
		Description: "Read and write data to Google Sheets",
		Version:     "2.0.0",
		Type:        NodeTypeAction,
		Category:    CategoryIntegration,
		Status:      NodeStatusStable,
		Icon:        "file:googlesheets.svg",
		Color:       "#34A853",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"sheet_name\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"google", "sheets", "spreadsheet", "data", "productivity"},
	}, func() NodeExecutor {
		return gsheet.New(r.logger)
	}); err != nil {
		r.logger.Error("Failed to register Google Sheets node", "error", err)
	}

	// Register Database node
	if err := r.Register(&NodeDefinition{
		Name:        "n8n-nodes-base.database",
		DisplayName: "Database",
		Description: "Execute SQL queries against databases",
		Version:     "1.0.0",
		Type:        NodeTypeDatabase,
		Category:    CategoryDatabase,
		Status:      NodeStatusStable,
		Icon:        "fa:database",
		Color:       "#336791",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"database\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"database", "sql", "postgres", "mysql", "data"},
	}, func() NodeExecutor {
		return db.New(r.logger)
	}); err != nil {
		r.logger.Error("Failed to register Database node", "error", err)
	}

	r.logger.Info("Core nodes registered", "count", 4)
}


