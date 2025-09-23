package nodes

import (
	"context"
	"time"
)

// NodeExecutor defines the interface that all node executors must implement
type NodeExecutor interface {
	Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error)
	Validate(parameters map[string]interface{}) error
	GetDefinition() *NodeDefinition
}

// NodeFactory is a function that creates a new instance of a node executor
type NodeFactory func() NodeExecutor

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