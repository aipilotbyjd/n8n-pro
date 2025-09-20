package workflows

import (
	"encoding/json"
	"fmt"
	"time"

	"n8n-pro/pkg/errors"

	"github.com/google/uuid"
)

// WorkflowStatus represents the status of a workflow
type WorkflowStatus string

const (
	WorkflowStatusActive   WorkflowStatus = "active"
	WorkflowStatusInactive WorkflowStatus = "inactive"
	WorkflowStatusDraft    WorkflowStatus = "draft"
	WorkflowStatusArchived WorkflowStatus = "archived"
)

// ExecutionStatus represents the status of a workflow execution
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCanceled  ExecutionStatus = "canceled"
	ExecutionStatusTimeout   ExecutionStatus = "timeout"
	ExecutionStatusRetrying  ExecutionStatus = "retrying"
	ExecutionStatusWaiting   ExecutionStatus = "waiting"
	ExecutionStatusPaused    ExecutionStatus = "paused"
)

// NodeStatus represents the status of a node execution
type NodeStatus string

const (
	NodeStatusPending   NodeStatus = "pending"
	NodeStatusRunning   NodeStatus = "running"
	NodeStatusCompleted NodeStatus = "completed"
	NodeStatusFailed    NodeStatus = "failed"
	NodeStatusSkipped   NodeStatus = "skipped"
	NodeStatusDisabled  NodeStatus = "disabled"
)

// TriggerType represents the type of workflow trigger
type TriggerType string

const (
	TriggerTypeWebhook   TriggerType = "webhook"
	TriggerTypeSchedule  TriggerType = "schedule"
	TriggerTypeManual    TriggerType = "manual"
	TriggerTypeEmail     TriggerType = "email"
	TriggerTypeFileWatch TriggerType = "file_watch"
	TriggerTypeDatabase  TriggerType = "database"
	TriggerTypeAPI       TriggerType = "api"
)

// NodeType represents the type of workflow node
type NodeType string

const (
	NodeTypeTrigger    NodeType = "trigger"
	NodeTypeAction     NodeType = "action"
	NodeTypeCondition  NodeType = "condition"
	NodeTypeTransform  NodeType = "transform"
	NodeTypeLoop       NodeType = "loop"
	NodeTypeWait       NodeType = "wait"
	NodeTypeSubflow    NodeType = "subflow"
	NodeTypeCode       NodeType = "code"
	NodeTypeWebhook    NodeType = "webhook"
	NodeTypeHTTP       NodeType = "http"
	NodeTypeDatabase   NodeType = "database"
	NodeTypeEmail      NodeType = "email"
	NodeTypeSlack      NodeType = "slack"
	NodeTypeGoogleDocs NodeType = "google_docs"
)

// Workflow represents a complete workflow definition
type Workflow struct {
	ID          string         `json:"id" db:"id"`
	Name        string         `json:"name" db:"name" validate:"required,min=1,max=255"`
	Description string         `json:"description" db:"description"`
	Status      WorkflowStatus `json:"status" db:"status"`
	TeamID      string         `json:"team_id" db:"team_id" validate:"required,uuid"`
	OwnerID     string         `json:"owner_id" db:"owner_id" validate:"required,uuid"`
	Version     int            `json:"version" db:"version"`
	IsTemplate  bool           `json:"is_template" db:"is_template"`
	TemplateID  *string        `json:"template_id,omitempty" db:"template_id"`

	// Workflow definition
	Nodes       []Node       `json:"nodes" db:"-"`
	Connections []Connection `json:"connections" db:"-"`
	Variables   []Variable   `json:"variables" db:"-"`
	Triggers    []Trigger    `json:"triggers" db:"-"`

	// Configuration
	Config WorkflowConfig `json:"config" db:"config"`

	// Metadata
	Tags     []Tag                  `json:"tags" db:"-"`
	Metadata map[string]interface{} `json:"metadata" db:"metadata"`

	// Statistics
	ExecutionCount  int64      `json:"execution_count" db:"execution_count"`
	LastExecutedAt  *time.Time `json:"last_executed_at,omitempty" db:"last_executed_at"`
	LastExecutionID *string    `json:"last_execution_id,omitempty" db:"last_execution_id"`
	SuccessRate     float64    `json:"success_rate" db:"success_rate"`
	AverageRuntime  int64      `json:"average_runtime" db:"average_runtime"` // milliseconds

	// Audit fields
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedBy string     `json:"created_by" db:"created_by"`
	UpdatedBy string     `json:"updated_by" db:"updated_by"`
}

// WorkflowConfig holds workflow-level configuration
type WorkflowConfig struct {
	Timeout             int                    `json:"timeout" validate:"min=1,max=86400"`            // seconds
	MaxExecutionTime    int                    `json:"max_execution_time" validate:"min=1,max=86400"` // seconds
	MaxRetryAttempts    int                    `json:"max_retry_attempts" validate:"min=0,max=10"`
	RetryInterval       int                    `json:"retry_interval" validate:"min=1,max=3600"` // seconds
	EnableErrorWorkflow bool                   `json:"enable_error_workflow"`
	ErrorWorkflowID     *string                `json:"error_workflow_id,omitempty" validate:"omitempty,uuid"`
	EnableLogging       bool                   `json:"enable_logging"`
	LogLevel            string                 `json:"log_level" validate:"oneof=debug info warn error"`
	EnableMetrics       bool                   `json:"enable_metrics"`
	EnableTracing       bool                   `json:"enable_tracing"`
	ExecutionPolicy     string                 `json:"execution_policy" validate:"oneof=parallel sequential"`
	MaxConcurrentRuns   int                    `json:"max_concurrent_runs" validate:"min=1,max=100"`
	Priority            int                    `json:"priority" validate:"min=1,max=10"`
	Environment         string                 `json:"environment"`
	Timezone            string                 `json:"timezone"`
	CustomSettings      map[string]interface{} `json:"custom_settings"`
}

// Node represents a single node in a workflow
type Node struct {
	ID          string                 `json:"id" validate:"required"`
	Name        string                 `json:"name" validate:"required,min=1,max=255"`
	Type        NodeType               `json:"type" validate:"required"`
	SubType     string                 `json:"sub_type"`
	Position    Position               `json:"position"`
	Parameters  map[string]interface{} `json:"parameters"`
	Credentials []CredentialReference  `json:"credentials"`
	Disabled    bool                   `json:"disabled"`
	Notes       string                 `json:"notes"`
	Color       string                 `json:"color"`

	// Execution settings
	ContinueOnFail   bool `json:"continue_on_fail"`
	AlwaysOutputData bool `json:"always_output_data"`
	RetryOnFail      bool `json:"retry_on_fail"`
	MaxTries         int  `json:"max_tries" validate:"min=1,max=5"`
	WaitBetweenTries int  `json:"wait_between_tries"` // milliseconds

	// Code execution (for code nodes)
	Code     string `json:"code,omitempty"`
	Language string `json:"language,omitempty" validate:"omitempty,oneof=javascript python"`

	// Webhook settings (for webhook nodes)
	WebhookID  string            `json:"webhook_id,omitempty"`
	HTTPMethod string            `json:"http_method,omitempty" validate:"omitempty,oneof=GET POST PUT DELETE PATCH"`
	Path       string            `json:"path,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`

	// Schedule settings (for schedule triggers)
	CronExpression string `json:"cron_expression,omitempty"`

	// Metadata
	Version     int                    `json:"version"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Position represents the visual position of a node in the workflow editor
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Connection represents a connection between two nodes
type Connection struct {
	ID         string            `json:"id" validate:"required"`
	SourceNode string            `json:"source_node" validate:"required"`
	TargetNode string            `json:"target_node" validate:"required"`
	SourcePort string            `json:"source_port"`
	TargetPort string            `json:"target_port"`
	Type       string            `json:"type" validate:"oneof=main error"`
	Condition  *ConnectionFilter `json:"condition,omitempty"`
	Enabled    bool              `json:"enabled"`
}

// ConnectionFilter represents conditional logic for connections
type ConnectionFilter struct {
	Field         string      `json:"field"`
	Operation     string      `json:"operation" validate:"oneof=equals not_equals greater less contains starts_with ends_with exists"`
	Value         interface{} `json:"value"`
	CaseSensitive bool        `json:"case_sensitive"`
}

// Variable represents a workflow variable
type Variable struct {
	ID           string      `json:"id" validate:"required"`
	Key          string      `json:"key" validate:"required,min=1,max=100"`
	Value        interface{} `json:"value"`
	Type         string      `json:"type" validate:"oneof=string number boolean object array"`
	Description  string      `json:"description"`
	Encrypted    bool        `json:"encrypted"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value,omitempty"`
}

// Trigger represents a workflow trigger
type Trigger struct {
	ID      string        `json:"id" validate:"required"`
	NodeID  string        `json:"node_id" validate:"required"`
	Type    TriggerType   `json:"type" validate:"required"`
	Enabled bool          `json:"enabled"`
	Config  TriggerConfig `json:"config"`
}

// TriggerConfig holds trigger-specific configuration
type TriggerConfig struct {
	// Webhook trigger
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookMethod  string            `json:"webhook_method,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`

	// Schedule trigger
	CronExpression string     `json:"cron_expression,omitempty"`
	Timezone       string     `json:"timezone,omitempty"`
	StartDate      *time.Time `json:"start_date,omitempty"`
	EndDate        *time.Time `json:"end_date,omitempty"`

	// Email trigger
	EmailAddress string   `json:"email_address,omitempty"`
	EmailSubject string   `json:"email_subject,omitempty"`
	EmailFrom    []string `json:"email_from,omitempty"`

	// File watch trigger
	WatchPath    string   `json:"watch_path,omitempty"`
	FilePatterns []string `json:"file_patterns,omitempty"`
	WatchEvents  []string `json:"watch_events,omitempty"` // create, modify, delete

	// Database trigger
	DatabaseConnection string `json:"database_connection,omitempty"`
	DatabaseTable      string `json:"database_table,omitempty"`
	DatabaseQuery      string `json:"database_query,omitempty"`
	PollInterval       int    `json:"poll_interval,omitempty"` // seconds
}

// CredentialReference represents a reference to stored credentials
type CredentialReference struct {
	ID   string `json:"id" validate:"required,uuid"`
	Name string `json:"name" validate:"required"`
	Type string `json:"type" validate:"required"`
}

// Tag represents a workflow tag
type Tag struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name" validate:"required,min=1,max=50"`
	Color       string    `json:"color" db:"color"`
	Description string    `json:"description" db:"description"`
	TeamID      string    `json:"team_id" db:"team_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	CreatedBy   string    `json:"created_by" db:"created_by"`
}

// WorkflowExecution represents a single execution of a workflow
type WorkflowExecution struct {
	ID           string          `json:"id" db:"id"`
	WorkflowID   string          `json:"workflow_id" db:"workflow_id" validate:"required,uuid"`
	WorkflowName string          `json:"workflow_name" db:"workflow_name"`
	TeamID       string          `json:"team_id" db:"team_id"`
	TriggerID    *string         `json:"trigger_id,omitempty" db:"trigger_id"`
	Status       ExecutionStatus `json:"status" db:"status"`
	Mode         string          `json:"mode" db:"mode"` // manual, webhook, schedule, etc.

	// Execution context
	TriggerData  map[string]interface{} `json:"trigger_data" db:"trigger_data"`
	InputData    map[string]interface{} `json:"input_data" db:"input_data"`
	OutputData   map[string]interface{} `json:"output_data" db:"output_data"`
	ErrorMessage *string                `json:"error_message,omitempty" db:"error_message"`
	ErrorStack   *string                `json:"error_stack,omitempty" db:"error_stack"`
	ErrorNodeID  *string                `json:"error_node_id,omitempty" db:"error_node_id"`

	// Timing
	StartTime time.Time  `json:"start_time" db:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty" db:"end_time"`
	Duration  *int64     `json:"duration,omitempty" db:"duration"` // milliseconds

	// Execution details
	NodesExecuted  int             `json:"nodes_executed" db:"nodes_executed"`
	NodesTotal     int             `json:"nodes_total" db:"nodes_total"`
	NodeExecutions []NodeExecution `json:"node_executions" db:"-"`

	// Retry information
	RetryCount        int     `json:"retry_count" db:"retry_count"`
	MaxRetries        int     `json:"max_retries" db:"max_retries"`
	ParentExecutionID *string `json:"parent_execution_id,omitempty" db:"parent_execution_id"`

	// Resources
	MemoryUsage int64 `json:"memory_usage" db:"memory_usage"` // bytes
	CPUTime     int64 `json:"cpu_time" db:"cpu_time"`         // milliseconds

	// Metadata
	UserAgent string                 `json:"user_agent" db:"user_agent"`
	IPAddress string                 `json:"ip_address" db:"ip_address"`
	Metadata  map[string]interface{} `json:"metadata" db:"metadata"`

	// Audit
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// NodeExecution represents the execution of a single node
type NodeExecution struct {
	ID          string     `json:"id" db:"id"`
	ExecutionID string     `json:"execution_id" db:"execution_id"`
	NodeID      string     `json:"node_id" db:"node_id"`
	NodeName    string     `json:"node_name" db:"node_name"`
	NodeType    NodeType   `json:"node_type" db:"node_type"`
	Status      NodeStatus `json:"status" db:"status"`

	// Data
	InputData    map[string]interface{} `json:"input_data" db:"input_data"`
	OutputData   map[string]interface{} `json:"output_data" db:"output_data"`
	ErrorMessage *string                `json:"error_message,omitempty" db:"error_message"`
	ErrorStack   *string                `json:"error_stack,omitempty" db:"error_stack"`

	// Timing
	StartTime time.Time  `json:"start_time" db:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty" db:"end_time"`
	Duration  *int64     `json:"duration,omitempty" db:"duration"` // milliseconds

	// Retry information
	RetryCount int `json:"retry_count" db:"retry_count"`
	MaxRetries int `json:"max_retries" db:"max_retries"`

	// Resources
	MemoryUsage int64 `json:"memory_usage" db:"memory_usage"`
	CPUTime     int64 `json:"cpu_time" db:"cpu_time"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata" db:"metadata"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// WorkflowVersion represents a version of a workflow
type WorkflowVersion struct {
	ID          string `json:"id" db:"id"`
	WorkflowID  string `json:"workflow_id" db:"workflow_id"`
	Version     int    `json:"version" db:"version"`
	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"description"`
	Definition  string `json:"definition" db:"definition"` // JSON string
	Hash        string `json:"hash" db:"hash"`             // SHA256 of definition
	ChangeLog   string `json:"change_log" db:"change_log"`
	IsActive    bool   `json:"is_active" db:"is_active"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	CreatedBy string    `json:"created_by" db:"created_by"`
}

// WorkflowTemplate represents a reusable workflow template
type WorkflowTemplate struct {
	ID          string   `json:"id" db:"id"`
	Name        string   `json:"name" db:"name"`
	Description string   `json:"description" db:"description"`
	Category    string   `json:"category" db:"category"`
	Tags        []string `json:"tags" db:"tags"`
	Definition  string   `json:"definition" db:"definition"`
	Preview     string   `json:"preview" db:"preview"` // Base64 encoded image
	UsageCount  int64    `json:"usage_count" db:"usage_count"`
	Rating      float64  `json:"rating" db:"rating"`
	IsPublic    bool     `json:"is_public" db:"is_public"`
	AuthorID    string   `json:"author_id" db:"author_id"`
	AuthorName  string   `json:"author_name" db:"author_name"`
	TeamID      *string  `json:"team_id,omitempty" db:"team_id"`

	// Metadata
	Requirements []string               `json:"requirements" db:"requirements"` // Required node types
	Metadata     map[string]interface{} `json:"metadata" db:"metadata"`

	// Audit
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// WorkflowShare represents sharing settings for a workflow
type WorkflowShare struct {
	ID         string     `json:"id" db:"id"`
	WorkflowID string     `json:"workflow_id" db:"workflow_id"`
	ShareType  string     `json:"share_type" db:"share_type"`           // public, team, user
	ShareWith  *string    `json:"share_with,omitempty" db:"share_with"` // user_id or team_id
	Permission string     `json:"permission" db:"permission"`           // read, write, execute
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	CreatedBy string    `json:"created_by" db:"created_by"`
}

// ExecutionSummary represents a summary of workflow executions
type ExecutionSummary struct {
	WorkflowID     string     `json:"workflow_id"`
	TotalCount     int64      `json:"total_count"`
	SuccessCount   int64      `json:"success_count"`
	FailureCount   int64      `json:"failure_count"`
	SuccessRate    float64    `json:"success_rate"`
	AverageRuntime int64      `json:"average_runtime"` // milliseconds
	LastExecution  *time.Time `json:"last_execution,omitempty"`
}

// WorkflowListFilter represents filters for listing workflows
type WorkflowListFilter struct {
	TeamID        *string         `json:"team_id,omitempty"`
	OwnerID       *string         `json:"owner_id,omitempty"`
	Status        *WorkflowStatus `json:"status,omitempty"`
	IsTemplate    *bool           `json:"is_template,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	Search        *string         `json:"search,omitempty"`
	CreatedBy     *string         `json:"created_by,omitempty"`
	CreatedAfter  *time.Time      `json:"created_after,omitempty"`
	CreatedBefore *time.Time      `json:"created_before,omitempty"`
	UpdatedAfter  *time.Time      `json:"updated_after,omitempty"`
	UpdatedBefore *time.Time      `json:"updated_before,omitempty"`
	Limit         int             `json:"limit"`
	Offset        int             `json:"offset"`
	SortBy        string          `json:"sort_by"`
	SortOrder     string          `json:"sort_order"`
}

// ExecutionListFilter represents filters for listing executions
type ExecutionListFilter struct {
	WorkflowID  *string          `json:"workflow_id,omitempty"`
	TeamID      *string          `json:"team_id,omitempty"`
	Status      *ExecutionStatus `json:"status,omitempty"`
	Mode        *string          `json:"mode,omitempty"`
	StartAfter  *time.Time       `json:"start_after,omitempty"`
	StartBefore *time.Time       `json:"start_before,omitempty"`
	Duration    *int64           `json:"duration,omitempty"` // Filter by duration range
	Limit       int              `json:"limit"`
	Offset      int              `json:"offset"`
	SortBy      string           `json:"sort_by"`
	SortOrder   string           `json:"sort_order"`
}

// WorkflowMetrics represents metrics for a workflow
type WorkflowMetrics struct {
	WorkflowID         string               `json:"workflow_id"`
	TotalExecutions    int64                `json:"total_executions"`
	SuccessfulRuns     int64                `json:"successful_runs"`
	FailedRuns         int64                `json:"failed_runs"`
	AverageRuntime     float64              `json:"average_runtime"` // seconds
	MedianRuntime      float64              `json:"median_runtime"`  // seconds
	MinRuntime         float64              `json:"min_runtime"`     // seconds
	MaxRuntime         float64              `json:"max_runtime"`     // seconds
	SuccessRate        float64              `json:"success_rate"`    // percentage
	ExecutionsToday    int64                `json:"executions_today"`
	ExecutionsThisWeek int64                `json:"executions_this_week"`
	LastExecution      *time.Time           `json:"last_execution,omitempty"`
	MostFailedNode     *string              `json:"most_failed_node,omitempty"`
	NodeExecutionStats []NodeExecutionStats `json:"node_execution_stats"`
}

// NodeExecutionStats represents execution statistics for a node
type NodeExecutionStats struct {
	NodeID         string  `json:"node_id"`
	NodeName       string  `json:"node_name"`
	NodeType       string  `json:"node_type"`
	TotalRuns      int64   `json:"total_runs"`
	SuccessfulRuns int64   `json:"successful_runs"`
	FailedRuns     int64   `json:"failed_runs"`
	SuccessRate    float64 `json:"success_rate"`
	AverageRuntime float64 `json:"average_runtime"` // seconds
}

// Helper methods for JSON marshaling/unmarshaling
func (w *Workflow) MarshalJSON() ([]byte, error) {
	type Alias Workflow
	return json.Marshal(&struct {
		*Alias
		NodesJSON       string `json:"nodes_json,omitempty"`
		ConnectionsJSON string `json:"connections_json,omitempty"`
	}{
		Alias: (*Alias)(w),
	})
}

func (w *Workflow) UnmarshalJSON(data []byte) error {
	type Alias Workflow
	aux := &struct {
		*Alias
		NodesJSON       string `json:"nodes_json,omitempty"`
		ConnectionsJSON string `json:"connections_json,omitempty"`
	}{
		Alias: (*Alias)(w),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Parse nodes JSON if present
	if aux.NodesJSON != "" {
		if err := json.Unmarshal([]byte(aux.NodesJSON), &w.Nodes); err != nil {
			return err
		}
	}

	// Parse connections JSON if present
	if aux.ConnectionsJSON != "" {
		if err := json.Unmarshal([]byte(aux.ConnectionsJSON), &w.Connections); err != nil {
			return err
		}
	}

	return nil
}

// IsValid checks if the workflow is valid
func (w *Workflow) IsValid() error {
	if w.Name == "" {
		return errors.ValidationError(errors.CodeMissingField, "workflow name is required")
	}

	if w.TeamID == "" {
		return errors.ValidationError(errors.CodeMissingField, "team ID is required")
	}

	if len(w.Nodes) == 0 {
		return errors.ValidationError(errors.CodeInvalidInput, "workflow must have at least one node")
	}

	// Validate nodes
	nodeIDs := make(map[string]bool)
	for _, node := range w.Nodes {
		if nodeIDs[node.ID] {
			return errors.ValidationError(errors.CodeInvalidInput, fmt.Sprintf("duplicate node ID: %s", node.ID))
		}
		nodeIDs[node.ID] = true

		if err := node.IsValid(); err != nil {
			return err
		}
	}

	// Validate connections
	for _, conn := range w.Connections {
		if !nodeIDs[conn.SourceNode] {
			return errors.ValidationError(errors.CodeInvalidInput, fmt.Sprintf("connection references non-existent source node: %s", conn.SourceNode))
		}
		if !nodeIDs[conn.TargetNode] {
			return errors.ValidationError(errors.CodeInvalidInput, fmt.Sprintf("connection references non-existent target node: %s", conn.TargetNode))
		}
	}

	return nil
}

// IsValid checks if the node is valid
func (n *Node) IsValid() error {
	if n.ID == "" {
		return errors.ValidationError(errors.CodeMissingField, "node ID is required")
	}

	if n.Name == "" {
		return errors.ValidationError(errors.CodeMissingField, "node name is required")
	}

	if n.Type == "" {
		return errors.ValidationError(errors.CodeMissingField, "node type is required")
	}

	// Validate code nodes
	if n.Type == NodeTypeCode {
		if n.Code == "" {
			return errors.ValidationError(errors.CodeMissingField, "code is required for code nodes")
		}
		if n.Language == "" {
			return errors.ValidationError(errors.CodeMissingField, "language is required for code nodes")
		}
	}

	return nil
}

// GenerateID generates a new UUID for the model
func GenerateID() string {
	return uuid.New().String()
}

// NewWorkflow creates a new workflow with default values
func NewWorkflow(name, teamID, ownerID string) *Workflow {
	now := time.Now()
	return &Workflow{
		ID:          GenerateID(),
		Name:        name,
		Status:      WorkflowStatusDraft,
		TeamID:      teamID,
		OwnerID:     ownerID,
		Version:     1,
		IsTemplate:  false,
		Nodes:       []Node{},
		Connections: []Connection{},
		Variables:   []Variable{},
		Triggers:    []Trigger{},
		Config: WorkflowConfig{
			Timeout:             3600,
			MaxExecutionTime:    3600,
			MaxRetryAttempts:    3,
			RetryInterval:       60,
			EnableErrorWorkflow: false,
			EnableLogging:       true,
			LogLevel:            "info",
			EnableMetrics:       true,
			EnableTracing:       false,
			ExecutionPolicy:     "sequential",
			MaxConcurrentRuns:   1,
			Priority:            5,
			Environment:         "production",
			Timezone:            "UTC",
			CustomSettings:      make(map[string]interface{}),
		},
		Tags:           []Tag{},
		Metadata:       make(map[string]interface{}),
		ExecutionCount: 0,
		SuccessRate:    0.0,
		AverageRuntime: 0,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      ownerID,
		UpdatedBy:      ownerID,
	}
}

// NewWorkflowExecution creates a new workflow execution
func NewWorkflowExecution(workflowID, workflowName, teamID string, triggerData map[string]interface{}) *WorkflowExecution {
	now := time.Now()
	return &WorkflowExecution{
		ID:            GenerateID(),
		WorkflowID:    workflowID,
		WorkflowName:  workflowName,
		TeamID:        teamID,
		Status:        ExecutionStatusPending,
		Mode:          "manual",
		TriggerData:   triggerData,
		InputData:     make(map[string]interface{}),
		OutputData:    make(map[string]interface{}),
		StartTime:     now,
		NodesExecuted: 0,
		NodesTotal:    0,
		RetryCount:    0,
		MaxRetries:    3,
		MemoryUsage:   0,
		CPUTime:       0,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// NewNode creates a new workflow node
func NewNode(name string, nodeType NodeType) *Node {
	return &Node{
		ID:               GenerateID(),
		Name:             name,
		Type:             nodeType,
		Position:         Position{X: 0, Y: 0},
		Parameters:       make(map[string]interface{}),
		Credentials:      []CredentialReference{},
		Disabled:         false,
		Notes:            "",
		Color:            "",
		ContinueOnFail:   false,
		AlwaysOutputData: false,
		RetryOnFail:      false,
		MaxTries:         1,
		WaitBetweenTries: 1000,
		Version:          1,
		Description:      "",
		Tags:             []string{},
		Metadata:         make(map[string]interface{}),
	}
}

// NewConnection creates a new node connection
func NewConnection(sourceNode, targetNode string) *Connection {
	return &Connection{
		ID:         GenerateID(),
		SourceNode: sourceNode,
		TargetNode: targetNode,
		SourcePort: "main",
		TargetPort: "main",
		Type:       "main",
		Enabled:    true,
	}
}

// NewVariable creates a new workflow variable
func NewVariable(key string, value interface{}, varType string) *Variable {
	return &Variable{
		ID:           GenerateID(),
		Key:          key,
		Value:        value,
		Type:         varType,
		Description:  "",
		Encrypted:    false,
		Required:     false,
		DefaultValue: nil,
	}
}

// GetDuration returns the execution duration
func (e *WorkflowExecution) GetDuration() time.Duration {
	if e.EndTime == nil {
		return time.Since(e.StartTime)
	}
	return e.EndTime.Sub(e.StartTime)
}

// IsCompleted returns true if the execution is in a final state
func (e *WorkflowExecution) IsCompleted() bool {
	return e.Status == ExecutionStatusCompleted ||
		e.Status == ExecutionStatusFailed ||
		e.Status == ExecutionStatusCanceled ||
		e.Status == ExecutionStatusTimeout
}

// IsRunning returns true if the execution is currently running
func (e *WorkflowExecution) IsRunning() bool {
	return e.Status == ExecutionStatusRunning ||
		e.Status == ExecutionStatusPending ||
		e.Status == ExecutionStatusRetrying
}

// MarkAsCompleted marks the execution as completed
func (e *WorkflowExecution) MarkAsCompleted(outputData map[string]interface{}) {
	now := time.Now()
	e.Status = ExecutionStatusCompleted
	e.EndTime = &now
	e.OutputData = outputData
	duration := e.GetDuration()
	durationMs := duration.Milliseconds()
	e.Duration = &durationMs
	e.UpdatedAt = now
}

// MarkAsFailed marks the execution as failed
func (e *WorkflowExecution) MarkAsFailed(errorMsg, errorStack, errorNodeID string) {
	now := time.Now()
	e.Status = ExecutionStatusFailed
	e.EndTime = &now
	e.ErrorMessage = &errorMsg
	e.ErrorStack = &errorStack
	e.ErrorNodeID = &errorNodeID
	duration := e.GetDuration()
	durationMs := duration.Milliseconds()
	e.Duration = &durationMs
	e.UpdatedAt = now
}

// MarkAsCanceled marks the execution as canceled
func (e *WorkflowExecution) MarkAsCanceled() {
	now := time.Now()
	e.Status = ExecutionStatusCanceled
	e.EndTime = &now
	duration := e.GetDuration()
	durationMs := duration.Milliseconds()
	e.Duration = &durationMs
	e.UpdatedAt = now
}

// GetSuccessRate calculates the success rate as a percentage
func (e *ExecutionSummary) GetSuccessRate() float64 {
	if e.TotalCount == 0 {
		return 0.0
	}
	return float64(e.SuccessCount) / float64(e.TotalCount) * 100.0
}

// GetFailureRate calculates the failure rate as a percentage
func (e *ExecutionSummary) GetFailureRate() float64 {
	if e.TotalCount == 0 {
		return 0.0
	}
	return float64(e.FailureCount) / float64(e.TotalCount) * 100.0
}

// Clone creates a deep copy of the workflow
func (w *Workflow) Clone() *Workflow {
	clone := *w
	clone.ID = GenerateID()
	clone.Name = w.Name + " (Copy)"
	clone.Version = 1
	clone.ExecutionCount = 0
	clone.LastExecutedAt = nil
	clone.LastExecutionID = nil
	clone.SuccessRate = 0.0
	clone.AverageRuntime = 0

	now := time.Now()
	clone.CreatedAt = now
	clone.UpdatedAt = now

	// Deep copy nodes
	clone.Nodes = make([]Node, len(w.Nodes))
	copy(clone.Nodes, w.Nodes)

	// Deep copy connections
	clone.Connections = make([]Connection, len(w.Connections))
	copy(clone.Connections, w.Connections)

	// Deep copy variables
	clone.Variables = make([]Variable, len(w.Variables))
	copy(clone.Variables, w.Variables)

	// Deep copy triggers
	clone.Triggers = make([]Trigger, len(w.Triggers))
	copy(clone.Triggers, w.Triggers)

	return &clone
}

// GetNodeByID returns a node by its ID
func (w *Workflow) GetNodeByID(nodeID string) *Node {
	for i := range w.Nodes {
		if w.Nodes[i].ID == nodeID {
			return &w.Nodes[i]
		}
	}
	return nil
}

// GetConnectionsBySourceNode returns all connections from a source node
func (w *Workflow) GetConnectionsBySourceNode(nodeID string) []Connection {
	var connections []Connection
	for _, conn := range w.Connections {
		if conn.SourceNode == nodeID {
			connections = append(connections, conn)
		}
	}
	return connections
}

// GetConnectionsByTargetNode returns all connections to a target node
func (w *Workflow) GetConnectionsByTargetNode(nodeID string) []Connection {
	var connections []Connection
	for _, conn := range w.Connections {
		if conn.TargetNode == nodeID {
			connections = append(connections, conn)
		}
	}
	return connections
}

// HasTriggerNodes returns true if the workflow has trigger nodes
func (w *Workflow) HasTriggerNodes() bool {
	for _, node := range w.Nodes {
		if node.Type == NodeTypeTrigger {
			return true
		}
	}
	return false
}

// GetTriggerNodes returns all trigger nodes in the workflow
func (w *Workflow) GetTriggerNodes() []Node {
	var triggers []Node
	for _, node := range w.Nodes {
		if node.Type == NodeTypeTrigger {
			triggers = append(triggers, node)
		}
	}
	return triggers
}

// IsExecutable returns true if the workflow can be executed
func (w *Workflow) IsExecutable() bool {
	return w.Status == WorkflowStatusActive && len(w.Nodes) > 0
}

// GetVariableByKey returns a variable by its key
func (w *Workflow) GetVariableByKey(key string) *Variable {
	for i := range w.Variables {
		if w.Variables[i].Key == key {
			return &w.Variables[i]
		}
	}
	return nil
}

// AddNode adds a new node to the workflow
func (w *Workflow) AddNode(node Node) {
	w.Nodes = append(w.Nodes, node)
	w.UpdatedAt = time.Now()
}

// RemoveNode removes a node and its connections from the workflow
func (w *Workflow) RemoveNode(nodeID string) {
	// Remove node
	for i, node := range w.Nodes {
		if node.ID == nodeID {
			w.Nodes = append(w.Nodes[:i], w.Nodes[i+1:]...)
			break
		}
	}

	// Remove connections
	var remainingConnections []Connection
	for _, conn := range w.Connections {
		if conn.SourceNode != nodeID && conn.TargetNode != nodeID {
			remainingConnections = append(remainingConnections, conn)
		}
	}
	w.Connections = remainingConnections
	w.UpdatedAt = time.Now()
}

// AddConnection adds a new connection to the workflow
func (w *Workflow) AddConnection(connection Connection) {
	w.Connections = append(w.Connections, connection)
	w.UpdatedAt = time.Now()
}

// RemoveConnection removes a connection from the workflow
func (w *Workflow) RemoveConnection(connectionID string) {
	for i, conn := range w.Connections {
		if conn.ID == connectionID {
			w.Connections = append(w.Connections[:i], w.Connections[i+1:]...)
			break
		}
	}
	w.UpdatedAt = time.Now()
}
