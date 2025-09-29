package workflow

import (
	"time"

	"github.com/google/uuid"
)

// Workflow represents a workflow entity
type Workflow struct {
	ID          string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string                 `json:"name" gorm:"not null;size:255"`
	Description string                 `json:"description" gorm:"type:text"`
	Status      string                 `json:"status" gorm:"not null;default:'draft'"`
	TeamID      string                 `json:"team_id" gorm:"type:uuid;not null;index"`
	OwnerID     string                 `json:"owner_id" gorm:"type:uuid;not null;index"`
	Version     int                    `json:"version" gorm:"not null;default:1"`
	IsTemplate  bool                   `json:"is_template" gorm:"not null;default:false"`
	TemplateID  string                 `json:"template_id" gorm:"type:uuid"`

	// Workflow definition stored as JSONB
	Definition map[string]interface{} `json:"definition" gorm:"type:jsonb;not null;default:'{}'"`

	// Configuration
	Config map[string]interface{} `json:"config" gorm:"type:jsonb;not null;default:'{}'"`

	// Tags and metadata
	Tags     []string               `json:"tags" gorm:"type:jsonb"`
	Metadata map[string]interface{} `json:"metadata" gorm:"type:jsonb;not null;default:'{}'"`

	// Statistics
	ExecutionCount  int64      `json:"execution_count" gorm:"not null;default:0"`
	LastExecutedAt  *time.Time `json:"last_executed_at,omitempty"`
	LastExecutionID string     `json:"last_execution_id,omitempty" gorm:"type:uuid"`
	SuccessRate     float64    `json:"success_rate" gorm:"not null;default:0"`
	AverageRuntime  int64      `json:"average_runtime" gorm:"not null;default:0"` // milliseconds

	// Timestamps
	CreatedAt time.Time      `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"not null"`
	DeletedAt *time.Time     `json:"deleted_at,omitempty" gorm:"index"`
	CreatedBy string         `json:"created_by" gorm:"type:uuid;not null"`
	UpdatedBy string         `json:"updated_by" gorm:"type:uuid;not null"`
}

// WorkflowExecution represents a workflow execution instance
type WorkflowExecution struct {
	ID           string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID   string                 `json:"workflow_id" gorm:"type:uuid;not null;index"`
	WorkflowName string                 `json:"workflow_name" gorm:"not null;size:255"`
	TeamID       string                 `json:"team_id" gorm:"type:uuid;not null;index"`
	TriggerID    string                 `json:"trigger_id,omitempty" gorm:"type:uuid"`
	Status       string                 `json:"status" gorm:"not null;default:'pending';index"`
	Mode         string                 `json:"mode" gorm:"not null;default:'manual'"`

	// Execution context and data
	TriggerData  map[string]interface{} `json:"trigger_data" gorm:"type:jsonb;not null;default:'{}'"`
	InputData    map[string]interface{} `json:"input_data" gorm:"type:jsonb;not null;default:'{}'"`
	OutputData   map[string]interface{} `json:"output_data" gorm:"type:jsonb;not null;default:'{}'"`
	ErrorMessage string                 `json:"error_message,omitempty" gorm:"type:text"`
	ErrorStack   string                 `json:"error_stack,omitempty" gorm:"type:text"`
	ErrorNodeID  string                 `json:"error_node_id,omitempty" gorm:"type:uuid"`

	// Timing
	StartTime time.Time  `json:"start_time" gorm:"not null;index"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  *int64     `json:"duration,omitempty"` // milliseconds

	// Execution details
	NodesExecuted int `json:"nodes_executed" gorm:"not null;default:0"`
	NodesTotal    int `json:"nodes_total" gorm:"not null;default:0"`

	// Retry information
	RetryCount        int    `json:"retry_count" gorm:"not null;default:0"`
	MaxRetries        int    `json:"max_retries" gorm:"not null;default:0"`
	ParentExecutionID string `json:"parent_execution_id,omitempty" gorm:"type:uuid"`

	// Resources
	MemoryUsage int64 `json:"memory_usage" gorm:"not null;default:0"` // bytes
	CPUTime     int64 `json:"cpu_time" gorm:"not null;default:0"`     // milliseconds

	// Context
	UserAgent string                 `json:"user_agent" gorm:"size:512"`
	IPAddress string                 `json:"ip_address" gorm:"size:45"`
	Metadata  map[string]interface{} `json:"metadata" gorm:"type:jsonb;not null;default:'{}'"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null"`
}

// NewWorkflow creates a new workflow instance
func NewWorkflow(name, description, teamID, ownerID string) *Workflow {
	return &Workflow{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Status:      "draft",
		TeamID:      teamID,
		OwnerID:     ownerID,
		Version:     1,
		IsTemplate:  false,
		Definition:  make(map[string]interface{}),
		Config:      make(map[string]interface{}),
		Tags:        []string{},
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   ownerID,
		UpdatedBy:   ownerID,
	}
}

// UpdateWorkflow updates a workflow instance
func (w *Workflow) Update(name, description string, definition map[string]interface{}) error {
	if name != "" {
		w.Name = name
	}
	if description != "" {
		w.Description = description
	}
	if definition != nil {
		w.Definition = definition
	}
	w.UpdatedAt = time.Now()
	return nil
}

// Activate sets the workflow status to active
func (w *Workflow) Activate() {
	w.Status = "active"
	w.UpdatedAt = time.Now()
}

// Deactivate sets the workflow status to inactive
func (w *Workflow) Deactivate() {
	w.Status = "inactive"
	w.UpdatedAt = time.Now()
}

// Validate checks if the workflow is valid
func (w *Workflow) Validate() error {
	// Add validation logic here
	if w.Name == "" {
		return ValidationError("workflow name is required")
	}
	if w.TeamID == "" {
		return ValidationError("team ID is required")
	}
	if w.OwnerID == "" {
		return ValidationError("owner ID is required")
	}
	return nil
}

// ValidationError represents a workflow validation error
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}

// WorkflowVersion represents a version of a workflow
type WorkflowVersion struct {
	ID          string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID  string                 `json:"workflow_id" gorm:"type:uuid;not null;index"`
	Version     int                    `json:"version" gorm:"not null"`
	Name        string                 `json:"name" gorm:"not null;size:255"`
	Description string                 `json:"description" gorm:"type:text"`
	Definition  map[string]interface{} `json:"definition" gorm:"type:jsonb;not null"`
	Hash        string                 `json:"hash" gorm:"not null;size:64"` // SHA256 of definition
	ChangeLog   string                 `json:"change_log" gorm:"type:text"`
	IsActive    bool                   `json:"is_active" gorm:"not null;default:false"`
	CreatedAt   time.Time              `json:"created_at"`
	CreatedBy   string                 `json:"created_by" gorm:"type:uuid;not null"`
}

// Node represents a workflow node
type Node struct {
	ID          string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID  string                 `json:"workflow_id" gorm:"type:uuid;not null;index"`
	Name        string                 `json:"name" gorm:"not null;size:255"`
	Type        string                 `json:"type" gorm:"not null;size:255"`
	Parameters  map[string]interface{} `json:"parameters" gorm:"type:jsonb;not null;default:'{}'"`
	Position    map[string]interface{} `json:"position" gorm:"type:jsonb;not null;default:'{}'"` // x, y coordinates
	Connections map[string]interface{} `json:"connections" gorm:"type:jsonb;not null;default:'{}'"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Trigger represents a workflow trigger
type Trigger struct {
	ID         string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID string                 `json:"workflow_id" gorm:"type:uuid;not null;index"`
	Type       string                 `json:"type" gorm:"not null;size:255"`
	Settings   map[string]interface{} `json:"settings" gorm:"type:jsonb;not null;default:'{}'"`
	IsActive   bool                   `json:"is_active" gorm:"not null;default:true"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}