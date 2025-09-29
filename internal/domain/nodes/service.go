package nodes

import (
	"context"
	"time"

	"n8n-pro/pkg/logger"
)

// Node represents a workflow node
type Node struct {
	ID          string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Type        string                 `json:"type" gorm:"not null;size:255"`
	Name        string                 `json:"name" gorm:"not null;size:255"`
	Description string                 `json:"description" gorm:"type:text"`
	WorkflowID  string                 `json:"workflow_id" gorm:"type:uuid;not null;index"`
	Parameters  map[string]interface{} `json:"parameters" gorm:"type:jsonb;not null;default:'{}'"`
	Position    map[string]interface{} `json:"position" gorm:"type:jsonb;not null;default:'{}'"` // x, y coordinates
	Connections map[string]interface{} `json:"connections" gorm:"type:jsonb;not null;default:'{}'"`
	Inputs      []NodeInput            `json:"inputs" gorm:"-"`
	Outputs     []NodeOutput           `json:"outputs" gorm:"-"`
	IsActive    bool                   `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// NodeInput represents a node input
type NodeInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// NodeOutput represents a node output
type NodeOutput struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// NodeType represents different types of nodes
type NodeType string

const (
	NodeTypeTrigger   NodeType = "trigger"
	NodeTypeAction    NodeType = "action"
	NodeTypeCondition NodeType = "condition"
	NodeTypeLoop      NodeType = "loop"
	NodeTypeTransformer NodeType = "transformer"
	NodeTypeData      NodeType = "data"
	NodeTypeHTTP      NodeType = "http"
	NodeTypeFunction  NodeType = "function"
)

// NodeStatus represents the status of a node
type NodeStatus string

const (
	NodeStatusPending   NodeStatus = "pending"
	NodeStatusRunning   NodeStatus = "running"
	NodeStatusCompleted NodeStatus = "completed"
	NodeStatusFailed    NodeStatus = "failed"
	NodeStatusSkipped   NodeStatus = "skipped"
)

// Service handles node operations
type Service struct {
	repo   Repository
	logger logger.Logger
}

// Repository defines the node data access interface
type Repository interface {
	Create(ctx context.Context, node *Node) error
	GetByID(ctx context.Context, id string) (*Node, error)
	GetByWorkflow(ctx context.Context, workflowID string) ([]*Node, error)
	Update(ctx context.Context, node *Node) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *ListFilter) ([]*Node, int64, error)
	GetNodeTypes(ctx context.Context) ([]*NodeTypeDefinition, error)
}

// ListFilter represents filters for listing nodes
type ListFilter struct {
	WorkflowID string
	NodeType   string
	IsActive   *bool
	Limit      int
	Offset     int
}

// NodeTypeDefinition represents a node type definition
type NodeTypeDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Icon        string                 `json:"icon"`
	Inputs      []NodeInput            `json:"inputs"`
	Outputs     []NodeOutput           `json:"outputs"`
	Parameters  map[string]interface{} `json:"parameters"`
	Defaults    map[string]interface{} `json:"defaults"`
}

// NewService creates a new node service
func NewService(repo Repository, logger logger.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// CreateNode creates a new node
func (s *Service) CreateNode(ctx context.Context, node *Node) error {
	s.logger.Info("Creating node", "name", node.Name, "workflow_id", node.WorkflowID)

	// Validate node
	if err := s.validateNode(node); err != nil {
		return err
	}

	// Set defaults
	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()

	// Create the node
	if err := s.repo.Create(ctx, node); err != nil {
		s.logger.Error("Failed to create node", "name", node.Name, "error", err)
		return err
	}

	s.logger.Info("Node created successfully", "node_id", node.ID)

	return nil
}

// GetNode retrieves a node by ID
func (s *Service) GetNode(ctx context.Context, id string) (*Node, error) {
	node, err := s.repo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get node", "node_id", id, "error", err)
		return nil, err
	}

	return node, nil
}

// GetNodesByWorkflow retrieves nodes for a workflow
func (s *Service) GetNodesByWorkflow(ctx context.Context, workflowID string) ([]*Node, error) {
	nodes, err := s.repo.GetByWorkflow(ctx, workflowID)
	if err != nil {
		s.logger.Error("Failed to get nodes by workflow", "workflow_id", workflowID, "error", err)
		return nil, err
	}

	return nodes, nil
}

// UpdateNode updates an existing node
func (s *Service) UpdateNode(ctx context.Context, node *Node) error {
	// Validate node
	if err := s.validateNode(node); err != nil {
		return err
	}

	node.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, node); err != nil {
		s.logger.Error("Failed to update node", "node_id", node.ID, "error", err)
		return err
	}

	s.logger.Info("Node updated successfully", "node_id", node.ID)

	return nil
}

// DeleteNode deletes a node by ID
func (s *Service) DeleteNode(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete node", "node_id", id, "error", err)
		return err
	}

	s.logger.Info("Node deleted successfully", "node_id", id)

	return nil
}

// ListNodes retrieves nodes based on filters
func (s *Service) ListNodes(ctx context.Context, filter *ListFilter) ([]*Node, int64, error) {
	return s.repo.List(ctx, filter)
}

// GetNodeTypes retrieves available node types
func (s *Service) GetNodeTypes(ctx context.Context) ([]*NodeTypeDefinition, error) {
	return s.repo.GetNodeTypes(ctx)
}

// validateNode validates node data
func (s *Service) validateNode(node *Node) error {
	if node.Name == "" {
		return ValidationError("node name is required")
	}

	if node.Type == "" {
		return ValidationError("node type is required")
	}

	if node.WorkflowID == "" {
		return ValidationError("workflow ID is required")
	}

	if len(node.Name) > 255 {
		return ValidationError("node name cannot exceed 255 characters")
	}

	return nil
}

// ExecuteNode executes a node with the given input
func (s *Service) ExecuteNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info("Executing node", "node_id", node.ID, "type", node.Type)

	// In a real implementation, this would execute the specific node logic
	// based on the node type and parameters
	result, err := s.executeNodeLogic(ctx, node, input)
	if err != nil {
		s.logger.Error("Node execution failed", "node_id", node.ID, "error", err)
		return nil, err
	}

	s.logger.Info("Node execution completed", "node_id", node.ID)

	return result, nil
}

// executeNodeLogic executes the specific logic for a node type
func (s *Service) executeNodeLogic(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	switch NodeType(node.Type) {
	case NodeTypeTrigger:
		return s.executeTriggerNode(ctx, node, input)
	case NodeTypeAction:
		return s.executeActionNode(ctx, node, input)
	case NodeTypeCondition:
		return s.executeConditionNode(ctx, node, input)
	case NodeTypeHTTP:
		return s.executeHTTPNode(ctx, node, input)
	case NodeTypeFunction:
		return s.executeFunctionNode(ctx, node, input)
	case NodeTypeTransformer:
		return s.executeTransformerNode(ctx, node, input)
	default:
		return s.executeGenericNode(ctx, node, input)
	}
}

// executeTriggerNode executes a trigger node
func (s *Service) executeTriggerNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Trigger nodes typically don't take input but generate output
	// For now, return the input as output
	return input, nil
}

// executeActionNode executes an action node
func (s *Service) executeActionNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Action nodes perform operations based on input
	return input, nil
}

// executeConditionNode executes a condition node
func (s *Service) executeConditionNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Condition nodes evaluate conditions and return appropriate output
	return input, nil
}

// executeHTTPNode executes an HTTP node
func (s *Service) executeHTTPNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// HTTP nodes make HTTP requests
	return input, nil
}

// executeFunctionNode executes a function node
func (s *Service) executeFunctionNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Function nodes execute custom code
	return input, nil
}

// executeTransformerNode executes a transformer node
func (s *Service) executeTransformerNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Transformer nodes transform data
	return input, nil
}

// executeGenericNode executes a generic node
func (s *Service) executeGenericNode(ctx context.Context, node *Node, input map[string]interface{}) (map[string]interface{}, error) {
	// Generic node execution
	return input, nil
}

// GetNodeExecutionStatus returns the execution status of a node
func (s *Service) GetNodeExecutionStatus(ctx context.Context, nodeID string) (NodeStatus, error) {
	// In a real implementation, this would check the execution status from the execution engine
	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return NodeStatusFailed, err
	}

	// For now, return completed if the node exists
	if node.IsActive {
		return NodeStatusCompleted, nil
	}

	return NodeStatusPending, nil
}

// ValidationError represents a validation error
type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}