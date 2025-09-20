package dag

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// NodeStatus represents the execution status of a node
type NodeStatus string

const (
	NodeStatusPending   NodeStatus = "pending"
	NodeStatusRunning   NodeStatus = "running"
	NodeStatusCompleted NodeStatus = "completed"
	NodeStatusFailed    NodeStatus = "failed"
	NodeStatusSkipped   NodeStatus = "skipped"
	NodeStatusCanceled  NodeStatus = "canceled"
)

// EdgeType represents the type of connection between nodes
type EdgeType string

const (
	EdgeTypeMain        EdgeType = "main"        // Normal execution flow
	EdgeTypeError       EdgeType = "error"       // Error handling flow
	EdgeTypeConditional EdgeType = "conditional" // Conditional execution
)

// ExecutionMode represents how the DAG should be executed
type ExecutionMode string

const (
	ExecutionModeSequential ExecutionMode = "sequential" // Execute nodes one by one
	ExecutionModeParallel   ExecutionMode = "parallel"   // Execute nodes in parallel when possible
)

// Node represents a single node in the DAG
type Node struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Parameters  map[string]interface{} `json:"parameters"`
	Position    Position               `json:"position"`
	Disabled    bool                   `json:"disabled"`
	Notes       string                 `json:"notes"`
	RetryOnFail int                    `json:"retry_on_fail"`
	WaitBefore  time.Duration          `json:"wait_before"`
	WaitAfter   time.Duration          `json:"wait_after"`

	// Execution state
	Status        NodeStatus             `json:"status"`
	StartTime     *time.Time             `json:"start_time"`
	EndTime       *time.Time             `json:"end_time"`
	ExecutionTime time.Duration          `json:"execution_time"`
	RetryCount    int                    `json:"retry_count"`
	Error         string                 `json:"error,omitempty"`
	OutputData    map[string]interface{} `json:"output_data,omitempty"`
	InputData     map[string]interface{} `json:"input_data,omitempty"`

	// Dependencies
	Dependencies []string `json:"dependencies"` // Node IDs this node depends on
	Dependents   []string `json:"dependents"`   // Node IDs that depend on this node
}

// Position represents the visual position of a node
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Edge represents a connection between nodes
type Edge struct {
	ID         string                 `json:"id"`
	SourceID   string                 `json:"source_id"`
	TargetID   string                 `json:"target_id"`
	Type       EdgeType               `json:"type"`
	Condition  string                 `json:"condition,omitempty"` // For conditional edges
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// DAG represents a Directed Acyclic Graph for workflow execution
type DAG struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	WorkflowID  string                 `json:"workflow_id"`
	ExecutionID string                 `json:"execution_id"`
	Mode        ExecutionMode          `json:"mode"`
	Settings    map[string]interface{} `json:"settings"`

	// Graph structure
	Nodes map[string]*Node `json:"nodes"`
	Edges map[string]*Edge `json:"edges"`

	// Execution state
	Status      NodeStatus `json:"status"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
	Duration    time.Duration
	CompletedAt *time.Time `json:"completed_at"`

	// Execution control
	Context    context.Context    `json:"-"`
	CancelFunc context.CancelFunc `json:"-"`
	WaitGroup  *sync.WaitGroup    `json:"-"`
	Mutex      *sync.RWMutex      `json:"-"`
	Logger     logger.Logger      `json:"-"`

	// Callbacks
	OnNodeStart    func(nodeID string)                                `json:"-"`
	OnNodeComplete func(nodeID string, output map[string]interface{}) `json:"-"`
	OnNodeError    func(nodeID string, err error)                     `json:"-"`
	OnComplete     func()                                             `json:"-"`
	OnError        func(err error)                                    `json:"-"`
}

// NodeExecutor defines the interface for executing nodes
type NodeExecutor interface {
	Execute(ctx context.Context, node *Node, inputData map[string]interface{}) (map[string]interface{}, error)
	Validate(node *Node) error
	GetType() string
}

// ExecutionContext holds the execution context for the DAG
type ExecutionContext struct {
	WorkflowID  string
	ExecutionID string
	UserID      string
	TeamID      string
	Variables   map[string]interface{}
	Credentials map[string]interface{}
	Settings    map[string]interface{}
	StartTime   time.Time
	MaxDuration time.Duration
	MaxRetries  int
	Executors   map[string]NodeExecutor
	Logger      logger.Logger
}

// NewDAG creates a new DAG instance
func NewDAG(workflowID, executionID string, mode ExecutionMode, log logger.Logger) *DAG {
	ctx, cancel := context.WithCancel(context.Background())

	return &DAG{
		ID:          uuid.New().String(),
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		Mode:        mode,
		Nodes:       make(map[string]*Node),
		Edges:       make(map[string]*Edge),
		Status:      NodeStatusPending,
		Context:     ctx,
		CancelFunc:  cancel,
		WaitGroup:   &sync.WaitGroup{},
		Mutex:       &sync.RWMutex{},
		Logger:      log,
		Settings:    make(map[string]interface{}),
	}
}

// AddNode adds a node to the DAG
func (d *DAG) AddNode(node *Node) error {
	if node == nil {
		return errors.NewValidationError("node cannot be nil")
	}
	if node.ID == "" {
		return errors.NewValidationError("node ID cannot be empty")
	}

	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	if _, exists := d.Nodes[node.ID]; exists {
		return errors.NewValidationError(fmt.Sprintf("node with ID %s already exists", node.ID))
	}

	// Initialize node state
	if node.Status == "" {
		node.Status = NodeStatusPending
	}
	if node.Dependencies == nil {
		node.Dependencies = make([]string, 0)
	}
	if node.Dependents == nil {
		node.Dependents = make([]string, 0)
	}

	d.Nodes[node.ID] = node
	return nil
}

// AddEdge adds an edge between two nodes
func (d *DAG) AddEdge(edge *Edge) error {
	if edge == nil {
		return errors.NewValidationError("edge cannot be nil")
	}
	if edge.ID == "" {
		edge.ID = uuid.New().String()
	}

	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	// Validate source and target nodes exist
	sourceNode, exists := d.Nodes[edge.SourceID]
	if !exists {
		return errors.NewValidationError(fmt.Sprintf("source node %s does not exist", edge.SourceID))
	}

	targetNode, exists := d.Nodes[edge.TargetID]
	if !exists {
		return errors.NewValidationError(fmt.Sprintf("target node %s does not exist", edge.TargetID))
	}

	// Add edge
	d.Edges[edge.ID] = edge

	// Update node dependencies
	if !contains(targetNode.Dependencies, edge.SourceID) {
		targetNode.Dependencies = append(targetNode.Dependencies, edge.SourceID)
	}
	if !contains(sourceNode.Dependents, edge.TargetID) {
		sourceNode.Dependents = append(sourceNode.Dependents, edge.TargetID)
	}

	return nil
}

// Validate validates the DAG structure
func (d *DAG) Validate() error {
	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	// Check for cycles
	if err := d.checkForCycles(); err != nil {
		return err
	}

	// Validate each node
	for _, node := range d.Nodes {
		if err := d.validateNode(node); err != nil {
			return fmt.Errorf("node %s validation failed: %w", node.ID, err)
		}
	}

	// Validate edges
	for _, edge := range d.Edges {
		if err := d.validateEdge(edge); err != nil {
			return fmt.Errorf("edge %s validation failed: %w", edge.ID, err)
		}
	}

	return nil
}

// Execute executes the DAG
func (d *DAG) Execute(ctx *ExecutionContext) error {
	d.Logger.Info("Starting DAG execution",
		"dag_id", d.ID,
		"workflow_id", d.WorkflowID,
		"execution_id", d.ExecutionID,
		"mode", string(d.Mode),
	)

	// Validate DAG before execution
	if err := d.Validate(); err != nil {
		return fmt.Errorf("DAG validation failed: %w", err)
	}

	d.Mutex.Lock()
	d.Status = NodeStatusRunning
	now := time.Now()
	d.StartTime = &now
	d.Mutex.Unlock()

	// Set up execution timeout if specified
	execCtx := d.Context
	if ctx.MaxDuration > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(d.Context, ctx.MaxDuration)
		defer cancel()
	}

	// Execute based on mode
	var err error
	switch d.Mode {
	case ExecutionModeSequential:
		err = d.executeSequential(execCtx, ctx)
	case ExecutionModeParallel:
		err = d.executeParallel(execCtx, ctx)
	default:
		err = fmt.Errorf("unsupported execution mode: %s", d.Mode)
	}

	// Update final status
	d.Mutex.Lock()
	if err != nil {
		d.Status = NodeStatusFailed
		if d.OnError != nil {
			go d.OnError(err)
		}
	} else {
		d.Status = NodeStatusCompleted
		if d.OnComplete != nil {
			go d.OnComplete()
		}
	}

	endTime := time.Now()
	d.EndTime = &endTime
	d.CompletedAt = &endTime
	if d.StartTime != nil {
		d.Duration = endTime.Sub(*d.StartTime)
	}
	d.Mutex.Unlock()

	d.Logger.Info("DAG execution completed",
		"dag_id", d.ID,
		"status", string(d.Status),
		"duration", d.Duration,
		"error", err,
	)

	return err
}

// executeSequential executes nodes sequentially based on dependencies
func (d *DAG) executeSequential(ctx context.Context, execCtx *ExecutionContext) error {
	executed := make(map[string]bool)

	for len(executed) < len(d.Nodes) {
		// Find nodes ready for execution
		readyNodes := d.getReadyNodes(executed)
		if len(readyNodes) == 0 {
			// Check if we're done or stuck
			if len(executed) == len(d.Nodes) {
				break
			}
			return errors.NewExecutionError("DAG execution stuck - no ready nodes found")
		}

		// Execute the first ready node
		node := readyNodes[0]
		if err := d.executeNode(ctx, execCtx, node); err != nil {
			return fmt.Errorf("failed to execute node %s: %w", node.ID, err)
		}
		executed[node.ID] = true
	}

	return nil
}

// executeParallel executes nodes in parallel when possible
func (d *DAG) executeParallel(ctx context.Context, execCtx *ExecutionContext) error {
	executed := make(map[string]bool)
	executing := make(map[string]bool)
	errors := make(chan error, len(d.Nodes))

	for len(executed) < len(d.Nodes) {
		// Find nodes ready for execution
		readyNodes := d.getReadyNodes(executed)

		// Start execution for all ready nodes
		for _, node := range readyNodes {
			if !executing[node.ID] {
				executing[node.ID] = true
				d.WaitGroup.Add(1)

				go func(n *Node) {
					defer d.WaitGroup.Done()
					if err := d.executeNode(ctx, execCtx, n); err != nil {
						errors <- fmt.Errorf("node %s failed: %w", n.ID, err)
						return
					}

					d.Mutex.Lock()
					executed[n.ID] = true
					delete(executing, n.ID)
					d.Mutex.Unlock()
				}(node)
			}
		}

		// Wait for at least one node to complete or error
		done := make(chan struct{})
		go func() {
			d.WaitGroup.Wait()
			close(done)
		}()

		select {
		case err := <-errors:
			d.Cancel()
			return err
		case <-done:
			// Continue to next iteration
		case <-ctx.Done():
			d.Cancel()
			return ctx.Err()
		}

		// Small delay to prevent busy waiting
		time.Sleep(10 * time.Millisecond)
	}

	return nil
}

// executeNode executes a single node
func (d *DAG) executeNode(ctx context.Context, execCtx *ExecutionContext, node *Node) error {
	if node.Disabled {
		d.setNodeStatus(node, NodeStatusSkipped)
		d.Logger.Info("Node skipped (disabled)", "node_id", node.ID, "node_name", node.Name)
		return nil
	}

	d.Logger.Info("Executing node", "node_id", node.ID, "node_name", node.Name, "node_type", node.Type)

	// Set node status to running
	d.setNodeStatus(node, NodeStatusRunning)
	startTime := time.Now()
	node.StartTime = &startTime

	// Trigger start callback
	if d.OnNodeStart != nil {
		go d.OnNodeStart(node.ID)
	}

	// Wait before execution if specified
	if node.WaitBefore > 0 {
		select {
		case <-time.After(node.WaitBefore):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Get input data from dependencies
	inputData, err := d.getNodeInputData(node)
	if err != nil {
		return fmt.Errorf("failed to get input data: %w", err)
	}
	node.InputData = inputData

	// Find appropriate executor
	executor, exists := execCtx.Executors[node.Type]
	if !exists {
		return fmt.Errorf("no executor found for node type: %s", node.Type)
	}

	// Execute with retries
	var outputData map[string]interface{}
	maxRetries := node.RetryOnFail
	if maxRetries == 0 {
		maxRetries = execCtx.MaxRetries
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			d.Logger.Info("Retrying node execution", "node_id", node.ID, "attempt", attempt)
			// Exponential backoff
			backoffDuration := time.Duration(attempt*attempt) * time.Second
			select {
			case <-time.After(backoffDuration):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		outputData, err = executor.Execute(ctx, node, inputData)
		if err == nil {
			break
		}

		node.RetryCount = attempt
		d.Logger.Warn("Node execution failed", "node_id", node.ID, "attempt", attempt, "error", err)

		if attempt == maxRetries {
			// Final failure
			d.setNodeStatus(node, NodeStatusFailed)
			node.Error = err.Error()
			endTime := time.Now()
			node.EndTime = &endTime
			node.ExecutionTime = endTime.Sub(startTime)

			if d.OnNodeError != nil {
				go d.OnNodeError(node.ID, err)
			}

			return err
		}
	}

	// Success
	node.OutputData = outputData
	endTime := time.Now()
	node.EndTime = &endTime
	node.ExecutionTime = endTime.Sub(startTime)
	d.setNodeStatus(node, NodeStatusCompleted)

	// Wait after execution if specified
	if node.WaitAfter > 0 {
		select {
		case <-time.After(node.WaitAfter):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Trigger complete callback
	if d.OnNodeComplete != nil {
		go d.OnNodeComplete(node.ID, outputData)
	}

	d.Logger.Info("Node executed successfully",
		"node_id", node.ID,
		"node_name", node.Name,
		"duration", node.ExecutionTime,
		"retries", node.RetryCount,
	)

	return nil
}

// getReadyNodes returns nodes that are ready for execution
func (d *DAG) getReadyNodes(executed map[string]bool) []*Node {
	var ready []*Node

	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	for _, node := range d.Nodes {
		if executed[node.ID] || node.Status == NodeStatusRunning {
			continue
		}

		// Check if all dependencies are completed
		allDepsCompleted := true
		for _, depID := range node.Dependencies {
			if !executed[depID] {
				allDepsCompleted = false
				break
			}
		}

		if allDepsCompleted {
			ready = append(ready, node)
		}
	}

	return ready
}

// getNodeInputData collects input data from node dependencies
func (d *DAG) getNodeInputData(node *Node) (map[string]interface{}, error) {
	inputData := make(map[string]interface{})

	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	for _, depID := range node.Dependencies {
		depNode, exists := d.Nodes[depID]
		if !exists {
			continue
		}

		if depNode.Status == NodeStatusCompleted && depNode.OutputData != nil {
			// Merge output data from dependency
			for key, value := range depNode.OutputData {
				inputData[fmt.Sprintf("%s.%s", depID, key)] = value
			}
		}
	}

	return inputData, nil
}

// setNodeStatus safely updates node status
func (d *DAG) setNodeStatus(node *Node, status NodeStatus) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	node.Status = status
}

// Cancel cancels the DAG execution
func (d *DAG) Cancel() {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	if d.CancelFunc != nil {
		d.CancelFunc()
	}

	// Mark all running nodes as canceled
	for _, node := range d.Nodes {
		if node.Status == NodeStatusRunning {
			node.Status = NodeStatusCanceled
		}
	}

	d.Status = NodeStatusCanceled
}

// GetStatus returns the current DAG status
func (d *DAG) GetStatus() NodeStatus {
	d.Mutex.RLock()
	defer d.Mutex.RUnlock()
	return d.Status
}

// GetNodeStatus returns the status of a specific node
func (d *DAG) GetNodeStatus(nodeID string) (NodeStatus, error) {
	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	node, exists := d.Nodes[nodeID]
	if !exists {
		return "", errors.NewValidationError(fmt.Sprintf("node %s not found", nodeID))
	}

	return node.Status, nil
}

// GetCompletedNodes returns all completed nodes
func (d *DAG) GetCompletedNodes() []*Node {
	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	var completed []*Node
	for _, node := range d.Nodes {
		if node.Status == NodeStatusCompleted {
			completed = append(completed, node)
		}
	}

	return completed
}

// Helper methods

func (d *DAG) checkForCycles() error {
	// Use DFS to detect cycles
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	for nodeID := range d.Nodes {
		if !visited[nodeID] {
			if d.hasCycleDFS(nodeID, visited, recStack) {
				return errors.NewValidationError("DAG contains cycles")
			}
		}
	}

	return nil
}

func (d *DAG) hasCycleDFS(nodeID string, visited, recStack map[string]bool) bool {
	visited[nodeID] = true
	recStack[nodeID] = true

	node := d.Nodes[nodeID]
	for _, depID := range node.Dependents {
		if !visited[depID] {
			if d.hasCycleDFS(depID, visited, recStack) {
				return true
			}
		} else if recStack[depID] {
			return true
		}
	}

	recStack[nodeID] = false
	return false
}

func (d *DAG) validateNode(node *Node) error {
	if node.ID == "" {
		return errors.NewValidationError("node ID cannot be empty")
	}
	if node.Type == "" {
		return errors.NewValidationError("node type cannot be empty")
	}
	return nil
}

func (d *DAG) validateEdge(edge *Edge) error {
	if edge.SourceID == "" || edge.TargetID == "" {
		return errors.NewValidationError("edge source and target cannot be empty")
	}
	if edge.SourceID == edge.TargetID {
		return errors.NewValidationError("edge cannot connect node to itself")
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetExecutionStats returns execution statistics
func (d *DAG) GetExecutionStats() map[string]interface{} {
	d.Mutex.RLock()
	defer d.Mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_nodes"] = len(d.Nodes)
	stats["status"] = string(d.Status)
	stats["duration"] = d.Duration

	// Count nodes by status
	statusCounts := make(map[string]int)
	for _, node := range d.Nodes {
		statusCounts[string(node.Status)]++
	}
	stats["node_status_counts"] = statusCounts

	return stats
}
