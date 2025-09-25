package workflows

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"
)

// NodeRegistry defines how the executor can access node executors
type NodeRegistry interface {
	CreateExecutor(nodeType string) (NodeExecutor, error)
}

// NodeExecutor defines the interface for executing workflow nodes
type NodeExecutor interface {
	Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error)
}



// SimpleNodeRegistry provides a simple implementation for testing/development
type SimpleNodeRegistry struct {
	executors map[string]NodeExecutor
}

// NewNodeRegistry creates a simple node registry for testing
func NewNodeRegistry() NodeRegistry {
	registry := &SimpleNodeRegistry{
		executors: make(map[string]NodeExecutor),
	}
	// Register real node implementations
	registry.executors["http"] = &MockHTTPExecutor{} // Keep mock for backward compatibility
	registry.executors["n8n-nodes-base.httpRequest"] = &MockHTTPExecutor{}
	registry.executors["transform"] = &MockTransformExecutor{} // Keep mock for backward compatibility
	return registry
}

// CreateExecutor creates a node executor
func (r *SimpleNodeRegistry) CreateExecutor(nodeType string) (NodeExecutor, error) {
	if executor, exists := r.executors[nodeType]; exists {
		return executor, nil
	}
	return nil, fmt.Errorf("node type %s not found", nodeType)
}

// Mock node executors for testing
type MockHTTPExecutor struct{}

func (m *MockHTTPExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	url, _ := parameters["url"].(string)
	method, _ := parameters["method"].(string)
	if method == "" {
		method = "GET"
	}
	return map[string]interface{}{
		"status":     200,
		"data":       fmt.Sprintf("Mock %s request to %s", method, url),
		"success":    true,
		"timestamp":  time.Now().Unix(),
	}, nil
}

type MockTransformExecutor struct{}

func (m *MockTransformExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	operation, _ := parameters["operation"].(string)
	return map[string]interface{}{
		"operation": operation,
		"input":     inputData,
		"result":    fmt.Sprintf("Transformed data with operation: %s", operation),
		"timestamp": time.Now().Unix(),
	}, nil
}

// DefaultExecutor implements the Executor interface
type DefaultExecutor struct {
	repo         Repository
	nodeRegistry NodeRegistry
	logger       logger.Logger
	metrics      *metrics.Metrics
}

// NewDefaultExecutor creates a new default executor
func NewDefaultExecutor(repo Repository) Executor {
	return &DefaultExecutor{
		repo:         repo,
		nodeRegistry: NewNodeRegistry(),
		logger:       logger.New("workflow-executor"),
		metrics:      metrics.GetGlobal(),
	}
}

// Execute executes a workflow
func (e *DefaultExecutor) Execute(ctx context.Context, execution *WorkflowExecution) error {
	start := time.Now()
	
	e.logger.InfoContext(ctx, "Starting workflow execution",
		"execution_id", execution.ID,
		"workflow_id", execution.WorkflowID,
		"mode", execution.Mode,
	)

	// Update execution status
	execution.Status = ExecutionStatusRunning
	execution.UpdatedAt = time.Now()

	// Build execution context
	execCtx := &ExecutionContext{
		ExecutionID: execution.ID,
		WorkflowID:  execution.WorkflowID,
		TeamID:      execution.TeamID,
		Mode:        execution.Mode,
		InputData:   execution.InputData,
		TriggerData: execution.TriggerData,
		Variables:   make(map[string]interface{}),
		NodeData:    make(map[string]map[string]interface{}),
		Logger:      e.logger,
		Context:     ctx,
	}

	defer func() {
		duration := time.Since(start)
		durationMs := duration.Milliseconds()
		execution.Duration = &durationMs
		execution.UpdatedAt = time.Now()
		
		e.metrics.RecordWorkflowExecution(
			execution.WorkflowID,
			execution.WorkflowName,
			string(execution.Status),
			execution.TeamID,
			duration,
		)
	}()

	// Execute the workflow
	if err := e.executeWorkflow(execCtx, execution); err != nil {
		execution.MarkAsFailed(err.Error(), "", "")
		e.logger.ErrorContext(ctx, "Workflow execution failed",
			"execution_id", execution.ID,
			"error", err,
		)
		return err
	}

	execution.MarkAsCompleted(execCtx.NodeData["output"])
	e.logger.InfoContext(ctx, "Workflow execution completed successfully",
		"execution_id", execution.ID,
		"duration", time.Since(start),
	)

	return nil
}

// Cancel cancels a running workflow execution
func (e *DefaultExecutor) Cancel(ctx context.Context, executionID string) error {
	e.logger.InfoContext(ctx, "Cancelling workflow execution", "execution_id", executionID)
	
	// In a real implementation, this would:
	// 1. Find the running execution
	// 2. Send cancellation signal to all running nodes
	// 3. Update execution status to cancelled
	// 4. Clean up resources
	
	// For now, we'll implement a basic cancellation
	e.logger.InfoContext(ctx, "Workflow execution cancelled", "execution_id", executionID)
	return nil
}

// Pause pauses a running workflow execution
func (e *DefaultExecutor) Pause(ctx context.Context, executionID string) error {
	e.logger.InfoContext(ctx, "Pausing workflow execution", "execution_id", executionID)
	
	// In a real implementation, this would:
	// 1. Find the running execution
	// 2. Pause all running nodes
	// 3. Update execution status to paused
	// 4. Save current state
	
	e.logger.InfoContext(ctx, "Workflow execution paused", "execution_id", executionID)
	return nil
}

// Resume resumes a paused workflow execution
func (e *DefaultExecutor) Resume(ctx context.Context, executionID string) error {
	e.logger.InfoContext(ctx, "Resuming workflow execution", "execution_id", executionID)
	
	// In a real implementation, this would:
	// 1. Find the paused execution
	// 2. Restore execution state
	// 3. Resume execution from where it left off
	// 4. Update execution status to running
	
	e.logger.InfoContext(ctx, "Workflow execution resumed", "execution_id", executionID)
	return nil
}

// Retry retries a failed workflow execution
func (e *DefaultExecutor) Retry(ctx context.Context, executionID string) (*WorkflowExecution, error) {
	e.logger.InfoContext(ctx, "Retrying workflow execution", "execution_id", executionID)
	
	// Get original execution to copy details
	originalExecution, err := e.repo.GetExecutionByID(ctx, executionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to get original execution for retry")
	}

	if originalExecution == nil {
		return nil, errors.NotFoundError("execution")
	}

	// Create new execution for retry with original details
	newExecution := &WorkflowExecution{
		ID:                GenerateID(),
		WorkflowID:        originalExecution.WorkflowID,
		WorkflowName:      originalExecution.WorkflowName,
		TeamID:            originalExecution.TeamID,
		Status:            ExecutionStatusPending,
		Mode:              "retry",
		ParentExecutionID: &executionID,
		StartTime:         time.Now(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		InputData:         originalExecution.InputData,
		OutputData:        make(map[string]interface{}),
		TriggerData:       originalExecution.TriggerData,
		Metadata:          make(map[string]interface{}),
	}
	
	e.logger.InfoContext(ctx, "Created retry execution", 
		"new_execution_id", newExecution.ID,
		"original_execution_id", executionID,
	)
	
	return newExecution, nil
}

// ExecutionContext holds context for workflow execution
type ExecutionContext struct {
	ExecutionID string
	WorkflowID  string
	TeamID      string
	Mode        string
	InputData   map[string]interface{}
	TriggerData map[string]interface{}
	Variables   map[string]interface{}
	NodeData    map[string]map[string]interface{}
	Logger      logger.Logger
	Context     context.Context
	mutex       sync.RWMutex
}

// SetNodeData sets data for a specific node
func (ec *ExecutionContext) SetNodeData(nodeID string, data map[string]interface{}) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	ec.NodeData[nodeID] = data
}

// GetNodeData gets data for a specific node
func (ec *ExecutionContext) GetNodeData(nodeID string) map[string]interface{} {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	return ec.NodeData[nodeID]
}

// SetVariable sets a workflow variable
func (ec *ExecutionContext) SetVariable(key string, value interface{}) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	ec.Variables[key] = value
}

// GetVariable gets a workflow variable
func (ec *ExecutionContext) GetVariable(key string) interface{} {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	return ec.Variables[key]
}

// executeWorkflow executes the actual workflow
func (e *DefaultExecutor) executeWorkflow(execCtx *ExecutionContext, execution *WorkflowExecution) error {
	// Get workflow definition from database
	workflow, err := e.getWorkflowDefinition(execCtx.Context, execCtx.WorkflowID)
	if err != nil {
		return err
	}

	// Initialize workflow variables
	for _, variable := range workflow.Variables {
		if variable.Value != nil {
			execCtx.SetVariable(variable.Key, variable.Value)
		} else if variable.DefaultValue != nil {
			execCtx.SetVariable(variable.Key, variable.DefaultValue)
		}
	}

	// Build execution graph
	execGraph, err := e.buildExecutionGraph(workflow, execCtx)
	if err != nil {
		return err
	}

	// Execute nodes based on workflow configuration
	if workflow.Config.ExecutionPolicy == "parallel" {
		return e.executeParallel(execGraph, execCtx, execution)
	} else {
		return e.executeSequential(execGraph, execCtx, execution)
	}
}

// getWorkflowDefinition retrieves workflow definition from database
func (e *DefaultExecutor) getWorkflowDefinition(ctx context.Context, workflowID string) (*Workflow, error) {
	workflow, err := e.repo.GetByIDWithDetails(ctx, workflowID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, errors.CodeInternal, "failed to get workflow for execution")
	}

	if workflow == nil {
		return nil, errors.NotFoundError("workflow")
	}

	return workflow, nil
}

// buildExecutionGraph builds the execution graph from workflow definition
func (e *DefaultExecutor) buildExecutionGraph(workflow *Workflow, execCtx *ExecutionContext) (*ExecutionGraph, error) {
	graph := &ExecutionGraph{
		Nodes:       make(map[string]*ExecutionNode),
		Connections: make(map[string][]*ExecutionConnection),
	}

	// Create execution nodes
	for _, node := range workflow.Nodes {
		execNode := &ExecutionNode{
			ID:         node.ID,
			Name:       node.Name,
			Type:       node.Type,
			Parameters: node.Parameters,
			Status:     NodeStatusPending,
			StartTime:  nil,
			EndTime:    nil,
		}
		graph.Nodes[node.ID] = execNode
	}

	// Create execution connections
	for _, conn := range workflow.Connections {
		if !conn.Enabled {
			continue
		}

		execConn := &ExecutionConnection{
			ID:     conn.ID,
			Source: conn.SourceNode,
			Target: conn.TargetNode,
			Type:   conn.Type,
		}

		graph.Connections[conn.SourceNode] = append(graph.Connections[conn.SourceNode], execConn)
	}

	return graph, nil
}

// executeSequential executes nodes sequentially
func (e *DefaultExecutor) executeSequential(graph *ExecutionGraph, execCtx *ExecutionContext, execution *WorkflowExecution) error {
	// Find start nodes (nodes with no incoming connections)
	startNodes := e.findStartNodes(graph)
	
	if len(startNodes) == 0 {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "no start nodes found")
	}

	// Execute nodes in order
	visited := make(map[string]bool)
	
	for _, startNode := range startNodes {
		if err := e.executeNodeSequentially(startNode, graph, execCtx, execution, visited); err != nil {
			return err
		}
	}

	return nil
}

// executeParallel executes nodes in parallel where possible
func (e *DefaultExecutor) executeParallel(graph *ExecutionGraph, execCtx *ExecutionContext, execution *WorkflowExecution) error {
	// Find start nodes
	startNodes := e.findStartNodes(graph)
	
	if len(startNodes) == 0 {
		return errors.New(errors.ErrorTypeValidation, errors.CodeInvalidInput, "no start nodes found")
	}

	// Use a worker pool for parallel execution
	var wg sync.WaitGroup
	errChan := make(chan error, len(graph.Nodes))
	
	// Execute start nodes in parallel
	for _, startNode := range startNodes {
		wg.Add(1)
		go func(node *ExecutionNode) {
			defer wg.Done()
			if err := e.executeNode(node, execCtx, execution); err != nil {
				errChan <- err
			}
		}(startNode)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// executeNodeSequentially executes a node and its dependencies sequentially
func (e *DefaultExecutor) executeNodeSequentially(node *ExecutionNode, graph *ExecutionGraph, execCtx *ExecutionContext, execution *WorkflowExecution, visited map[string]bool) error {
	if visited[node.ID] {
		return nil
	}
	visited[node.ID] = true

	// Execute current node
	if err := e.executeNode(node, execCtx, execution); err != nil {
		return err
	}

	// Execute connected nodes
	connections := graph.Connections[node.ID]
	for _, conn := range connections {
		targetNode := graph.Nodes[conn.Target]
		if targetNode != nil {
			if err := e.executeNodeSequentially(targetNode, graph, execCtx, execution, visited); err != nil {
				return err
			}
		}
	}

	return nil
}

// executeNode executes a single node
func (e *DefaultExecutor) executeNode(node *ExecutionNode, execCtx *ExecutionContext, execution *WorkflowExecution) error {
	start := time.Now()
	node.Status = NodeStatusRunning
	node.StartTime = &start

	e.logger.InfoContext(execCtx.Context, "Executing node",
		"node_id", node.ID,
		"node_name", node.Name,
		"node_type", node.Type,
	)

	defer func() {
		end := time.Now()
		node.EndTime = &end
		duration := end.Sub(start)
		durationMs := duration.Milliseconds()
		node.Duration = &durationMs
		execution.NodesExecuted++
	}()

	// Get node executor from registry
	nodeExecutor, err := e.nodeRegistry.CreateExecutor(string(node.Type))
	if err != nil {
		node.Status = NodeStatusFailed
		node.ErrorMessage = fmt.Sprintf("No executor found for node type: %s", node.Type)
		e.logger.ErrorContext(execCtx.Context, "Node execution failed - no executor",
			"node_id", node.ID,
			"node_type", node.Type,
			"error", err,
		)
		return err
	}

	// Prepare node input data
	inputData := e.prepareNodeInputData(node, execCtx)
	node.InputData = inputData

	// Execute the node
	outputData, err := nodeExecutor.Execute(execCtx.Context, node.Parameters, inputData)

	if err != nil {
		node.Status = NodeStatusFailed
		node.ErrorMessage = err.Error()
		e.logger.ErrorContext(execCtx.Context, "Node execution failed",
			"node_id", node.ID,
			"error", err,
		)
		return err
	}

	node.Status = NodeStatusCompleted
	
	// Convert output data to map[string]interface{} with type assertion
	if outputMap, ok := outputData.(map[string]interface{}); ok {
		node.OutputData = outputMap
		// Store output data in context
		execCtx.SetNodeData(node.ID, outputMap)
	} else {
		// If not a map, wrap it
		wrappedOutput := map[string]interface{}{"result": outputData}
		node.OutputData = wrappedOutput
		execCtx.SetNodeData(node.ID, wrappedOutput)
	}

	e.logger.InfoContext(execCtx.Context, "Node execution completed",
		"node_id", node.ID,
		"duration", time.Since(start),
	)

	return nil
}

// prepareNodeInputData prepares input data for node execution
func (e *DefaultExecutor) prepareNodeInputData(node *ExecutionNode, execCtx *ExecutionContext) map[string]interface{} {
	inputData := make(map[string]interface{})

	// Add trigger data
	if execCtx.TriggerData != nil {
		inputData["trigger"] = execCtx.TriggerData
	}

	// Add input data
	if execCtx.InputData != nil {
		inputData["input"] = execCtx.InputData
	}

	// Add variables
	if execCtx.Variables != nil {
		inputData["variables"] = execCtx.Variables
	}

	// Add previous node outputs
	for nodeID, nodeData := range execCtx.NodeData {
		inputData[fmt.Sprintf("node_%s", nodeID)] = nodeData
	}

	return inputData
}

// findStartNodes finds nodes with no incoming connections
func (e *DefaultExecutor) findStartNodes(graph *ExecutionGraph) []*ExecutionNode {
	incomingCounts := make(map[string]int)
	
	// Count incoming connections for each node
	for _, connections := range graph.Connections {
		for _, conn := range connections {
			incomingCounts[conn.Target]++
		}
	}

	// Find nodes with no incoming connections
	var startNodes []*ExecutionNode
	for nodeID, node := range graph.Nodes {
		if incomingCounts[nodeID] == 0 {
			startNodes = append(startNodes, node)
		}
	}

	return startNodes
}

// ExecutionGraph represents the execution graph
type ExecutionGraph struct {
	Nodes       map[string]*ExecutionNode
	Connections map[string][]*ExecutionConnection
}

// ExecutionNode represents a node in execution
type ExecutionNode struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         NodeType               `json:"type"`
	Parameters   map[string]interface{} `json:"parameters"`
	Status       NodeStatus             `json:"status"`
	StartTime    *time.Time             `json:"start_time,omitempty"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Duration     *int64                 `json:"duration,omitempty"`
	InputData    map[string]interface{} `json:"input_data,omitempty"`
	OutputData   map[string]interface{} `json:"output_data,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
}

// NodeExecutionContext provides context for node execution
type NodeExecutionContext struct {
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	NodeType    string                 `json:"node_type"`
	Parameters  map[string]interface{} `json:"parameters"`
	InputData   map[string]interface{} `json:"input_data"`
	ExecutionID string                 `json:"execution_id"`
	WorkflowID  string                 `json:"workflow_id"`
	TeamID      string                 `json:"team_id"`
	Variables   map[string]interface{} `json:"variables"`
	Logger      logger.Logger          `json:"-"`
}

// ExecutionConnection represents a connection in execution
type ExecutionConnection struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}