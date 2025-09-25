package workflows

import (
	"context"
	"fmt"
	"time"

	"n8n-pro/internal/workflows/nodes"
)

// EnhancedNodeRegistry provides real node implementations
type EnhancedNodeRegistry struct {
	executors map[string]NodeExecutor
}

// NewEnhancedNodeRegistry creates a new enhanced node registry with real implementations
func NewEnhancedNodeRegistry() NodeRegistry {
	registry := &EnhancedNodeRegistry{
		executors: make(map[string]NodeExecutor),
	}

	// Register real HTTP executor
	httpExecutor := nodes.NewHTTPExecutor()
	registry.executors["http"] = httpExecutor
	registry.executors["n8n-nodes-base.httpRequest"] = httpExecutor
	registry.executors["n8n-nodes-base.http"] = httpExecutor

	// Register real Transform executor
	transformExecutor := nodes.NewTransformExecutor()
	registry.executors["transform"] = transformExecutor
	registry.executors["n8n-nodes-base.transform"] = transformExecutor
	registry.executors["n8n-nodes-base.set"] = transformExecutor

	// Add mock executors for nodes not yet implemented
	registry.executors["webhook"] = &MockWebhookExecutor{}
	registry.executors["schedule"] = &MockScheduleExecutor{}
	registry.executors["email"] = &MockEmailExecutor{}

	return registry
}

// CreateExecutor creates a node executor
func (r *EnhancedNodeRegistry) CreateExecutor(nodeType string) (NodeExecutor, error) {
	if executor, exists := r.executors[nodeType]; exists {
		return executor, nil
	}
	return nil, fmt.Errorf("node type %s not found", nodeType)
}

// GetAvailableNodeTypes returns a list of all available node types
func (r *EnhancedNodeRegistry) GetAvailableNodeTypes() []string {
	var nodeTypes []string
	for nodeType := range r.executors {
		nodeTypes = append(nodeTypes, nodeType)
	}
	return nodeTypes
}

// Mock executors for nodes not yet implemented
type MockWebhookExecutor struct{}

func (m *MockWebhookExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	return map[string]interface{}{
		"status":    "success",
		"message":   "Mock webhook executed",
		"timestamp": time.Now().Unix(),
	}, nil
}

type MockScheduleExecutor struct{}

func (m *MockScheduleExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	return map[string]interface{}{
		"status":    "success",
		"message":   "Mock schedule executed",
		"timestamp": time.Now().Unix(),
	}, nil
}

type MockEmailExecutor struct{}

func (m *MockEmailExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	to, _ := parameters["to"].(string)
	subject, _ := parameters["subject"].(string)
	return map[string]interface{}{
		"status":    "success",
		"message":   fmt.Sprintf("Mock email sent to %s with subject: %s", to, subject),
		"timestamp": time.Now().Unix(),
	}, nil
}