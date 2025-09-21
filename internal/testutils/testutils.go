package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/errors"

	"github.com/google/uuid"
)

// TestUser represents a test user
type TestUser struct {
	ID     string
	Email  string
	Name   string
	TeamID string
	Role   string
}

// TestWorkflow represents a test workflow
type TestWorkflow struct {
	ID          string
	Name        string
	Description string
	TeamID      string
	OwnerID     string
	Status      workflows.WorkflowStatus
	Nodes       []workflows.Node
	Connections []workflows.Connection
	Config      workflows.WorkflowConfig
}

// TestExecution represents a test execution
type TestExecution struct {
	ID          string
	WorkflowID  string
	Status      workflows.ExecutionStatus
	TriggerData map[string]interface{}
	OutputData  map[string]interface{}
}

// CreateTestUser creates a test user with default values
func CreateTestUser() *TestUser {
	return &TestUser{
		ID:     uuid.New().String(),
		Email:  "test@example.com",
		Name:   "Test User",
		TeamID: uuid.New().String(),
		Role:   "admin",
	}
}

// CreateTestWorkflow creates a test workflow with default values
func CreateTestWorkflow(teamID, ownerID string) *TestWorkflow {
	workflowID := uuid.New().String()
	
	return &TestWorkflow{
		ID:          workflowID,
		Name:        "Test Workflow",
		Description: "A test workflow",
		TeamID:      teamID,
		OwnerID:     ownerID,
		Status:      workflows.WorkflowStatusDraft,
		Nodes: []workflows.Node{
			{
				ID:   "start-node",
				Name: "Start",
				Type: workflows.NodeTypeTrigger,
				Position: workflows.Position{
					X: 100,
					Y: 100,
				},
				Parameters: make(map[string]interface{}),
			},
			{
				ID:   "http-node",
				Name: "HTTP Request",
				Type: workflows.NodeTypeHTTP,
				Position: workflows.Position{
					X: 300,
					Y: 100,
				},
				Parameters: map[string]interface{}{
					"url":    "https://api.example.com/test",
					"method": "GET",
				},
			},
		},
		Connections: []workflows.Connection{
			{
				ID:         uuid.New().String(),
				SourceNode: "start-node",
				TargetNode: "http-node",
				Type:       "main",
				Enabled:    true,
			},
		},
		Config: workflows.WorkflowConfig{
			Timeout:             3600,
			MaxExecutionTime:    3600,
			MaxRetryAttempts:    3,
			RetryInterval:       60,
			EnableErrorWorkflow: false,
			EnableLogging:       true,
			LogLevel:            "info",
			EnableMetrics:       true,
			ExecutionPolicy:     "sequential",
			MaxConcurrentRuns:   1,
			Priority:            5,
			Environment:         "test",
			Timezone:            "UTC",
			CustomSettings:      make(map[string]interface{}),
		},
	}
}

// CreateTestExecution creates a test execution
func CreateTestExecution(workflowID string) *TestExecution {
	return &TestExecution{
		ID:         uuid.New().String(),
		WorkflowID: workflowID,
		Status:     workflows.ExecutionStatusPending,
		TriggerData: map[string]interface{}{
			"input": "test data",
		},
		OutputData: make(map[string]interface{}),
	}
}

// ToWorkflow converts TestWorkflow to workflows.Workflow
func (tw *TestWorkflow) ToWorkflow() *workflows.Workflow {
	now := time.Now()
	return &workflows.Workflow{
		ID:          tw.ID,
		Name:        tw.Name,
		Description: tw.Description,
		Status:      tw.Status,
		TeamID:      tw.TeamID,
		OwnerID:     tw.OwnerID,
		Version:     1,
		IsTemplate:  false,
		Nodes:       tw.Nodes,
		Connections: tw.Connections,
		Variables:   []workflows.Variable{},
		Triggers:    []workflows.Trigger{},
		Config:      tw.Config,
		Tags:        []workflows.Tag{},
		Metadata:    make(map[string]interface{}),
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   tw.OwnerID,
		UpdatedBy:   tw.OwnerID,
	}
}

// ToUser converts TestUser to auth.User
func (tu *TestUser) ToUser() *auth.User {
	now := time.Now()
	return &auth.User{
		ID:        tu.ID,
		Email:     tu.Email,
		Name:      tu.Name,
		Active:    true,
		TeamID:    tu.TeamID,
		Role:      tu.Role,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ToExecution converts TestExecution to workflows.WorkflowExecution
func (te *TestExecution) ToExecution() *workflows.WorkflowExecution {
	now := time.Now()
	return &workflows.WorkflowExecution{
		ID:           te.ID,
		WorkflowID:   te.WorkflowID,
		WorkflowName: "Test Workflow",
		TeamID:       uuid.New().String(),
		Status:       te.Status,
		Mode:         "manual",
		TriggerData:  te.TriggerData,
		InputData:    make(map[string]interface{}),
		OutputData:   te.OutputData,
		StartTime:    now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// AssertWorkflowEqual compares two workflows for testing
func AssertWorkflowEqual(t *testing.T, expected, actual *workflows.Workflow) {
	t.Helper()
	
	if expected.ID != actual.ID {
		t.Errorf("Expected ID %s, got %s", expected.ID, actual.ID)
	}
	if expected.Name != actual.Name {
		t.Errorf("Expected Name %s, got %s", expected.Name, actual.Name)
	}
	if expected.TeamID != actual.TeamID {
		t.Errorf("Expected TeamID %s, got %s", expected.TeamID, actual.TeamID)
	}
	if expected.Status != actual.Status {
		t.Errorf("Expected Status %s, got %s", expected.Status, actual.Status)
	}
	if len(expected.Nodes) != len(actual.Nodes) {
		t.Errorf("Expected %d nodes, got %d", len(expected.Nodes), len(actual.Nodes))
	}
}

// AssertExecutionEqual compares two executions for testing
func AssertExecutionEqual(t *testing.T, expected, actual *workflows.WorkflowExecution) {
	t.Helper()
	
	if expected.ID != actual.ID {
		t.Errorf("Expected ID %s, got %s", expected.ID, actual.ID)
	}
	if expected.WorkflowID != actual.WorkflowID {
		t.Errorf("Expected WorkflowID %s, got %s", expected.WorkflowID, actual.WorkflowID)
	}
	if expected.Status != actual.Status {
		t.Errorf("Expected Status %s, got %s", expected.Status, actual.Status)
	}
}

// CreateTestHTTPRequest creates a test HTTP request
func CreateTestHTTPRequest(method, url string, body interface{}) (*http.Request, error) {
	var req *http.Request
	
	if body != nil {
		reqBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req = httptest.NewRequest(method, url, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	
	return req, nil
}

// CreateTestContext creates a test context with timeout
func CreateTestContext(timeout time.Duration) context.Context {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return ctx
}

// CreateComplexTestWorkflow creates a complex workflow for testing
func CreateComplexTestWorkflow(teamID, ownerID string) *workflows.Workflow {
	now := time.Now()
	workflowID := uuid.New().String()
	
	nodes := []workflows.Node{
		{
			ID:   "webhook-trigger",
			Name: "Webhook Trigger",
			Type: workflows.NodeTypeTrigger,
			Position: workflows.Position{X: 100, Y: 100},
			Parameters: map[string]interface{}{
				"path": "/webhook/test",
				"methods": []string{"POST"},
			},
		},
		{
			ID:   "condition-node",
			Name: "Condition Check",
			Type: workflows.NodeTypeCondition,
			Position: workflows.Position{X: 300, Y: 100},
			Parameters: map[string]interface{}{
				"condition": "{{$json.type}} === 'important'",
			},
		},
		{
			ID:   "http-request",
			Name: "HTTP Request",
			Type: workflows.NodeTypeHTTP,
			Position: workflows.Position{X: 500, Y: 50},
			Parameters: map[string]interface{}{
				"url": "https://api.example.com/notify",
				"method": "POST",
				"headers": map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		{
			ID:   "slack-notification",
			Name: "Slack Notification",
			Type: workflows.NodeTypeSlack,
			Position: workflows.Position{X: 500, Y: 150},
			Parameters: map[string]interface{}{
				"channel": "#alerts",
				"message": "New important message received",
			},
		},
		{
			ID:   "database-insert",
			Name: "Database Insert",
			Type: workflows.NodeTypeDatabase,
			Position: workflows.Position{X: 700, Y: 100},
			Parameters: map[string]interface{}{
				"operation": "insert",
				"table": "notifications",
			},
		},
	}
	
	connections := []workflows.Connection{
		{
			ID:         uuid.New().String(),
			SourceNode: "webhook-trigger",
			TargetNode: "condition-node",
			Type:       "main",
			Enabled:    true,
		},
		{
			ID:         uuid.New().String(),
			SourceNode: "condition-node",
			TargetNode: "http-request",
			Type:       "main",
			Enabled:    true,
			Condition: &workflows.ConnectionFilter{
				Field:     "result",
				Operation: "equals",
				Value:     true,
			},
		},
		{
			ID:         uuid.New().String(),
			SourceNode: "condition-node",
			TargetNode: "slack-notification",
			Type:       "main",
			Enabled:    true,
			Condition: &workflows.ConnectionFilter{
				Field:     "result",
				Operation: "equals",
				Value:     false,
			},
		},
		{
			ID:         uuid.New().String(),
			SourceNode: "http-request",
			TargetNode: "database-insert",
			Type:       "main",
			Enabled:    true,
		},
		{
			ID:         uuid.New().String(),
			SourceNode: "slack-notification",
			TargetNode: "database-insert",
			Type:       "main",
			Enabled:    true,
		},
	}
	
	variables := []workflows.Variable{
		{
			ID:    uuid.New().String(),
			Key:   "api_key",
			Value: "test-api-key",
			Type:  "string",
			Encrypted: true,
		},
		{
			ID:    uuid.New().String(),
			Key:   "max_retries",
			Value: 3,
			Type:  "number",
		},
	}
	
	triggers := []workflows.Trigger{
		{
			ID:     uuid.New().String(),
			NodeID: "webhook-trigger",
			Type:   workflows.TriggerTypeWebhook,
			Enabled: true,
			Config: workflows.TriggerConfig{
				WebhookURL:    "/webhook/test",
				WebhookMethod: "POST",
			},
		},
	}
	
	return &workflows.Workflow{
		ID:          workflowID,
		Name:        "Complex Test Workflow",
		Description: "A complex workflow for comprehensive testing",
		Status:      workflows.WorkflowStatusDraft,
		TeamID:      teamID,
		OwnerID:     ownerID,
		Version:     1,
		IsTemplate:  false,
		Nodes:       nodes,
		Connections: connections,
		Variables:   variables,
		Triggers:    triggers,
		Config: workflows.WorkflowConfig{
			Timeout:             7200,
			MaxExecutionTime:    7200,
			MaxRetryAttempts:    5,
			RetryInterval:       120,
			EnableErrorWorkflow: true,
			EnableLogging:       true,
			LogLevel:            "debug",
			EnableMetrics:       true,
			EnableTracing:       true,
			ExecutionPolicy:     "parallel",
			MaxConcurrentRuns:   3,
			Priority:            8,
			Environment:         "test",
			Timezone:            "UTC",
			CustomSettings: map[string]interface{}{
				"slack_webhook": "https://hooks.slack.com/test",
				"db_connection": "test-db",
			},
		},
		Tags:     []workflows.Tag{},
		Metadata: map[string]interface{}{
			"created_by_test": true,
			"complexity":      "high",
		},
		ExecutionCount: 0,
		SuccessRate:    0.0,
		AverageRuntime: 0,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      ownerID,
		UpdatedBy:      ownerID,
	}
}

// ValidateWorkflowStructure validates basic workflow structure
func ValidateWorkflowStructure(t *testing.T, workflow *workflows.Workflow) {
	t.Helper()
	
	if workflow == nil {
		t.Fatal("Workflow is nil")
	}
	
	if workflow.ID == "" {
		t.Error("Workflow ID is empty")
	}
	
	if workflow.Name == "" {
		t.Error("Workflow name is empty")
	}
	
	if workflow.TeamID == "" {
		t.Error("Workflow TeamID is empty")
	}
	
	if workflow.OwnerID == "" {
		t.Error("Workflow OwnerID is empty")
	}
	
	if len(workflow.Nodes) == 0 {
		t.Error("Workflow has no nodes")
	}
	
	// Validate node IDs are unique
	nodeIds := make(map[string]bool)
	for _, node := range workflow.Nodes {
		if nodeIds[node.ID] {
			t.Errorf("Duplicate node ID: %s", node.ID)
		}
		nodeIds[node.ID] = true
	}
	
	// Validate connections reference existing nodes
	for _, conn := range workflow.Connections {
		if !nodeIds[conn.SourceNode] {
			t.Errorf("Connection references non-existent source node: %s", conn.SourceNode)
		}
		if !nodeIds[conn.TargetNode] {
			t.Errorf("Connection references non-existent target node: %s", conn.TargetNode)
		}
	}
}

// CreateTestError creates a test error
func CreateTestError(errorType errors.ErrorType, code errors.ErrorCode, message string) *errors.AppError {
	return errors.New(errorType, code, message)
}

// CreateTestValidationError creates a validation error for testing
func CreateTestValidationError(field string) *errors.AppError {
	return errors.ValidationError(errors.CodeMissingField, fmt.Sprintf("field '%s' is required", field))
}

// AssertError checks if an error matches expected criteria
func AssertError(t *testing.T, err error, expectedType errors.ErrorType, expectedCode errors.ErrorCode) {
	t.Helper()
	
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	
	appErr := errors.GetAppError(err)
	if appErr == nil {
		t.Fatalf("Expected AppError but got: %T", err)
	}
	
	if appErr.Type != expectedType {
		t.Errorf("Expected error type %s, got %s", expectedType, appErr.Type)
	}
	
	if appErr.Code != expectedCode {
		t.Errorf("Expected error code %s, got %s", expectedCode, appErr.Code)
	}
}

// MockTime provides a mock time for testing
type MockTime struct {
	CurrentTime time.Time
}

// Now returns the mock current time
func (mt *MockTime) Now() time.Time {
	return mt.CurrentTime
}

// NewMockTime creates a new mock time instance
func NewMockTime(t time.Time) *MockTime {
	return &MockTime{CurrentTime: t}
}