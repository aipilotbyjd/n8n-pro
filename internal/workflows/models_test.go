package workflows

import (
	"encoding/json"
	"testing"

	"n8n-pro/pkg/errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkflowModel(t *testing.T) {
	t.Run("NewWorkflow creates valid workflow", func(t *testing.T) {
		teamID := uuid.New().String()
		ownerID := uuid.New().String()
		name := "Test Workflow"

		workflow := NewWorkflow(name, teamID, ownerID)

		assert.NotEmpty(t, workflow.ID)
		assert.Equal(t, name, workflow.Name)
		assert.Equal(t, teamID, workflow.TeamID)
		assert.Equal(t, ownerID, workflow.OwnerID)
		assert.Equal(t, WorkflowStatusDraft, workflow.Status)
		assert.Equal(t, 1, workflow.Version)
		assert.False(t, workflow.IsTemplate)
		assert.NotNil(t, workflow.Nodes)
		assert.NotNil(t, workflow.Connections)
		assert.NotNil(t, workflow.Variables)
		assert.NotNil(t, workflow.Triggers)
		assert.NotNil(t, workflow.Tags)
		assert.NotNil(t, workflow.Metadata)
		assert.NotNil(t, workflow.Config.CustomSettings)
		
		// Test default config values
		assert.Equal(t, 3600, workflow.Config.Timeout)
		assert.Equal(t, 3, workflow.Config.MaxRetryAttempts)
		assert.Equal(t, "info", workflow.Config.LogLevel)
		assert.Equal(t, "sequential", workflow.Config.ExecutionPolicy)
		assert.Equal(t, 1, workflow.Config.MaxConcurrentRuns)
	})

	t.Run("IsValid returns no error for valid workflow", func(t *testing.T) {
		teamID := uuid.New().String()
		userID := uuid.New().String()
		workflow := NewWorkflow("Test Workflow", teamID, userID)
		
		// Add a simple node to make it valid
		node := NewNode("Start", NodeTypeTrigger)
		workflow.AddNode(*node)

		err := workflow.IsValid()
		assert.NoError(t, err)
	})

	t.Run("IsValid returns error for invalid workflow", func(t *testing.T) {
		t.Run("missing name", func(t *testing.T) {
			workflow := &Workflow{
				Name:   "",
				TeamID: uuid.New().String(),
				Nodes:  []Node{{ID: "test", Name: "Test", Type: NodeTypeTrigger}},
			}

			err := workflow.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeMissingField)
		})

		t.Run("missing teamID", func(t *testing.T) {
			workflow := &Workflow{
				Name:   "Test Workflow",
				TeamID: "",
				Nodes:  []Node{{ID: "test", Name: "Test", Type: NodeTypeTrigger}},
			}

			err := workflow.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeMissingField)
		})

		t.Run("no nodes", func(t *testing.T) {
			workflow := &Workflow{
				Name:   "Test Workflow",
				TeamID: uuid.New().String(),
				Nodes:  []Node{},
			}

			err := workflow.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeInvalidInput)
		})

		t.Run("duplicate node IDs", func(t *testing.T) {
			workflow := &Workflow{
				Name:   "Test Workflow",
				TeamID: uuid.New().String(),
				Nodes: []Node{
					{ID: "same-id", Name: "Node 1", Type: NodeTypeTrigger},
					{ID: "same-id", Name: "Node 2", Type: NodeTypeAction},
				},
			}

			err := workflow.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeInvalidInput)
		})
	})

	t.Run("Workflow helper methods", func(t *testing.T) {
		teamID := uuid.New().String()
		userID := uuid.New().String()
		workflow := NewWorkflow("Test Workflow", teamID, userID)
		
		// Add nodes
		startNode := NewNode("Start", NodeTypeTrigger)
		startNode.ID = "start-node"
		httpNode := NewNode("HTTP Request", NodeTypeHTTP)
		httpNode.ID = "http-node"
		workflow.AddNode(*startNode)
		workflow.AddNode(*httpNode)
		
		// Add connection
		connection := NewConnection("start-node", "http-node")
		workflow.AddConnection(*connection)

		t.Run("GetNodeByID", func(t *testing.T) {
			node := workflow.GetNodeByID("start-node")
			assert.NotNil(t, node)
			assert.Equal(t, "start-node", node.ID)
			assert.Equal(t, "Start", node.Name)

			nonExistentNode := workflow.GetNodeByID("non-existent")
			assert.Nil(t, nonExistentNode)
		})

		t.Run("GetConnectionsBySourceNode", func(t *testing.T) {
			connections := workflow.GetConnectionsBySourceNode("start-node")
			assert.Len(t, connections, 1)
			assert.Equal(t, "http-node", connections[0].TargetNode)

			noConnections := workflow.GetConnectionsBySourceNode("http-node")
			assert.Len(t, noConnections, 0)
		})

		t.Run("HasTriggerNodes", func(t *testing.T) {
			assert.True(t, workflow.HasTriggerNodes())

			workflowWithoutTriggers := &Workflow{
				Nodes: []Node{
					{ID: "action", Type: NodeTypeAction},
				},
			}
			assert.False(t, workflowWithoutTriggers.HasTriggerNodes())
		})

		t.Run("IsExecutable", func(t *testing.T) {
			workflow.Status = WorkflowStatusActive
			assert.True(t, workflow.IsExecutable())

			workflow.Status = WorkflowStatusInactive
			assert.False(t, workflow.IsExecutable())
		})
	})

	t.Run("Clone workflow", func(t *testing.T) {
		original := NewWorkflow("Original Workflow", "team-id", "owner-id")
		original.Version = 5
		original.ExecutionCount = 100
		original.LastExecutionID = &[]string{"exec-123"}[0]

		clone := original.Clone()

		assert.NotEqual(t, original.ID, clone.ID)
		assert.Equal(t, "Original Workflow (Copy)", clone.Name)
		assert.Equal(t, 1, clone.Version)
		assert.Equal(t, int64(0), clone.ExecutionCount)
		assert.Nil(t, clone.LastExecutionID)
		assert.Equal(t, original.TeamID, clone.TeamID)
		assert.Equal(t, original.OwnerID, clone.OwnerID)
	})
}

func TestNodeModel(t *testing.T) {
	t.Run("NewNode creates valid node", func(t *testing.T) {
		node := NewNode("Test Node", NodeTypeHTTP)

		assert.NotEmpty(t, node.ID)
		assert.Equal(t, "Test Node", node.Name)
		assert.Equal(t, NodeTypeHTTP, node.Type)
		assert.NotNil(t, node.Parameters)
		assert.NotNil(t, node.Credentials)
		assert.NotNil(t, node.Tags)
		assert.NotNil(t, node.Metadata)
		assert.False(t, node.Disabled)
		assert.Equal(t, 1, node.MaxTries)
	})

	t.Run("IsValid returns no error for valid node", func(t *testing.T) {
		node := NewNode("Test Node", NodeTypeHTTP)
		err := node.IsValid()
		assert.NoError(t, err)
	})

	t.Run("IsValid returns error for invalid node", func(t *testing.T) {
		t.Run("missing ID", func(t *testing.T) {
			node := &Node{
				ID:   "",
				Name: "Test",
				Type: NodeTypeHTTP,
			}

			err := node.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeMissingField)
		})

		t.Run("code node without code", func(t *testing.T) {
			node := &Node{
				ID:   "test-id",
				Name: "Test",
				Type: NodeTypeCode,
				Code: "",
			}

			err := node.IsValid()
			assert.Error(t, err)
			assertError(t, err, errors.ErrorTypeValidation, errors.CodeMissingField)
		})
	})
}

func TestWorkflowExecutionModel(t *testing.T) {
	t.Run("NewWorkflowExecution creates valid execution", func(t *testing.T) {
		workflowID := uuid.New().String()
		workflowName := "Test Workflow"
		teamID := uuid.New().String()
		triggerData := map[string]interface{}{"test": "data"}

		execution := NewWorkflowExecution(workflowID, workflowName, teamID, triggerData)

		assert.NotEmpty(t, execution.ID)
		assert.Equal(t, workflowID, execution.WorkflowID)
		assert.Equal(t, workflowName, execution.WorkflowName)
		assert.Equal(t, teamID, execution.TeamID)
		assert.Equal(t, ExecutionStatusPending, execution.Status)
		assert.Equal(t, "manual", execution.Mode)
		assert.Equal(t, triggerData, execution.TriggerData)
		assert.NotNil(t, execution.InputData)
		assert.NotNil(t, execution.OutputData)
		assert.NotNil(t, execution.Metadata)
		assert.Equal(t, 3, execution.MaxRetries)
	})

	t.Run("Execution status methods", func(t *testing.T) {
		execution := NewWorkflowExecution("wf-id", "Test", "team-id", nil)

		t.Run("IsCompleted", func(t *testing.T) {
			assert.False(t, execution.IsCompleted())

			execution.Status = ExecutionStatusCompleted
			assert.True(t, execution.IsCompleted())

			execution.Status = ExecutionStatusFailed
			assert.True(t, execution.IsCompleted())
		})

		t.Run("IsRunning", func(t *testing.T) {
			execution.Status = ExecutionStatusPending
			assert.True(t, execution.IsRunning())

			execution.Status = ExecutionStatusRunning
			assert.True(t, execution.IsRunning())

			execution.Status = ExecutionStatusCompleted
			assert.False(t, execution.IsRunning())
		})
	})

	t.Run("MarkAsCompleted", func(t *testing.T) {
		execution := NewWorkflowExecution("wf-id", "Test", "team-id", nil)
		outputData := map[string]interface{}{"result": "success"}

		execution.MarkAsCompleted(outputData)

		assert.Equal(t, ExecutionStatusCompleted, execution.Status)
		assert.NotNil(t, execution.EndTime)
		assert.Equal(t, outputData, execution.OutputData)
		assert.NotNil(t, execution.Duration)
	})
}

func TestGenerateID(t *testing.T) {
	t.Run("GenerateID creates unique IDs", func(t *testing.T) {
		id1 := GenerateID()
		id2 := GenerateID()

		assert.NotEmpty(t, id1)
		assert.NotEmpty(t, id2)
		assert.NotEqual(t, id1, id2)

		// Validate UUID format
		_, err := uuid.Parse(id1)
		assert.NoError(t, err)

		_, err = uuid.Parse(id2)
		assert.NoError(t, err)
	})
}

func TestWorkflowConstants(t *testing.T) {
	t.Run("WorkflowStatus constants", func(t *testing.T) {
		assert.Equal(t, WorkflowStatus("active"), WorkflowStatusActive)
		assert.Equal(t, WorkflowStatus("inactive"), WorkflowStatusInactive)
		assert.Equal(t, WorkflowStatus("draft"), WorkflowStatusDraft)
		assert.Equal(t, WorkflowStatus("archived"), WorkflowStatusArchived)
	})

	t.Run("ExecutionStatus constants", func(t *testing.T) {
		assert.Equal(t, ExecutionStatus("pending"), ExecutionStatusPending)
		assert.Equal(t, ExecutionStatus("running"), ExecutionStatusRunning)
		assert.Equal(t, ExecutionStatus("completed"), ExecutionStatusCompleted)
		assert.Equal(t, ExecutionStatus("failed"), ExecutionStatusFailed)
	})

	t.Run("NodeType constants", func(t *testing.T) {
		assert.Equal(t, NodeType("trigger"), NodeTypeTrigger)
		assert.Equal(t, NodeType("action"), NodeTypeAction)
		assert.Equal(t, NodeType("condition"), NodeTypeCondition)
		assert.Equal(t, NodeType("http"), NodeTypeHTTP)
	})
}

func TestWorkflowJSONSerialization(t *testing.T) {
	t.Run("Workflow JSON marshaling/unmarshaling", func(t *testing.T) {
		teamID := uuid.New().String()
		userID := uuid.New().String()
		original := NewWorkflow("Test", teamID, userID)
		
		// Add a node to make it more realistic
		node := NewNode("Start", NodeTypeTrigger)
		original.AddNode(*node)

		// Marshal to JSON
		jsonData, err := json.Marshal(original)
		require.NoError(t, err)

		// Unmarshal from JSON
		var unmarshaled Workflow
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		// Verify core fields
		assert.Equal(t, original.ID, unmarshaled.ID)
		assert.Equal(t, original.Name, unmarshaled.Name)
		assert.Equal(t, original.TeamID, unmarshaled.TeamID)
		assert.Equal(t, original.Status, unmarshaled.Status)
	})
}

// Helper function to assert errors
func assertError(t *testing.T, err error, expectedType errors.ErrorType, expectedCode errors.ErrorCode) {
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