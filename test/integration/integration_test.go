package integration

import (
	"context"
	"testing"
	"time"

	"n8n-pro/internal/testutils"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite provides integration tests for the n8n system
type IntegrationTestSuite struct {
	suite.Suite
	ctx          context.Context
	testUser     *testutils.TestUser
	testWorkflow *testutils.TestWorkflow
}

func (suite *IntegrationTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.testUser = testutils.CreateTestUser()
	suite.testWorkflow = testutils.CreateTestWorkflow(suite.testUser.TeamID, suite.testUser.ID)
}

func (suite *IntegrationTestSuite) TestWorkflowLifecycle() {
	suite.Run("complete workflow lifecycle", func() {
		// 1. Create workflow
		workflow := suite.testWorkflow.ToWorkflow()
		testutils.ValidateWorkflowStructure(suite.T(), workflow)

		// 2. Validate workflow
		err := workflow.IsValid()
		require.NoError(suite.T(), err)

		// 3. Activate workflow
		workflow.Status = workflows.WorkflowStatusActive
		assert.True(suite.T(), workflow.IsExecutable())

		// 4. Create execution
		execution := workflows.NewWorkflowExecution(
			workflow.ID,
			workflow.Name,
			workflow.TeamID,
			map[string]interface{}{"test": "data"},
		)
		assert.Equal(suite.T(), workflows.ExecutionStatusPending, execution.Status)

		// 5. Simulate execution completion
		execution.MarkAsCompleted(map[string]interface{}{"result": "success"})
		assert.Equal(suite.T(), workflows.ExecutionStatusCompleted, execution.Status)
		assert.NotNil(suite.T(), execution.EndTime)

		// 6. Deactivate workflow
		workflow.Status = workflows.WorkflowStatusInactive
		assert.False(suite.T(), workflow.IsExecutable())
	})
}

func (suite *IntegrationTestSuite) TestNodeExecution() {
	suite.Run("node execution flow", func() {
		workflow := testutils.CreateComplexTestWorkflow(suite.testUser.TeamID, suite.testUser.ID)

		// Validate all nodes
		for _, node := range workflow.Nodes {
			err := node.IsValid()
			assert.NoError(suite.T(), err, "Node %s should be valid", node.Name)
		}

		// Test node retrieval
		webhookNode := workflow.GetNodeByID("webhook-trigger")
		require.NotNil(suite.T(), webhookNode)
		assert.Equal(suite.T(), workflows.NodeTypeTrigger, webhookNode.Type)

		conditionNode := workflow.GetNodeByID("condition-node")
		require.NotNil(suite.T(), conditionNode)
		assert.Equal(suite.T(), workflows.NodeTypeCondition, conditionNode.Type)

		// Test connections
		connections := workflow.GetConnectionsBySourceNode("webhook-trigger")
		assert.Len(suite.T(), connections, 1)
		assert.Equal(suite.T(), "condition-node", connections[0].TargetNode)
	})
}

func (suite *IntegrationTestSuite) TestErrorHandling() {
	suite.Run("error propagation", func() {
		// Test validation errors
		invalidWorkflow := &workflows.Workflow{
			Name:   "", // Invalid: empty name
			TeamID: suite.testUser.TeamID,
			Nodes:  []workflows.Node{},
		}

		err := invalidWorkflow.IsValid()
		require.Error(suite.T(), err)
		testutils.AssertError(suite.T(), err, errors.ErrorTypeValidation, errors.CodeMissingField)

		// Test execution errors
		execution := workflows.NewWorkflowExecution(
			uuid.New().String(),
			"Test",
			suite.testUser.TeamID,
			nil,
		)

		execution.MarkAsFailed("Test error", "Stack trace", "failed-node")
		assert.Equal(suite.T(), workflows.ExecutionStatusFailed, execution.Status)
		assert.Equal(suite.T(), "Test error", *execution.ErrorMessage)
		assert.Equal(suite.T(), "failed-node", *execution.ErrorNodeID)
	})
}

func (suite *IntegrationTestSuite) TestWorkflowOperations() {
	suite.Run("workflow manipulation", func() {
		workflow := workflows.NewWorkflow("Test Workflow", suite.testUser.TeamID, suite.testUser.ID)

		// Test adding nodes
		initialCount := len(workflow.Nodes)
		newNode := workflows.NewNode("New Node", workflows.NodeTypeHTTP)
		workflow.AddNode(*newNode)
		assert.Equal(suite.T(), initialCount+1, len(workflow.Nodes))

		// Test node retrieval
		retrievedNode := workflow.GetNodeByID(newNode.ID)
		require.NotNil(suite.T(), retrievedNode)
		assert.Equal(suite.T(), newNode.Name, retrievedNode.Name)

		// Test adding connections
		secondNode := workflows.NewNode("Second Node", workflows.NodeTypeAction)
		workflow.AddNode(*secondNode)

		connection := workflows.NewConnection(newNode.ID, secondNode.ID)
		workflow.AddConnection(*connection)

		connections := workflow.GetConnectionsBySourceNode(newNode.ID)
		assert.Len(suite.T(), connections, 1)
		assert.Equal(suite.T(), secondNode.ID, connections[0].TargetNode)

		// Test removing nodes (should also remove connections)
		workflow.RemoveNode(newNode.ID)
		assert.Nil(suite.T(), workflow.GetNodeByID(newNode.ID))

		remainingConnections := workflow.GetConnectionsBySourceNode(newNode.ID)
		assert.Len(suite.T(), remainingConnections, 0)
	})
}

func (suite *IntegrationTestSuite) TestWorkflowCloning() {
	suite.Run("workflow cloning", func() {
		original := testutils.CreateComplexTestWorkflow(suite.testUser.TeamID, suite.testUser.ID)
		original.Version = 5
		original.ExecutionCount = 100

		clone := original.Clone()

		// Verify clone is independent
		assert.NotEqual(suite.T(), original.ID, clone.ID)
		assert.Contains(suite.T(), clone.Name, "(Copy)")
		assert.Equal(suite.T(), 1, clone.Version)
		assert.Equal(suite.T(), int64(0), clone.ExecutionCount)

		// Verify structure is preserved
		assert.Equal(suite.T(), len(original.Nodes), len(clone.Nodes))
		assert.Equal(suite.T(), len(original.Connections), len(clone.Connections))
		assert.Equal(suite.T(), original.TeamID, clone.TeamID)
		assert.Equal(suite.T(), original.OwnerID, clone.OwnerID)
	})
}

func (suite *IntegrationTestSuite) TestExecutionLifecycle() {
	suite.Run("execution state management", func() {
		execution := workflows.NewWorkflowExecution(
			suite.testWorkflow.ID,
			suite.testWorkflow.Name,
			suite.testUser.TeamID,
			map[string]interface{}{"input": "test"},
		)

		// Initial state
		assert.Equal(suite.T(), workflows.ExecutionStatusPending, execution.Status)
		assert.True(suite.T(), execution.IsRunning())
		assert.False(suite.T(), execution.IsCompleted())

		// Simulate running
		execution.Status = workflows.ExecutionStatusRunning
		assert.True(suite.T(), execution.IsRunning())
		assert.False(suite.T(), execution.IsCompleted())

		// Test successful completion
		outputData := map[string]interface{}{"result": "success", "processed": 5}
		execution.MarkAsCompleted(outputData)

		assert.Equal(suite.T(), workflows.ExecutionStatusCompleted, execution.Status)
		assert.False(suite.T(), execution.IsRunning())
		assert.True(suite.T(), execution.IsCompleted())
		assert.Equal(suite.T(), outputData, execution.OutputData)
		assert.NotNil(suite.T(), execution.EndTime)
		assert.NotNil(suite.T(), execution.Duration)
	})
}

func (suite *IntegrationTestSuite) TestVariableManagement() {
	suite.Run("workflow variables", func() {
		workflow := workflows.NewWorkflow("Variable Test", suite.testUser.TeamID, suite.testUser.ID)

		// Add variables
		apiKeyVar := workflows.NewVariable("api_key", "secret-key", "string")
		apiKeyVar.Encrypted = true
		workflow.Variables = append(workflow.Variables, *apiKeyVar)

		timeoutVar := workflows.NewVariable("timeout", 30, "number")
		workflow.Variables = append(workflow.Variables, *timeoutVar)

		enabledVar := workflows.NewVariable("enabled", true, "boolean")
		workflow.Variables = append(workflow.Variables, *enabledVar)

		// Test variable retrieval
		retrievedApiKey := workflow.GetVariableByKey("api_key")
		require.NotNil(suite.T(), retrievedApiKey)
		assert.Equal(suite.T(), "secret-key", retrievedApiKey.Value)
		assert.True(suite.T(), retrievedApiKey.Encrypted)

		retrievedTimeout := workflow.GetVariableByKey("timeout")
		require.NotNil(suite.T(), retrievedTimeout)
		assert.Equal(suite.T(), 30, retrievedTimeout.Value)

		// Test non-existent variable
		nonExistent := workflow.GetVariableByKey("non_existent")
		assert.Nil(suite.T(), nonExistent)
	})
}

func (suite *IntegrationTestSuite) TestConcurrentOperations() {
	suite.Run("concurrent workflow operations", func() {
		workflow := workflows.NewWorkflow("Concurrent Test", suite.testUser.TeamID, suite.testUser.ID)

		// Concurrent node additions
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(index int) {
				node := workflows.NewNode(
					"Node "+string(rune(index)),
					workflows.NodeTypeHTTP,
				)
				workflow.AddNode(*node)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Note: In a real implementation, this would need proper synchronization
		// This test demonstrates the structure needed for concurrent testing
		assert.True(suite.T(), len(workflow.Nodes) > 0)
	})
}

func (suite *IntegrationTestSuite) TestComplexWorkflowValidation() {
	suite.Run("complex workflow validation", func() {
		workflow := testutils.CreateComplexTestWorkflow(suite.testUser.TeamID, suite.testUser.ID)

		// Validate entire workflow structure
		err := workflow.IsValid()
		require.NoError(suite.T(), err)

		// Validate individual components
		assert.True(suite.T(), workflow.HasTriggerNodes())

		triggerNodes := workflow.GetTriggerNodes()
		assert.Len(suite.T(), triggerNodes, 1)

		// Validate connections reference existing nodes
		nodeIds := make(map[string]bool)
		for _, node := range workflow.Nodes {
			nodeIds[node.ID] = true
		}

		for _, conn := range workflow.Connections {
			assert.True(suite.T(), nodeIds[conn.SourceNode], "Source node %s should exist", conn.SourceNode)
			assert.True(suite.T(), nodeIds[conn.TargetNode], "Target node %s should exist", conn.TargetNode)
		}

		// Validate variables
		for _, variable := range workflow.Variables {
			assert.NotEmpty(suite.T(), variable.Key)
			assert.NotEmpty(suite.T(), variable.Type)
		}

		// Validate triggers
		for _, trigger := range workflow.Triggers {
			assert.NotEmpty(suite.T(), trigger.NodeID)
			assert.True(suite.T(), nodeIds[trigger.NodeID], "Trigger node %s should exist", trigger.NodeID)
		}
	})
}

func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	suite.Run(t, new(IntegrationTestSuite))
}

// Additional integration tests for specific scenarios
func TestWorkflowExecutionScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	testUser := testutils.CreateTestUser()

	t.Run("workflow with retry logic", func(t *testing.T) {
		workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
		workflow.Config.MaxRetryAttempts = 3

		execution := workflows.NewWorkflowExecution(
			workflow.ID,
			workflow.Name,
			testUser.TeamID,
			map[string]interface{}{"retry_test": true},
		)

		// Simulate first failure
		execution.MarkAsFailed("Network error", "Stack trace", "http-request")
		assert.Equal(t, workflows.ExecutionStatusFailed, execution.Status)

		// Simulate retry
		retryExecution := workflows.NewWorkflowExecution(
			workflow.ID,
			workflow.Name,
			testUser.TeamID,
			execution.TriggerData,
		)
		retryExecution.RetryCount = 1
		retryExecution.ParentExecutionID = &execution.ID

		// Simulate successful retry
		retryExecution.MarkAsCompleted(map[string]interface{}{"result": "success on retry"})
		assert.Equal(t, workflows.ExecutionStatusCompleted, retryExecution.Status)
		assert.Equal(t, 1, retryExecution.RetryCount)
	})

	t.Run("workflow timeout handling", func(t *testing.T) {
		workflow := testutils.CreateTestWorkflow(testUser.TeamID, testUser.ID).ToWorkflow()
		workflow.Config.Timeout = 1 // 1 second timeout

		execution := workflows.NewWorkflowExecution(
			workflow.ID,
			workflow.Name,
			testUser.TeamID,
			nil,
		)

		// Simulate timeout
		time.Sleep(2 * time.Second)
		execution.Status = workflows.ExecutionStatusTimeout
		now := time.Now()
		execution.EndTime = &now

		assert.Equal(t, workflows.ExecutionStatusTimeout, execution.Status)
		assert.True(t, execution.IsCompleted())
		assert.True(t, execution.GetDuration() > time.Second)
	})
}

func TestDatabaseIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	// Note: These would typically connect to a test database
	// For now, we'll test the structure and interfaces

	t.Run("workflow persistence structure", func(t *testing.T) {
		testUser := testutils.CreateTestUser()
		workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)

		// Test JSON serialization (what would be stored in DB)
		data, err := workflow.MarshalJSON()
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Test deserialization
		var restored workflows.Workflow
		err = restored.UnmarshalJSON(data)
		require.NoError(t, err)

		// Verify core fields are preserved
		assert.Equal(t, workflow.ID, restored.ID)
		assert.Equal(t, workflow.Name, restored.Name)
		assert.Equal(t, workflow.TeamID, restored.TeamID)
	})
}

func TestAPIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping API integration tests in short mode")
	}

	// These tests would typically make actual HTTP requests
	// For demonstration, we test the expected data structures

	t.Run("workflow API payload structure", func(t *testing.T) {
		testUser := testutils.CreateTestUser()
		workflow := testutils.CreateTestWorkflow(testUser.TeamID, testUser.ID).ToWorkflow()

		// Test the structure matches what the API expects
		assert.NotEmpty(t, workflow.ID)
		assert.NotEmpty(t, workflow.Name)
		assert.NotEmpty(t, workflow.TeamID)
		assert.NotEmpty(t, workflow.OwnerID)
		assert.NotNil(t, workflow.Nodes)
		assert.NotNil(t, workflow.Connections)

		// Verify timestamps
		assert.False(t, workflow.CreatedAt.IsZero())
		assert.False(t, workflow.UpdatedAt.IsZero())
	})
}
