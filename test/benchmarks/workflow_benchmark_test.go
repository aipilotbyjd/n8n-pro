package benchmarks

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"n8n-pro/internal/testutils"
	"n8n-pro/internal/workflows"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// BenchmarkWorkflowCreationLogic benchmarks workflow creation performance
func BenchmarkWorkflowCreationLogic(b *testing.B) {
	testUser := testutils.CreateTestUser()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		workflow := workflows.NewWorkflow(
			fmt.Sprintf("Benchmark Workflow %d", i),
			testUser.TeamID,
			testUser.ID,
		)
		
		// Add some nodes to make it more realistic
		for j := 0; j < 5; j++ {
			node := workflows.NewNode(
				fmt.Sprintf("Node %d", j),
				workflows.NodeTypeHTTP,
			)
			workflow.AddNode(*node)
		}
		
		// Validate workflow
		_ = workflow.IsValid()
	}
}

// BenchmarkWorkflowValidation benchmarks workflow validation
func BenchmarkWorkflowValidation(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = workflow.IsValid()
	}
}

// BenchmarkWorkflowSerialization benchmarks JSON serialization
func BenchmarkWorkflowSerialization(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
	
	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_, err := workflow.MarshalJSON()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Unmarshal", func(b *testing.B) {
		data, _ := workflow.MarshalJSON()
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			var w workflows.Workflow
			err := w.UnmarshalJSON(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkNodeOperations benchmarks node operations
func BenchmarkNodeOperations(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := workflows.NewWorkflow("Test", testUser.TeamID, testUser.ID)
	
	b.Run("AddNode", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
			workflow.AddNode(*node)
		}
	})
	
	b.Run("GetNodeByID", func(b *testing.B) {
		// Pre-populate with nodes
		nodeIDs := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
			workflow.AddNode(*node)
			nodeIDs[i] = node.ID
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			nodeID := nodeIDs[i%len(nodeIDs)]
			_ = workflow.GetNodeByID(nodeID)
		}
	})
}

// BenchmarkConnectionOperations benchmarks connection operations
func BenchmarkConnectionOperations(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := workflows.NewWorkflow("Test", testUser.TeamID, testUser.ID)
	
	// Pre-populate with nodes
	nodeIDs := make([]string, 100)
	for i := 0; i < 100; i++ {
		node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
		workflow.AddNode(*node)
		nodeIDs[i] = node.ID
	}
	
	b.Run("AddConnection", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			sourceIdx := i % (len(nodeIDs) - 1)
			targetIdx := (i + 1) % len(nodeIDs)
			
			connection := workflows.NewConnection(nodeIDs[sourceIdx], nodeIDs[targetIdx])
			workflow.AddConnection(*connection)
		}
	})
	
	b.Run("GetConnectionsBySourceNode", func(b *testing.B) {
		// Pre-populate with connections
		for i := 0; i < len(nodeIDs)-1; i++ {
			connection := workflows.NewConnection(nodeIDs[i], nodeIDs[i+1])
			workflow.AddConnection(*connection)
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			nodeID := nodeIDs[i%len(nodeIDs)]
			_ = workflow.GetConnectionsBySourceNode(nodeID)
		}
	})
}

// BenchmarkWorkflowExecution benchmarks workflow execution creation
func BenchmarkWorkflowExecution(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflowID := uuid.New().String()
	
	b.Run("NewExecution", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			triggerData := map[string]interface{}{
				"timestamp": time.Now(),
				"data":      fmt.Sprintf("test data %d", i),
			}
			
			_ = workflows.NewWorkflowExecution(
				workflowID,
				"Test Workflow",
				testUser.TeamID,
				triggerData,
			)
		}
	})
	
	b.Run("ExecutionStatusOperations", func(b *testing.B) {
		execution := workflows.NewWorkflowExecution(workflowID, "Test", testUser.TeamID, nil)
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			execution.IsRunning()
			execution.IsCompleted()
			execution.GetDuration()
		}
	})
}

// BenchmarkConcurrentWorkflowOperations benchmarks concurrent operations
func BenchmarkConcurrentWorkflowLogic(b *testing.B) {
	testUser := testutils.CreateTestUser()
	
	b.Run("ConcurrentCreation", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				workflow := workflows.NewWorkflow(
					fmt.Sprintf("Concurrent Workflow %d", i),
					testUser.TeamID,
					testUser.ID,
				)
				_ = workflow.IsValid()
				i++
			}
		})
	})
	
	b.Run("ConcurrentNodeOperations", func(b *testing.B) {
		workflow := workflows.NewWorkflow("Concurrent Test", testUser.TeamID, testUser.ID)
		mu := &sync.RWMutex{}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
				
				mu.Lock()
				workflow.AddNode(*node)
				mu.Unlock()
				
				mu.RLock()
				_ = workflow.GetNodeByID(node.ID)
				mu.RUnlock()
				
				i++
			}
		})
	})
}

// BenchmarkWorkflowCloning benchmarks workflow cloning operations
func BenchmarkWorkflowCloning(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = workflow.Clone()
	}
}

// BenchmarkVariableOperations benchmarks variable operations
func BenchmarkVariableOperations(b *testing.B) {
	testUser := testutils.CreateTestUser()
	workflow := workflows.NewWorkflow("Test", testUser.TeamID, testUser.ID)
	
	b.Run("AddVariable", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			variable := workflows.NewVariable(
				fmt.Sprintf("var_%d", i),
				fmt.Sprintf("value_%d", i),
				"string",
			)
			workflow.Variables = append(workflow.Variables, *variable)
		}
	})
	
	b.Run("GetVariableByKey", func(b *testing.B) {
		// Pre-populate with variables
		for i := 0; i < 1000; i++ {
			variable := workflows.NewVariable(
				fmt.Sprintf("var_%d", i),
				fmt.Sprintf("value_%d", i),
				"string",
			)
			workflow.Variables = append(workflow.Variables, *variable)
		}
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("var_%d", i%1000)
			_ = workflow.GetVariableByKey(key)
		}
	})
}

// BenchmarkLargeWorkflowOperations benchmarks operations on large workflows
func BenchmarkLargeWorkflowOperations(b *testing.B) {
	testUser := testutils.CreateTestUser()
	
	// Create a large workflow with many nodes and connections
	createLargeWorkflow := func(nodeCount int) *workflows.Workflow {
		workflow := workflows.NewWorkflow("Large Workflow", testUser.TeamID, testUser.ID)
		
		nodeIDs := make([]string, nodeCount)
		for i := 0; i < nodeCount; i++ {
			node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
			workflow.AddNode(*node)
			nodeIDs[i] = node.ID
		}
		
		// Create connections (each node connects to the next)
		for i := 0; i < nodeCount-1; i++ {
			connection := workflows.NewConnection(nodeIDs[i], nodeIDs[i+1])
			workflow.AddConnection(*connection)
		}
		
		return workflow
	}
	
	b.Run("SmallWorkflow100Nodes", func(b *testing.B) {
		workflow := createLargeWorkflow(100)
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = workflow.IsValid()
		}
	})
	
	b.Run("MediumWorkflow500Nodes", func(b *testing.B) {
		workflow := createLargeWorkflow(500)
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = workflow.IsValid()
		}
	})
	
	b.Run("LargeWorkflow1000Nodes", func(b *testing.B) {
		workflow := createLargeWorkflow(1000)
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			_ = workflow.IsValid()
		}
	})
}

// Performance test to measure actual performance characteristics
func TestWorkflowPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	testUser := testutils.CreateTestUser()
	
	t.Run("WorkflowCreationPerformance", func(t *testing.T) {
		start := time.Now()
		
		for i := 0; i < 10000; i++ {
			workflow := workflows.NewWorkflow(
				fmt.Sprintf("Perf Test %d", i),
				testUser.TeamID,
				testUser.ID,
			)
			
			// Add nodes
			for j := 0; j < 10; j++ {
				node := workflows.NewNode(fmt.Sprintf("Node %d", j), workflows.NodeTypeHTTP)
				workflow.AddNode(*node)
			}
			
			_ = workflow.IsValid()
		}
		
		duration := time.Since(start)
		t.Logf("Created 10,000 workflows with 10 nodes each in %v", duration)
		t.Logf("Average time per workflow: %v", duration/10000)
		
		// Performance assertion - should complete within reasonable time
		assert.Less(t, duration, 5*time.Second, "Workflow creation should be fast")
	})
	
	t.Run("WorkflowValidationPerformance", func(t *testing.T) {
		// Create a complex workflow once
		workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
		
		start := time.Now()
		
		for i := 0; i < 100000; i++ {
			_ = workflow.IsValid()
		}
		
		duration := time.Since(start)
		t.Logf("Validated workflow 100,000 times in %v", duration)
		t.Logf("Average validation time: %v", duration/100000)
		
		// Validation should be very fast
		assert.Less(t, duration, 1*time.Second, "Workflow validation should be very fast")
	})
}

// Memory usage test
func TestWorkflowMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory tests in short mode")
	}
	
	testUser := testutils.CreateTestUser()
	
	t.Run("WorkflowMemoryFootprint", func(t *testing.T) {
		// Create workflows of different sizes and measure memory impact
		workflows := make([]*workflows.Workflow, 0, 1000)
		
		for i := 0; i < 1000; i++ {
			workflow := testutils.CreateComplexTestWorkflow(testUser.TeamID, testUser.ID)
			workflows = append(workflows, workflow)
		}
		
		// Keep workflows in memory to prevent GC
		assert.Len(t, workflows, 1000)
		t.Logf("Created %d complex workflows in memory", len(workflows))
	})
}

// Concurrency stress test
func TestConcurrentWorkflowOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency tests in short mode")
	}
	
	testUser := testutils.CreateTestUser()
	workflow := workflows.NewWorkflow("Concurrent Test", testUser.TeamID, testUser.ID)
	
	t.Run("ConcurrentNodeAccess", func(t *testing.T) {
		// Pre-populate with nodes
		nodeIDs := make([]string, 100)
		for i := 0; i < 100; i++ {
			node := workflows.NewNode(fmt.Sprintf("Node %d", i), workflows.NodeTypeHTTP)
			workflow.AddNode(*node)
			nodeIDs[i] = node.ID
		}
		
		// Concurrent read access
		done := make(chan bool, 10)
		for worker := 0; worker < 10; worker++ {
			go func() {
				for i := 0; i < 1000; i++ {
					nodeID := nodeIDs[i%len(nodeIDs)]
					node := workflow.GetNodeByID(nodeID)
					assert.NotNil(t, node)
				}
				done <- true
			}()
		}
		
		// Wait for all workers to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// Edge case performance tests
func TestEdgeCasePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping edge case tests in short mode")
	}
	
	testUser := testutils.CreateTestUser()
	
	t.Run("EmptyWorkflowOperations", func(t *testing.T) {
		workflow := workflows.NewWorkflow("Empty", testUser.TeamID, testUser.ID)
		
		start := time.Now()
		for i := 0; i < 100000; i++ {
			_ = workflow.GetNodeByID("nonexistent")
			_ = workflow.GetConnectionsBySourceNode("nonexistent")
			_ = workflow.GetVariableByKey("nonexistent")
		}
		duration := time.Since(start)
		
		t.Logf("Empty workflow operations took %v", duration)
		assert.Less(t, duration, 1*time.Second)
	})
	
	t.Run("SingleNodeWorkflow", func(t *testing.T) {
		workflow := workflows.NewWorkflow("Single", testUser.TeamID, testUser.ID)
		node := workflows.NewNode("Only Node", workflows.NodeTypeHTTP)
		workflow.AddNode(*node)
		
		start := time.Now()
		for i := 0; i < 100000; i++ {
			_ = workflow.IsValid()
		}
		duration := time.Since(start)
		
		t.Logf("Single node workflow validation took %v", duration)
		assert.Less(t, duration, 500*time.Millisecond)
	})
}