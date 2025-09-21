package runner

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	t.Run("Execute logs workflow data", func(t *testing.T) {
		// Capture log output
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		testData := []byte(`{"workflow_id": "test-123", "name": "Test Workflow"}`)
		
		Execute(testData)
		
		output := buf.String()
		assert.Contains(t, output, "Executing workflow with data:")
		assert.Contains(t, output, string(testData))
		assert.Contains(t, output, "Workflow execution finished.")
	})

	t.Run("Execute handles empty data", func(t *testing.T) {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		Execute([]byte{})
		
		output := buf.String()
		assert.Contains(t, output, "Executing workflow with data:")
		assert.Contains(t, output, "Workflow execution finished.")
	})

	t.Run("Execute handles nil data", func(t *testing.T) {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		Execute(nil)
		
		output := buf.String()
		assert.Contains(t, output, "Executing workflow with data:")
		assert.Contains(t, output, "Workflow execution finished.")
	})

	t.Run("Execute handles large workflow data", func(t *testing.T) {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		// Create large JSON payload
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = 'a'
		}
		
		Execute(largeData)
		
		output := buf.String()
		assert.Contains(t, output, "Executing workflow with data:")
		assert.Contains(t, output, "Workflow execution finished.")
	})
}

func BenchmarkExecute(b *testing.B) {
	// Silence logs during benchmark
	log.SetOutput(os.NewFile(0, os.DevNull))
	defer log.SetOutput(os.Stderr)

	testData := []byte(`{"workflow_id": "bench-test", "nodes": [{"id": "1", "type": "trigger"}]}`)

	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		Execute(testData)
	}
}