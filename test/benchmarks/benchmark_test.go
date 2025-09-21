package benchmarks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/internal/execution/dag"
	nodes_http "n8n-pro/internal/nodes/http"
	"n8n-pro/internal/storage/cache"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Benchmark configuration
const (
	smallDataSize  = 100
	mediumDataSize = 1000
	largeDataSize  = 10000
)

// Test data generators
func generateWorkflowData(size int) map[string]interface{} {
	nodes := make([]map[string]interface{}, size)
	edges := make([]map[string]interface{}, 0)

	for i := 0; i < size; i++ {
		nodes[i] = map[string]interface{}{
			"id":   fmt.Sprintf("node-%d", i),
			"type": "n8n-nodes-base.set",
			"name": fmt.Sprintf("Node %d", i),
			"parameters": map[string]interface{}{
				"values": map[string]interface{}{
					"string": []map[string]interface{}{
						{
							"name":  "data",
							"value": fmt.Sprintf("test-data-%d", i),
						},
					},
				},
			},
			"position": map[string]float64{
				"x": float64(100 * (i % 10)),
				"y": float64(100 * (i / 10)),
			},
		}

		if i > 0 {
			edges = append(edges, map[string]interface{}{
				"source": fmt.Sprintf("node-%d", i-1),
				"target": fmt.Sprintf("node-%d", i),
			})
		}
	}

	return map[string]interface{}{
		"name":  fmt.Sprintf("Benchmark Workflow %d nodes", size),
		"nodes": nodes,
		"edges": edges,
		"settings": map[string]interface{}{
			"timeout": 300,
		},
	}
}

func generateExecutionData(size int) map[string]interface{} {
	data := make([]map[string]interface{}, size)
	for i := 0; i < size; i++ {
		data[i] = map[string]interface{}{
			"id":    fmt.Sprintf("item-%d", i),
			"value": fmt.Sprintf("value-%d", i),
			"index": i,
		}
	}

	return map[string]interface{}{
		"items": data,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"size":      size,
		},
	}
}

// HTTP API Benchmarks

func BenchmarkHealthEndpoint(b *testing.B) {
	baseURL := "http://localhost:3000" // Default test URL
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(baseURL + "/health")
		if err != nil {
			b.Skip("Health endpoint not available")
		}
		resp.Body.Close()
	}
}

func BenchmarkHealthEndpointParallel(b *testing.B) {
	baseURL := "http://localhost:3000"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := http.Get(baseURL + "/health")
			if err != nil {
				b.Skip("Health endpoint not available")
			}
			resp.Body.Close()
		}
	})
}

func BenchmarkWorkflowCreation(b *testing.B) {
	baseURL := "http://localhost:3000"
	workflowData := generateWorkflowData(smallDataSize)
	jsonData, _ := json.Marshal(workflowData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(
			baseURL+"/api/v1/workflows",
			"application/json",
			bytes.NewBuffer(jsonData),
		)
		if err != nil {
			b.Skip("API endpoint not available")
		}
		resp.Body.Close()
	}
}

func BenchmarkWorkflowCreationSizes(b *testing.B) {
	baseURL := "http://localhost:3000"
	sizes := []int{10, 50, 100, 500, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size%d", size), func(b *testing.B) {
			workflowData := generateWorkflowData(size)
			jsonData, _ := json.Marshal(workflowData)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := http.Post(
					baseURL+"/api/v1/workflows",
					"application/json",
					bytes.NewBuffer(jsonData),
				)
				if err != nil {
					b.Skip("API endpoint not available")
				}
				resp.Body.Close()
			}
		})
	}
}

// DAG Execution Benchmarks

func BenchmarkDAGExecution(b *testing.B) {
	log := logger.New("benchmark")
	executionMode := dag.ExecutionModeSequential

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := dag.NewDAG("workflow-123", "execution-123", executionMode, log)

		// Add simple nodes
		for j := 0; j < 10; j++ {
			node := &dag.Node{
				ID:   fmt.Sprintf("node-%d", j),
				Type: "test",
				Name: fmt.Sprintf("Test Node %d", j),
			}
			d.AddNode(node)

			if j > 0 {
				edge := &dag.Edge{
					SourceID: fmt.Sprintf("node-%d", j-1),
					TargetID: fmt.Sprintf("node-%d", j),
					Type:     dag.EdgeTypeMain,
				}
				d.AddEdge(edge)
			}
		}

		ctx := &dag.ExecutionContext{
			WorkflowID:  "workflow-123",
			ExecutionID: "execution-123",
			UserID:      "user-123",
			Executors:   make(map[string]dag.NodeExecutor),
		}

		// Add mock executor
		ctx.Executors["test"] = &mockNodeExecutor{}

		d.Execute(ctx)
	}
}

func BenchmarkDAGExecutionParallel(b *testing.B) {
	log := logger.New("benchmark")
	executionMode := dag.ExecutionModeParallel

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := dag.NewDAG("workflow-123", "execution-123", executionMode, log)

		// Add parallel nodes
		startNode := &dag.Node{
			ID:   "start",
			Type: "test",
			Name: "Start Node",
		}
		d.AddNode(startNode)

		for j := 0; j < 5; j++ {
			node := &dag.Node{
				ID:   fmt.Sprintf("parallel-%d", j),
				Type: "test",
				Name: fmt.Sprintf("Parallel Node %d", j),
			}
			d.AddNode(node)

			edge := &dag.Edge{
				SourceID: "start",
				TargetID: fmt.Sprintf("parallel-%d", j),
				Type:     dag.EdgeTypeMain,
			}
			d.AddEdge(edge)
		}

		ctx := &dag.ExecutionContext{
			WorkflowID:  "workflow-123",
			ExecutionID: "execution-123",
			UserID:      "user-123",
			Executors:   make(map[string]dag.NodeExecutor),
		}

		ctx.Executors["test"] = &mockNodeExecutor{}
		d.Execute(ctx)
	}
}

// Node Execution Benchmarks

func BenchmarkHTTPNodeExecution(b *testing.B) {
	log := logger.New("benchmark")
	nodesHttpNode := nodes_http.New(log)

	// Mock HTTP server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "success", "timestamp": "2023-01-01T00:00:00Z"}`))
	}))
	defer mockServer.Close()

	parameters := map[string]interface{}{
		"url":    mockServer.URL,
		"method": "GET",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := nodesHttpNode.Execute(context.Background(), parameters, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPNodeExecutionParallel(b *testing.B) {
	log := logger.New("benchmark")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "success"}`))
	}))
	defer mockServer.Close()

	parameters := map[string]interface{}{
		"url":    mockServer.URL,
		"method": "GET",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		nodesHttpNode := nodes_http.New(log)
		for pb.Next() {
			_, err := nodesHttpNode.Execute(context.Background(), parameters, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Cache Benchmarks

func BenchmarkMemoryCacheSet(b *testing.B) {
	config := cache.DefaultConfig()
	log := logger.New("benchmark")
	memCache := cache.NewMemoryCache(config, log)

	data := []byte("benchmark test data for cache operations")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i)
		memCache.Set(ctx, key, data, time.Hour)
	}
}

func BenchmarkMemoryCacheGet(b *testing.B) {
	config := cache.DefaultConfig()
	log := logger.New("benchmark")
	memCache := cache.NewMemoryCache(config, log)

	data := []byte("benchmark test data for cache operations")
	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key-%d", i)
		memCache.Set(ctx, key, data, time.Hour)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		_, err := memCache.Get(ctx, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemoryCacheSetParallel(b *testing.B) {
	config := cache.DefaultConfig()
	log := logger.New("benchmark")
	memCache := cache.NewMemoryCache(config, log)

	data := []byte("benchmark test data")
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d-%d", runtime.NumGoroutine(), i)
			memCache.Set(ctx, key, data, time.Hour)
			i++
		}
	})
}

func BenchmarkMemoryCacheGetParallel(b *testing.B) {
	config := cache.DefaultConfig()
	log := logger.New("benchmark")
	memCache := cache.NewMemoryCache(config, log)

	data := []byte("benchmark test data")
	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("key-%d", i)
		memCache.Set(ctx, key, data, time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%10000)
			memCache.Get(ctx, key)
			i++
		}
	})
}

// JSON Processing Benchmarks

func BenchmarkJSONMarshaling(b *testing.B) {
	data := generateWorkflowData(mediumDataSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONUnmarshaling(b *testing.B) {
	data := generateWorkflowData(mediumDataSize)
	jsonData, _ := json.Marshal(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result map[string]interface{}
		err := json.Unmarshal(jsonData, &result)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Concurrent Operations Benchmarks

func BenchmarkConcurrentWorkflowOperations(b *testing.B) {
	baseURL := "http://localhost:3000"
	workflowData := generateWorkflowData(smallDataSize)
	jsonData, _ := json.Marshal(workflowData)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create workflow
			resp, err := http.Post(
				baseURL+"/api/v1/workflows",
				"application/json",
				bytes.NewBuffer(jsonData),
			)
			if err != nil {
				b.Skip("API endpoint not available")
			}
			resp.Body.Close()
		}
	})
}

// Memory and GC Benchmarks

func BenchmarkMemoryAllocation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate workflow data allocation
		data := make([]map[string]interface{}, 1000)
		for j := 0; j < 1000; j++ {
			data[j] = map[string]interface{}{
				"id":         fmt.Sprintf("node-%d", j),
				"type":       "test",
				"parameters": make(map[string]interface{}),
			}
		}
		_ = data
	}
}

func BenchmarkMemoryAllocationWithPool(b *testing.B) {
	pool := sync.Pool{
		New: func() interface{} {
			return make([]map[string]interface{}, 0, 1000)
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := pool.Get().([]map[string]interface{})
		data = data[:0] // Reset slice

		for j := 0; j < 1000; j++ {
			data = append(data, map[string]interface{}{
				"id":         fmt.Sprintf("node-%d", j),
				"type":       "test",
				"parameters": make(map[string]interface{}),
			})
		}

		pool.Put(data)
	}
}

// Helper functions and mocks

func createBenchmarkServer() *httptest.Server {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	r.Post("/api/v1/workflows", func(w http.ResponseWriter, r *http.Request) {
		var workflowData map[string]interface{}
		json.NewDecoder(r.Body).Decode(&workflowData)

		response := map[string]interface{}{
			"id":         fmt.Sprintf("workflow-%d", time.Now().UnixNano()),
			"name":       workflowData["name"],
			"created_at": time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(r)
}

type mockNodeExecutor struct{}

func (m *mockNodeExecutor) Execute(ctx context.Context, node *dag.Node, inputData map[string]interface{}) (map[string]interface{}, error) {
	// Simulate some work
	time.Sleep(1 * time.Millisecond)
	return map[string]interface{}{
		"success": true,
		"data":    fmt.Sprintf("processed-%s", node.ID),
	}, nil
}

func (m *mockNodeExecutor) Validate(node *dag.Node) error {
	return nil
}

func (m *mockNodeExecutor) GetType() string {
	return "mock"
}

// Benchmark suite runner
func BenchmarkSuite(b *testing.B) {
	// Initialize metrics for benchmarking
	config := &config.Config{
		Metrics: &config.MetricsConfig{
			Enabled: false, // Disable metrics during benchmarking
		},
	}
	metrics.Initialize(config.Metrics)

	// Create a single HTTP test server for all API benchmarks
	server := createBenchmarkServer()
	defer server.Close()

	// Run sub-benchmarks
	b.Run("API", func(b *testing.B) {
		b.Run("Health", BenchmarkHealthEndpoint)
		b.Run("HealthParallel", BenchmarkHealthEndpointParallel)
		b.Run("WorkflowCreation", BenchmarkWorkflowCreation)
		b.Run("WorkflowCreationSizes", BenchmarkWorkflowCreationSizes)
	})

	b.Run("DAG", func(b *testing.B) {
		b.Run("Sequential", BenchmarkDAGExecution)
		b.Run("Parallel", BenchmarkDAGExecutionParallel)
	})

	b.Run("Cache", func(b *testing.B) {
		b.Run("Set", BenchmarkMemoryCacheSet)
		b.Run("Get", BenchmarkMemoryCacheGet)
		b.Run("SetParallel", BenchmarkMemoryCacheSetParallel)
		b.Run("GetParallel", BenchmarkMemoryCacheGetParallel)
	})

	b.Run("JSON", func(b *testing.B) {
		b.Run("Marshal", BenchmarkJSONMarshaling)
		b.Run("Unmarshal", BenchmarkJSONUnmarshaling)
	})

	b.Run("Memory", func(b *testing.B) {
		b.Run("Allocation", BenchmarkMemoryAllocation)
		b.Run("AllocationWithPool", BenchmarkMemoryAllocationWithPool)
	})
}
