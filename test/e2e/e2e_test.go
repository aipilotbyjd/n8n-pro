package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// E2ETestSuite represents the end-to-end test suite
type E2ETestSuite struct {
	suite.Suite
	server     *httptest.Server
	client     *http.Client
	config     *config.Config
	logger     logger.Logger
	baseURL    string
	authToken  string
	testUserID string
	testTeamID string
}

// SetupSuite sets up the test suite
func (suite *E2ETestSuite) SetupSuite() {
	// Initialize logger
	suite.logger = logger.New("e2e-test")

	// Load test configuration
	suite.config = &config.Config{
		API: &config.APIConfig{
			Host:        "localhost",
			Port:        0, // Use random port
			ReadTimeout: 30 * time.Second,
			EnableCORS:  true,
		},
		Database: &config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "n8n_test",
			Username: getEnvOrDefault("TEST_DB_USER", "postgres"),
			Password: getEnvOrDefault("TEST_DB_PASSWORD", "password"),
		},
		Metrics: &config.MetricsConfig{
			Enabled: false,
		},
	}

	// Initialize metrics
	metrics.Initialize(suite.config.Metrics)

	// Create test server
	suite.server = suite.createTestServer()
	suite.baseURL = suite.server.URL
	suite.client = suite.server.Client()

	// Set test identifiers
	suite.testUserID = "test-user-123"
	suite.testTeamID = "test-team-456"
	suite.authToken = "test-auth-token"

	suite.logger.Info("E2E test suite setup completed", "base_url", suite.baseURL)
}

// TearDownSuite tears down the test suite
func (suite *E2ETestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
	suite.logger.Info("E2E test suite teardown completed")
}

// createTestServer creates a test HTTP server
func (suite *E2ETestSuite) createTestServer() *httptest.Server {
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"api","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// Version endpoint
	r.Get("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"version":"test",
			"build_time":"unknown",
			"git_commit":"test",
			"go_version":"go1.23"
		}`
		w.Write([]byte(response))
	})

	// Mock authentication endpoint
	r.Post("/api/v1/auth/login", suite.handleLogin)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Add auth middleware for protected routes
		r.Use(suite.authMiddleware)

		// Workflows
		r.Route("/workflows", func(r chi.Router) {
			r.Get("/", suite.handleListWorkflows)
			r.Post("/", suite.handleCreateWorkflow)
			r.Get("/{id}", suite.handleGetWorkflow)
			r.Put("/{id}", suite.handleUpdateWorkflow)
			r.Delete("/{id}", suite.handleDeleteWorkflow)
			r.Post("/{id}/execute", suite.handleExecuteWorkflow)
		})

		// Executions
		r.Route("/executions", func(r chi.Router) {
			r.Get("/", suite.handleListExecutions)
			r.Get("/{id}", suite.handleGetExecution)
			r.Delete("/{id}/cancel", suite.handleCancelExecution)
		})
	})

	return httptest.NewServer(r)
}

// Test health endpoint
func (suite *E2ETestSuite) TestHealthEndpoint() {
	resp, err := suite.client.Get(suite.baseURL + "/health")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	assert.Equal(suite.T(), "application/json", resp.Header.Get("Content-Type"))

	var healthResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthResponse)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), "healthy", healthResponse["status"])
	assert.Equal(suite.T(), "api", healthResponse["service"])
	assert.NotEmpty(suite.T(), healthResponse["timestamp"])
}

// Test version endpoint
func (suite *E2ETestSuite) TestVersionEndpoint() {
	resp, err := suite.client.Get(suite.baseURL + "/version")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var versionResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&versionResponse)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), "test", versionResponse["version"])
	assert.Equal(suite.T(), "go1.23", versionResponse["go_version"])
}

// Test authentication flow
func (suite *E2ETestSuite) TestAuthenticationFlow() {
	// Test login
	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "testpassword",
	}

	jsonData, err := json.Marshal(loginData)
	require.NoError(suite.T(), err)

	resp, err := suite.client.Post(
		suite.baseURL+"/api/v1/auth/login",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var loginResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&loginResponse)
	require.NoError(suite.T(), err)

	assert.NotEmpty(suite.T(), loginResponse["token"])
	assert.Equal(suite.T(), "test@example.com", loginResponse["email"])
}

// Test workflow CRUD operations
func (suite *E2ETestSuite) TestWorkflowCRUD() {
	token := suite.getAuthToken()

	// Create workflow
	workflowData := map[string]interface{}{
		"name":        "Test Workflow",
		"description": "A test workflow for e2e testing",
		"nodes": []map[string]interface{}{
			{
				"id":         "start",
				"type":       "n8n-nodes-base.start",
				"name":       "Start",
				"parameters": map[string]interface{}{},
				"position":   map[string]float64{"x": 100, "y": 100},
			},
			{
				"id":   "http",
				"type": "n8n-nodes-base.httpRequest",
				"name": "HTTP Request",
				"parameters": map[string]interface{}{
					"url":    "https://api.example.com/test",
					"method": "GET",
				},
				"position": map[string]float64{"x": 300, "y": 100},
			},
		},
		"edges": []map[string]interface{}{
			{
				"source": "start",
				"target": "http",
			},
		},
		"settings": map[string]interface{}{
			"timeout": 60,
		},
	}

	// Create workflow
	workflowID := suite.createWorkflow(token, workflowData)
	assert.NotEmpty(suite.T(), workflowID)

	// Get workflow
	workflow := suite.getWorkflow(token, workflowID)
	assert.Equal(suite.T(), "Test Workflow", workflow["name"])
	assert.Equal(suite.T(), workflowID, workflow["id"])

	// Update workflow
	updateData := map[string]interface{}{
		"name":        "Updated Test Workflow",
		"description": "Updated description",
	}
	suite.updateWorkflow(token, workflowID, updateData)

	// Verify update
	updatedWorkflow := suite.getWorkflow(token, workflowID)
	assert.Equal(suite.T(), "Updated Test Workflow", updatedWorkflow["name"])

	// List workflows
	workflows := suite.listWorkflows(token)
	assert.True(suite.T(), len(workflows) > 0)

	// Delete workflow
	suite.deleteWorkflow(token, workflowID)

	// Verify deletion
	suite.verifyWorkflowDeleted(token, workflowID)
}

// Test workflow execution
func (suite *E2ETestSuite) TestWorkflowExecution() {
	token := suite.getAuthToken()

	// Create a simple workflow
	workflowData := map[string]interface{}{
		"name": "Execution Test Workflow",
		"nodes": []map[string]interface{}{
			{
				"id":   "start",
				"type": "n8n-nodes-base.start",
				"name": "Start",
				"parameters": map[string]interface{}{
					"data": map[string]interface{}{
						"message": "Hello World",
					},
				},
				"position": map[string]float64{"x": 100, "y": 100},
			},
		},
	}

	workflowID := suite.createWorkflow(token, workflowData)

	// Execute workflow
	executionData := map[string]interface{}{
		"mode": "sync",
		"data": map[string]interface{}{
			"input": "test data",
		},
	}

	executionID := suite.executeWorkflow(token, workflowID, executionData)
	assert.NotEmpty(suite.T(), executionID)

	// Get execution details
	execution := suite.getExecution(token, executionID)
	assert.Equal(suite.T(), executionID, execution["id"])
	assert.Equal(suite.T(), workflowID, execution["workflow_id"])

	// List executions
	executions := suite.listExecutions(token)
	assert.True(suite.T(), len(executions) > 0)

	// Cleanup
	suite.deleteWorkflow(token, workflowID)
}

// Test error handling
func (suite *E2ETestSuite) TestErrorHandling() {
	token := suite.getAuthToken()

	// Test invalid workflow ID
	resp := suite.makeRequest("GET", "/api/v1/workflows/invalid-id", token, nil)
	assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)

	// Test unauthorized request
	resp = suite.makeRequest("GET", "/api/v1/workflows", "", nil)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)

	// Test invalid JSON
	resp = suite.makeRequest("POST", "/api/v1/workflows", token, []byte("invalid json"))
	assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
}

// Test concurrent operations
func (suite *E2ETestSuite) TestConcurrentOperations() {
	token := suite.getAuthToken()
	const numRoutines = 10

	workflowData := map[string]interface{}{
		"name": "Concurrent Test Workflow",
		"nodes": []map[string]interface{}{
			{
				"id":   "start",
				"type": "n8n-nodes-base.start",
				"name": "Start",
			},
		},
	}

	// Create multiple workflows concurrently
	workflowIDs := make(chan string, numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func(index int) {
			data := workflowData
			data.(map[string]interface{})["name"] = fmt.Sprintf("Concurrent Test Workflow %d", index)
			workflowID := suite.createWorkflow(token, data)
			workflowIDs <- workflowID
		}(i)
	}

	// Collect workflow IDs
	var createdIDs []string
	for i := 0; i < numRoutines; i++ {
		createdIDs = append(createdIDs, <-workflowIDs)
	}

	// Verify all workflows were created
	assert.Len(suite.T(), createdIDs, numRoutines)

	// Clean up
	for _, id := range createdIDs {
		suite.deleteWorkflow(token, id)
	}
}

// Helper methods

func (suite *E2ETestSuite) getAuthToken() string {
	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "testpassword",
	}

	jsonData, _ := json.Marshal(loginData)
	resp, err := suite.client.Post(
		suite.baseURL+"/api/v1/auth/login",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var loginResponse map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&loginResponse)

	return loginResponse["token"].(string)
}

func (suite *E2ETestSuite) createWorkflow(token string, data map[string]interface{}) string {
	jsonData, _ := json.Marshal(data)
	resp := suite.makeRequest("POST", "/api/v1/workflows", token, jsonData)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response["id"].(string)
}

func (suite *E2ETestSuite) getWorkflow(token, id string) map[string]interface{} {
	resp := suite.makeRequest("GET", "/api/v1/workflows/"+id, token, nil)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var workflow map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&workflow)
	return workflow
}

func (suite *E2ETestSuite) updateWorkflow(token, id string, data map[string]interface{}) {
	jsonData, _ := json.Marshal(data)
	resp := suite.makeRequest("PUT", "/api/v1/workflows/"+id, token, jsonData)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

func (suite *E2ETestSuite) deleteWorkflow(token, id string) {
	resp := suite.makeRequest("DELETE", "/api/v1/workflows/"+id, token, nil)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusNoContent, resp.StatusCode)
}

func (suite *E2ETestSuite) verifyWorkflowDeleted(token, id string) {
	resp := suite.makeRequest("GET", "/api/v1/workflows/"+id, token, nil)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)
}

func (suite *E2ETestSuite) listWorkflows(token string) []interface{} {
	resp := suite.makeRequest("GET", "/api/v1/workflows", token, nil)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response["workflows"].([]interface{})
}

func (suite *E2ETestSuite) executeWorkflow(token, workflowID string, data map[string]interface{}) string {
	jsonData, _ := json.Marshal(data)
	resp := suite.makeRequest("POST", "/api/v1/workflows/"+workflowID+"/execute", token, jsonData)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusAccepted, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response["execution_id"].(string)
}

func (suite *E2ETestSuite) getExecution(token, id string) map[string]interface{} {
	resp := suite.makeRequest("GET", "/api/v1/executions/"+id, token, nil)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var execution map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&execution)
	return execution
}

func (suite *E2ETestSuite) listExecutions(token string) []interface{} {
	resp := suite.makeRequest("GET", "/api/v1/executions", token, nil)
	defer resp.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	return response["executions"].([]interface{})
}

func (suite *E2ETestSuite) makeRequest(method, path, token string, body []byte) *http.Response {
	var reqBody *bytes.Buffer
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, suite.baseURL+path, reqBody)
	require.NoError(suite.T(), err)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := suite.client.Do(req)
	require.NoError(suite.T(), err)

	return resp
}

// Mock handlers

func (suite *E2ETestSuite) handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginData map[string]string
	json.NewDecoder(r.Body).Decode(&loginData)

	response := map[string]interface{}{
		"token":   "mock-jwt-token",
		"email":   loginData["email"],
		"user_id": suite.testUserID,
		"team_id": suite.testTeamID,
		"expires": time.Now().Add(24 * time.Hour).Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (suite *E2ETestSuite) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"workflows": []interface{}{},
		"total":     0,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleCreateWorkflow(w http.ResponseWriter, r *http.Request) {
	var workflowData map[string]interface{}
	json.NewDecoder(r.Body).Decode(&workflowData)

	response := map[string]interface{}{
		"id":         "workflow-" + generateID(),
		"name":       workflowData["name"],
		"created_at": time.Now().Format(time.RFC3339),
		"updated_at": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	response := map[string]interface{}{
		"id":   id,
		"name": "Test Workflow",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleUpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var updateData map[string]interface{}
	json.NewDecoder(r.Body).Decode(&updateData)

	response := map[string]interface{}{
		"id":         id,
		"name":       updateData["name"],
		"updated_at": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleDeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (suite *E2ETestSuite) handleExecuteWorkflow(w http.ResponseWriter, r *http.Request) {
	workflowID := chi.URLParam(r, "id")
	response := map[string]interface{}{
		"execution_id": "execution-" + generateID(),
		"workflow_id":  workflowID,
		"status":       "running",
		"started_at":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleListExecutions(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"executions": []interface{}{},
		"total":      0,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	response := map[string]interface{}{
		"id":          id,
		"workflow_id": "workflow-123",
		"status":      "completed",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (suite *E2ETestSuite) handleCancelExecution(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Execution canceled",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Utility functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// TestE2ESuite runs the e2e test suite
func TestE2ESuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}
