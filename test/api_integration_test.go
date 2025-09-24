package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/config"
	"n8n-pro/internal/workflows"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// N8nAPIIntegrationTestSuite tests all APIs like n8n clone
type N8nAPIIntegrationTestSuite struct {
	suite.Suite
	server      *httptest.Server
	client      *http.Client
	testUser    *TestUser
	authToken   string
	testTeamID  string
}

type TestUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	TeamID   string `json:"team_id"`
	Role     string `json:"role"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    string      `json:"code,omitempty"`
}

func (suite *N8nAPIIntegrationTestSuite) SetupSuite() {
	// Setup test configuration
	cfg := &config.Config{
		Environment: "test",
		Debug:       true,
		LogLevel:    "debug",
		API: &config.APIConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			EnableCORS:   true,
		},
		Database: &config.DatabaseConfig{
			Host:               "localhost",
			Port:               5432,
			Database:           "n8n_clone",
			Username:           "user",
			Password:           "password",
			SSLMode:            "disable",
			MaxOpenConnections: 5,
			MaxIdleConnections: 2,
			EnableMigrations:   true,
		},
		Auth: &config.AuthConfig{
			JWTSecret:              "test-secret-key-for-jwt-signing-32-chars",
			JWTExpiration:          time.Hour,
			RefreshTokenExpiration: 24 * time.Hour,
		},
		Metrics: &config.MetricsConfig{
			Enabled: true,
			Host:    "localhost",
			Port:    9090,
		},
	}

	// Create test server
	server, err := createTestServer(cfg)
	require.NoError(suite.T(), err)
	
	suite.server = httptest.NewServer(server.Handler)
	suite.client = &http.Client{Timeout: 30 * time.Second}
	
	suite.testUser = &TestUser{
		Name:     "Test User",
		Email:    "test@n8n-clone.com",
		Password: "TestPassword123!",
		Role:     "admin",
	}
}

func (suite *N8nAPIIntegrationTestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
}

// Test 1: Health and Version Endpoints
func (suite *N8nAPIIntegrationTestSuite) TestHealthAndVersion() {
	suite.Run("health endpoint", func() {
		resp, err := suite.client.Get(suite.server.URL + "/health")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var healthResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&healthResp)
		require.NoError(suite.T(), err)
		
		assert.Equal(suite.T(), "healthy", healthResp["status"])
		assert.Equal(suite.T(), "api", healthResp["service"])
		assert.NotEmpty(suite.T(), healthResp["timestamp"])
	})

	suite.Run("version endpoint", func() {
		resp, err := suite.client.Get(suite.server.URL + "/version")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var versionResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&versionResp)
		require.NoError(suite.T(), err)
		
		assert.NotEmpty(suite.T(), versionResp["version"])
		assert.NotEmpty(suite.T(), versionResp["go_version"])
	})
}

// Test 2: Authentication Flow (like n8n)
func (suite *N8nAPIIntegrationTestSuite) TestAuthenticationFlow() {
	suite.Run("user registration", func() {
		reqBody := map[string]string{
			"name":     suite.testUser.Name,
			"email":    suite.testUser.Email,
			"password": suite.testUser.Password,
		}
		
		resp := suite.makeRequest("POST", "/api/v1/auth/register", reqBody, "")
		assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		assert.Contains(suite.T(), apiResp.Message, "registered successfully")
		
		// Extract user data
		userData := apiResp.Data.(map[string]interface{})
		suite.testUser.ID = userData["user_id"].(string)
		suite.testTeamID = userData["team_id"].(string)
	})

	suite.Run("user login", func() {
		reqBody := map[string]string{
			"email":    suite.testUser.Email,
			"password": suite.testUser.Password,
		}
		
		resp := suite.makeRequest("POST", "/api/v1/auth/login", reqBody, "")
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		// Extract tokens
		tokenData := apiResp.Data.(map[string]interface{})
		suite.authToken = tokenData["access_token"].(string)
		
		assert.NotEmpty(suite.T(), suite.authToken)
		assert.NotEmpty(suite.T(), tokenData["refresh_token"])
	})

	suite.Run("get current user profile", func() {
		resp := suite.makeRequest("GET", "/api/v1/profile", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		userData := apiResp.Data.(map[string]interface{})
		assert.Equal(suite.T(), suite.testUser.Email, userData["email"])
		assert.Equal(suite.T(), suite.testUser.Name, userData["name"])
	})
}

// Test 3: Workflow Management (core n8n functionality)
func (suite *N8nAPIIntegrationTestSuite) TestWorkflowManagement() {
	var workflowID string

	suite.Run("create workflow", func() {
		workflow := map[string]interface{}{
			"name":        "Test Workflow",
			"description": "A test workflow for integration testing",
			"nodes": []map[string]interface{}{
				{
					"id":   "start-node",
					"type": "n8n-nodes-base.start",
					"name": "Start",
					"parameters": map[string]interface{}{},
					"position": []float64{250, 300},
				},
				{
					"id":   "http-node",
					"type": "n8n-nodes-base.httpRequest",
					"name": "HTTP Request",
					"parameters": map[string]interface{}{
						"url":    "https://api.github.com/users/octocat",
						"method": "GET",
					},
					"position": []float64{450, 300},
				},
			},
			"connections": map[string]interface{}{
				"Start": map[string]interface{}{
					"main": [][]map[string]interface{}{
						{
							{"node": "HTTP Request", "type": "main", "index": 0},
						},
					},
				},
			},
			"tags":   []string{"test", "integration"},
			"active": true,
		}
		
		resp := suite.makeRequest("POST", "/api/v1/workflows", workflow, suite.authToken)
		assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		workflowData := apiResp.Data.(map[string]interface{})
		workflowID = workflowData["id"].(string)
		assert.NotEmpty(suite.T(), workflowID)
		assert.Equal(suite.T(), "Test Workflow", workflowData["name"])
	})

	suite.Run("get workflow", func() {
		resp := suite.makeRequest("GET", "/api/v1/workflows/"+workflowID, nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		workflowData := apiResp.Data.(map[string]interface{})
		assert.Equal(suite.T(), workflowID, workflowData["id"])
		assert.Equal(suite.T(), "Test Workflow", workflowData["name"])
	})

	suite.Run("list workflows", func() {
		resp := suite.makeRequest("GET", "/api/v1/workflows", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		workflowList := apiResp.Data.(map[string]interface{})
		workflows := workflowList["workflows"].([]interface{})
		assert.GreaterOrEqual(suite.T(), len(workflows), 1)
	})

	suite.Run("update workflow", func() {
		update := map[string]interface{}{
			"name":        "Updated Test Workflow",
			"description": "Updated description",
		}
		
		resp := suite.makeRequest("PUT", "/api/v1/workflows/"+workflowID, update, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		workflowData := apiResp.Data.(map[string]interface{})
		assert.Equal(suite.T(), "Updated Test Workflow", workflowData["name"])
	})

	suite.Run("execute workflow", func() {
		execReq := map[string]interface{}{
			"input_data": map[string]interface{}{
				"test": "data",
			},
		}
		
		resp := suite.makeRequest("POST", "/api/v1/workflows/"+workflowID+"/execute", execReq, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		execData := apiResp.Data.(map[string]interface{})
		assert.NotEmpty(suite.T(), execData["execution_id"])
	})
}

// Test 4: Credential Management (n8n feature)
func (suite *N8nAPIIntegrationTestSuite) TestCredentialManagement() {
	var credentialID string

	suite.Run("create credential", func() {
		credential := map[string]interface{}{
			"name": "Test API Credential",
			"type": "httpBasicAuth",
			"data": map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			"description": "Test credential for integration testing",
		}
		
		resp := suite.makeRequest("POST", "/api/v1/credentials", credential, suite.authToken)
		assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		credData := apiResp.Data.(map[string]interface{})
		credentialID = credData["id"].(string)
		assert.NotEmpty(suite.T(), credentialID)
		assert.Equal(suite.T(), "Test API Credential", credData["name"])
	})

	suite.Run("list credentials", func() {
		resp := suite.makeRequest("GET", "/api/v1/credentials", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		credList := apiResp.Data.(map[string]interface{})
		credentials := credList["credentials"].([]interface{})
		assert.GreaterOrEqual(suite.T(), len(credentials), 1)
	})

	suite.Run("get credential types", func() {
		resp := suite.makeRequest("GET", "/api/v1/credentials/types", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		types := apiResp.Data.([]interface{})
		assert.GreaterOrEqual(suite.T(), len(types), 1)
	})

	suite.Run("test credential", func() {
		resp := suite.makeRequest("POST", "/api/v1/credentials/"+credentialID+"/test", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		testResult := apiResp.Data.(map[string]interface{})
		assert.NotNil(suite.T(), testResult["success"])
	})
}

// Test 5: Execution Management
func (suite *N8nAPIIntegrationTestSuite) TestExecutionManagement() {
	suite.Run("list executions", func() {
		resp := suite.makeRequest("GET", "/api/v1/executions", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		execList := apiResp.Data.(map[string]interface{})
		assert.NotNil(suite.T(), execList["executions"])
	})
}

// Test 6: Metrics and Monitoring (n8n Pro feature)
func (suite *N8nAPIIntegrationTestSuite) TestMetricsAndMonitoring() {
	suite.Run("get system metrics", func() {
		resp := suite.makeRequest("GET", "/api/v1/metrics/system", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
		
		metrics := apiResp.Data.(map[string]interface{})
		assert.NotNil(suite.T(), metrics)
	})

	suite.Run("get team metrics", func() {
		resp := suite.makeRequest("GET", "/api/v1/metrics/team", nil, suite.authToken)
		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		var apiResp APIResponse
		err := json.NewDecoder(resp.Body).Decode(&apiResp)
		require.NoError(suite.T(), err)
		
		assert.True(suite.T(), apiResp.Success)
	})

	suite.Run("prometheus metrics endpoint", func() {
		resp, err := suite.client.Get(suite.server.URL + "/metrics")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		
		// Should return prometheus format metrics
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		metricsText := buf.String()
		
		// Check for basic Prometheus metrics format
		assert.Contains(suite.T(), metricsText, "# HELP")
		assert.Contains(suite.T(), metricsText, "# TYPE")
	})
}

// Helper method to make HTTP requests
func (suite *N8nAPIIntegrationTestSuite) makeRequest(method, path string, body interface{}, token string) *http.Response {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer([]byte{})
	}

	req, err := http.NewRequest(method, suite.server.URL+path, reqBody)
	require.NoError(suite.T(), err)

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := suite.client.Do(req)
	require.NoError(suite.T(), err)

	return resp
}

// Helper function to create test server
func createTestServer(cfg *config.Config) (*http.Server, error) {
	// This would normally call the main server creation function
	// For now, we'll mock it with a simple server
	return &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port),
		Handler: createMockRouter(),
	}, nil
}

// Mock router for testing (simplified)
func createMockRouter() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple mock responses for testing
		w.Header().Set("Content-Type", "application/json")
		
		switch {
		case r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "healthy",
				"service":   "api",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		case r.URL.Path == "/version":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":    "test-1.0.0",
				"go_version": "go1.23",
			})
		case strings.HasPrefix(r.URL.Path, "/api/v1/"):
			// Mock API responses
			response := APIResponse{
				Success: true,
				Data: map[string]interface{}{
					"id":      "test-id-123",
					"message": "Test response",
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Not found",
			})
		}
	})
}

// Test runner
func TestN8nAPIIntegrationSuite(t *testing.T) {
	suite.Run(t, new(N8nAPIIntegrationTestSuite))
}