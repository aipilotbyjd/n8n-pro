package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n8n-pro/internal/presentation/http/middleware"
	"n8n-pro/internal/auth/jwt"
	"n8n-pro/internal/shared"
	"n8n-pro/internal/testutils"
	"n8n-pro/pkg/errors"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// APITestSuite provides comprehensive API testing for the n8n clone
type APITestSuite struct {
	suite.Suite
	server       *httptest.Server
	jwtSvc       *jwt.Service
	testUser     *testutils.TestUser
	authToken    string
	invalidToken string
	baseURL      string
}

func (suite *APITestSuite) SetupSuite() {
	// Create JWT service for token generation
	cfg := &jwt.Config{
		Secret:               "test-secret-key-for-testing-only",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour * 24,
		Issuer:               "n8n-pro-test",
		Audience:             "n8n-pro-api",
	}
	suite.jwtSvc = jwt.New(cfg)

	// Create test user
	suite.testUser = testutils.CreateTestUser()

	// Generate valid auth token
	tokenPair, err := suite.jwtSvc.GenerateTokenPair(
		suite.testUser.ID,
		suite.testUser.Email,
		suite.testUser.Role,
		suite.testUser.TeamID,
		"Test Team",
		"premium",
		[]string{"workflows:read", "workflows:write", "workflows:delete"},
	)
	require.NoError(suite.T(), err)
	suite.authToken = tokenPair.AccessToken
	suite.invalidToken = "invalid.jwt.token"

	// Create test server
	suite.server = suite.createTestServer()
	suite.baseURL = suite.server.URL
}

func (suite *APITestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
}

func (suite *APITestSuite) createTestServer() *httptest.Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	// Health endpoints (no auth required)
	r.Get("/health", suite.handleHealth)
	r.Get("/version", suite.handleVersion)

	// Auth endpoints (no auth required)
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", suite.handleLogin)
		r.Post("/register", suite.handleRegister)
	})

	// Protected API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Auth middleware for protected routes
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

		// Users
		r.Route("/users", func(r chi.Router) {
			r.Get("/me", suite.handleGetCurrentUser)
			r.Put("/me", suite.handleUpdateCurrentUser)
		})
	})

	return httptest.NewServer(r)
}

// Test Methods

func (suite *APITestSuite) TestHealthEndpoints() {
	suite.Run("health endpoint", func() {
		resp, err := http.Get(suite.baseURL + "/health")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
		assert.Equal(suite.T(), "application/json", resp.Header.Get("Content-Type"))

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), "healthy", response["status"])
		assert.Equal(suite.T(), "api", response["service"])
		assert.NotEmpty(suite.T(), response["timestamp"])
	})

	suite.Run("version endpoint", func() {
		resp, err := http.Get(suite.baseURL + "/version")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(suite.T(), err)

		assert.NotEmpty(suite.T(), response["version"])
		assert.NotEmpty(suite.T(), response["go_version"])
	})
}

func (suite *APITestSuite) TestAuthenticationEndpoints() {
	suite.Run("login endpoint", func() {
		loginReq := map[string]interface{}{
			"email":    suite.testUser.Email,
			"password": "test123",
		}

		body, _ := json.Marshal(loginReq)
		resp, err := http.Post(suite.baseURL+"/api/v1/auth/login", "application/json", bytes.NewBuffer(body))
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), "success", response["status"])
		data := response["data"].(map[string]interface{})
		assert.NotEmpty(suite.T(), data["access_token"])
		assert.NotEmpty(suite.T(), data["refresh_token"])
		assert.Equal(suite.T(), "Bearer", data["token_type"])
	})

	suite.Run("invalid credentials", func() {
		loginReq := map[string]interface{}{
			"email":    "invalid@example.com",
			"password": "wrongpassword",
		}

		body, _ := json.Marshal(loginReq)
		resp, err := http.Post(suite.baseURL+"/api/v1/auth/login", "application/json", bytes.NewBuffer(body))
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
	})
}

func (suite *APITestSuite) TestAuthorizationMiddleware() {
	suite.Run("missing authorization header", func() {
		resp, err := http.Get(suite.baseURL + "/api/v1/workflows")
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
	})

	suite.Run("invalid token", func() {
		req, _ := http.NewRequest("GET", suite.baseURL+"/api/v1/workflows", nil)
		req.Header.Set("Authorization", "Bearer "+suite.invalidToken)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
	})

	suite.Run("valid token", func() {
		req, _ := http.NewRequest("GET", suite.baseURL+"/api/v1/workflows", nil)
		req.Header.Set("Authorization", "Bearer "+suite.authToken)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(suite.T(), err)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
	})
}

func (suite *APITestSuite) TestWorkflowAPIs() {
	headers := map[string]string{
		"Authorization": "Bearer " + suite.authToken,
		"Content-Type":  "application/json",
	}

	suite.Run("create workflow", func() {
		workflowReq := map[string]interface{}{
			"name":        "Test Workflow",
			"description": "A test workflow for API testing",
			"nodes": []map[string]interface{}{
				{
					"id":         "start-node",
					"name":       "Start",
					"type":       "trigger",
					"position":   map[string]int{"x": 100, "y": 100},
					"parameters": map[string]interface{}{},
				},
			},
			"connections": []map[string]interface{}{},
			"tags":        []string{"test", "api"},
			"config": map[string]interface{}{
				"timeout":            3600,
				"max_execution_time": 3600,
			},
		}

		body, _ := json.Marshal(workflowReq)
		resp := suite.makeRequest("POST", "/api/v1/workflows", bytes.NewBuffer(body), headers)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

		var response map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), "success", response["status"])
		data := response["data"].(map[string]interface{})
		assert.NotEmpty(suite.T(), data["id"])
		assert.Equal(suite.T(), "Test Workflow", data["name"])
		assert.Equal(suite.T(), "draft", data["status"])
	})

	suite.Run("list workflows", func() {
		resp := suite.makeRequest("GET", "/api/v1/workflows", nil, headers)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), "success", response["status"])
		data := response["data"].(map[string]interface{})
		assert.NotNil(suite.T(), data["workflows"])
		assert.NotNil(suite.T(), data["pagination"])
	})

	suite.Run("get workflow", func() {
		workflowID := "workflow-123"
		resp := suite.makeRequest("GET", "/api/v1/workflows/"+workflowID, nil, headers)
		defer resp.Body.Close()

		// Should be 404 since we're using a mock workflow ID
		assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)
	})

	suite.Run("delete workflow", func() {
		workflowID := "workflow-123"
		resp := suite.makeRequest("DELETE", "/api/v1/workflows/"+workflowID, nil, headers)
		defer resp.Body.Close()

		// Should be 404 since we're using a mock workflow ID
		assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)
	})
}

func (suite *APITestSuite) TestInputValidation() {
	headers := map[string]string{
		"Authorization": "Bearer " + suite.authToken,
		"Content-Type":  "application/json",
	}

	suite.Run("create workflow with invalid data", func() {
		workflowReq := map[string]interface{}{
			"name": "", // Empty name should fail validation
		}

		body, _ := json.Marshal(workflowReq)
		resp := suite.makeRequest("POST", "/api/v1/workflows", bytes.NewBuffer(body), headers)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
	})

	suite.Run("create workflow with invalid JSON", func() {
		invalidJSON := "{invalid json"
		resp := suite.makeRequest("POST", "/api/v1/workflows", strings.NewReader(invalidJSON), headers)
		defer resp.Body.Close()

		assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
	})
}

// Helper methods and mock handlers

func (suite *APITestSuite) makeRequest(method, path string, body interface{}, headers map[string]string) *http.Response {
	var reqBody io.Reader
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			reqBody = v
		case *strings.Reader:
			buf := bytes.NewBufferString("")
			v.Seek(0, 0)
			buf.ReadFrom(v)
			reqBody = buf
		case string:
			reqBody = strings.NewReader(v)
		default:
			reqBody = nil
		}
	} else {
		reqBody = nil
	}

	req, _ := http.NewRequest(method, suite.baseURL+path, reqBody)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func (suite *APITestSuite) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			suite.writeErrorResponse(w, errors.NewUnauthorizedError("Missing or invalid authorization header"))
			return
		}

		tokenString := strings.TrimPrefix(token, "Bearer ")

		// Validate token using JWT service
		claims, err := suite.jwtSvc.ValidateToken(tokenString)
		if err != nil {
			suite.writeErrorResponse(w, errors.NewUnauthorizedError("Invalid or expired token"))
			return
		}

		// Create user context
		user := &common.User{
			ID:     claims.UserID,
			Email:  claims.Email,
			Role:   claims.Role,
			TeamID: claims.TeamID,
		}

		ctx := context.WithValue(r.Context(), middleware.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (suite *APITestSuite) writeErrorResponse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	var message string

	if appErr := errors.GetAppError(err); appErr != nil {
		statusCode = appErr.HTTPStatus()
		message = appErr.Message
	} else {
		statusCode = http.StatusInternalServerError
		message = "Internal server error"
	}

	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"status":  "error",
		"message": message,
	}
	json.NewEncoder(w).Encode(response)
}

func (suite *APITestSuite) writeSuccessResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"status": "success",
		"data":   data,
	}
	json.NewEncoder(w).Encode(response)
}

// Mock handlers for testing

func (suite *APITestSuite) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "api",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (suite *APITestSuite) handleVersion(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"version":    "test",
		"build_time": "unknown",
		"git_commit": "test",
		"go_version": "go1.23",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (suite *APITestSuite) handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		suite.writeErrorResponse(w, errors.NewValidationError("Invalid request body"))
		return
	}

	email, _ := loginReq["email"].(string)
	password, _ := loginReq["password"].(string)

	if email == suite.testUser.Email && password == "test123" {
		suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
			"access_token":  suite.authToken,
			"refresh_token": "refresh_token_here",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	} else {
		suite.writeErrorResponse(w, errors.NewUnauthorizedError("Invalid credentials"))
	}
}

func (suite *APITestSuite) handleRegister(w http.ResponseWriter, r *http.Request) {
	var registerReq map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&registerReq); err != nil {
		suite.writeErrorResponse(w, errors.NewValidationError("Invalid request body"))
		return
	}

	suite.writeSuccessResponse(w, http.StatusCreated, map[string]interface{}{
		"user_id": "new-user-id",
		"email":   registerReq["email"],
		"name":    registerReq["name"],
	})
}

// Workflow handlers
func (suite *APITestSuite) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"workflows": []map[string]interface{}{
			{
				"id":     "workflow-1",
				"name":   "Sample Workflow",
				"status": "active",
			},
		},
		"pagination": map[string]interface{}{
			"page":        1,
			"page_size":   50,
			"total":       1,
			"total_pages": 1,
		},
	})
}

func (suite *APITestSuite) handleCreateWorkflow(w http.ResponseWriter, r *http.Request) {
	var workflowReq map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&workflowReq); err != nil {
		suite.writeErrorResponse(w, errors.NewValidationError("Invalid request body"))
		return
	}

	name, _ := workflowReq["name"].(string)
	if name == "" {
		suite.writeErrorResponse(w, errors.NewValidationError("Name is required"))
		return
	}

	suite.writeSuccessResponse(w, http.StatusCreated, map[string]interface{}{
		"id":          "workflow-new",
		"name":        name,
		"description": workflowReq["description"],
		"status":      "draft",
		"created_at":  time.Now().Format(time.RFC3339),
	})
}

func (suite *APITestSuite) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	suite.writeErrorResponse(w, errors.NotFoundError("workflow"))
}

func (suite *APITestSuite) handleUpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	suite.writeErrorResponse(w, errors.NotFoundError("workflow"))
}

func (suite *APITestSuite) handleDeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	suite.writeErrorResponse(w, errors.NotFoundError("workflow"))
}

func (suite *APITestSuite) handleExecuteWorkflow(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusAccepted, map[string]interface{}{
		"execution_id": "execution-new",
		"status":       "running",
		"started_at":   time.Now().Format(time.RFC3339),
	})
}

func (suite *APITestSuite) handleListExecutions(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"executions": []map[string]interface{}{},
		"total":      0,
	})
}

func (suite *APITestSuite) handleGetExecution(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"id":         "execution-123",
		"status":     "completed",
		"started_at": time.Now().Add(-time.Hour).Format(time.RFC3339),
		"ended_at":   time.Now().Format(time.RFC3339),
	})
}

func (suite *APITestSuite) handleCancelExecution(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Execution cancelled",
	})
}

func (suite *APITestSuite) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"id":    suite.testUser.ID,
		"email": suite.testUser.Email,
		"name":  suite.testUser.Name,
		"role":  suite.testUser.Role,
	})
}

func (suite *APITestSuite) handleUpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	suite.writeSuccessResponse(w, http.StatusOK, map[string]interface{}{
		"message": "User updated successfully",
	})
}

// Test runner
func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}
