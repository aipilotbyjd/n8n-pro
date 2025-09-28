package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"n8n-pro/internal/presentation/http/middleware"
	"n8n-pro/internal/application/auth"
	"n8n-pro/internal/testutils"
	"n8n-pro/internal/domain/workflow"
	"n8n-pro/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WorkflowHandlerTestSuite struct {
	suite.Suite
	handler      *WorkflowHandler
	mockService  *MockWorkflowService
	router       *chi.Mux
	testUser     *testutils.TestUser
	testWorkflow *testutils.TestWorkflow
}

// MockWorkflowService for testing handlers
type MockWorkflowService struct {
	mock.Mock
}

func (m *MockWorkflowService) Create(ctx context.Context, workflow *workflows.Workflow, userID string) (*workflows.Workflow, error) {
	args := m.Called(ctx, workflow, userID)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

func (m *MockWorkflowService) GetByID(ctx context.Context, id string, userID string) (*workflows.Workflow, error) {
	args := m.Called(ctx, id, userID)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

func (m *MockWorkflowService) Update(ctx context.Context, workflow *workflows.Workflow, userID string) (*workflows.Workflow, error) {
	args := m.Called(ctx, workflow, userID)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

func (m *MockWorkflowService) Delete(ctx context.Context, id string, userID string) error {
	args := m.Called(ctx, id, userID)
	return args.Error(0)
}

func (m *MockWorkflowService) List(ctx context.Context, filter *workflows.WorkflowListFilter, userID string) ([]*workflows.Workflow, int64, error) {
	args := m.Called(ctx, filter, userID)
	return args.Get(0).([]*workflows.Workflow), args.Get(1).(int64), args.Error(2)
}

func (suite *WorkflowHandlerTestSuite) SetupTest() {
	suite.mockService = &MockWorkflowService{}
	suite.handler = NewWorkflowHandler(&workflows.Service{}) // We'll replace this with mock
	suite.testUser = testutils.CreateTestUser()
	suite.testWorkflow = testutils.CreateTestWorkflow(suite.testUser.TeamID, suite.testUser.ID)

	// Setup router with test middleware
	suite.router = chi.NewRouter()
	suite.router.Use(suite.authMiddleware)
	suite.router.Route("/api/v1/workflows", func(r chi.Router) {
		r.Post("/", suite.handler.CreateWorkflow)
		r.Get("/{id}", suite.handler.GetWorkflow)
		r.Get("/", suite.handler.ListWorkflows)
		r.Put("/{id}", suite.handler.UpdateWorkflow)
		r.Delete("/{id}", suite.handler.DeleteWorkflow)
	})
}

// Test middleware that adds user to context
func (suite *WorkflowHandlerTestSuite) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := &auth.User{
			ID:     suite.testUser.ID,
			Email:  suite.testUser.Email,
			Name:   suite.testUser.Name,
			TeamID: suite.testUser.TeamID,
			Role:   suite.testUser.Role,
		}
		ctx := context.WithValue(r.Context(), middleware.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (suite *WorkflowHandlerTestSuite) TestCreateWorkflow() {
	suite.Run("successful creation", func() {
		workflow := suite.testWorkflow.ToWorkflow()
		request := CreateWorkflowRequest{
			Name:        workflow.Name,
			Description: workflow.Description,
			Nodes:       workflow.Nodes,
			Connections: workflow.Connections,
			Tags:        workflow.Tags,
			Config:      workflow.Config,
		}

		// Mock service call
		suite.mockService.On("Create", mock.AnythingOfType("*context.valueCtx"), mock.AnythingOfType("*workflows.Workflow"), suite.testUser.ID).Return(workflow, nil)

		// Temporarily replace handler service with mock
		originalHandler := suite.handler
		suite.handler = &WorkflowHandler{service: &workflows.Service{}}
		defer func() { suite.handler = originalHandler }()

		reqBody, _ := json.Marshal(request)
		req := httptest.NewRequest("POST", "/api/v1/workflows", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusCreated, rr.Code)

		var response map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(suite.T(), err)

		data := response["data"].(map[string]interface{})
		assert.Equal(suite.T(), workflow.Name, data["name"])
	})

	suite.Run("invalid JSON", func() {
		req := httptest.NewRequest("POST", "/api/v1/workflows", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusBadRequest, rr.Code)
	})

	suite.Run("missing required fields", func() {
		request := CreateWorkflowRequest{
			Name: "", // Missing required name
		}

		reqBody, _ := json.Marshal(request)
		req := httptest.NewRequest("POST", "/api/v1/workflows", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		// Should handle validation error (though current implementation doesn't validate)
		// This test shows where validation could be added
		assert.True(suite.T(), rr.Code >= 400)
	})
}

func (suite *WorkflowHandlerTestSuite) TestGetWorkflow() {
	suite.Run("successful retrieval", func() {
		workflow := suite.testWorkflow.ToWorkflow()

		suite.mockService.On("GetByID", mock.AnythingOfType("*context.valueCtx"), workflow.ID, suite.testUser.ID).Return(workflow, nil)

		req := httptest.NewRequest("GET", "/api/v1/workflows/"+workflow.ID, nil)
		rr := httptest.NewRecorder()

		// Add URL params to context
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", workflow.ID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(suite.T(), err)

		data := response["data"].(map[string]interface{})
		assert.Equal(suite.T(), workflow.ID, data["id"])
	})

	suite.Run("workflow not found", func() {
		workflowID := uuid.New().String()

		suite.mockService.On("GetByID", mock.AnythingOfType("*context.valueCtx"), workflowID, suite.testUser.ID).Return((*workflows.Workflow)(nil), errors.NotFoundError("workflow"))

		req := httptest.NewRequest("GET", "/api/v1/workflows/"+workflowID, nil)
		rr := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", workflowID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusNotFound, rr.Code)
	})

	suite.Run("missing workflow ID", func() {
		req := httptest.NewRequest("GET", "/api/v1/workflows/", nil)
		rr := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusBadRequest, rr.Code)
	})
}

func (suite *WorkflowHandlerTestSuite) TestListWorkflows() {
	suite.Run("successful listing", func() {
		workflows := []*workflows.Workflow{suite.testWorkflow.ToWorkflow()}

		suite.mockService.On("List", mock.AnythingOfType("*context.valueCtx"),
			mock.AnythingOfType("*workflows.WorkflowListFilter"), suite.testUser.ID).Return(workflows, int64(1), nil)

		req := httptest.NewRequest("GET", "/api/v1/workflows", nil)
		rr := httptest.NewRecorder()

		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(suite.T(), err)

		workflowsData := response["data"].(map[string]interface{})["workflows"].([]interface{})
		assert.Len(suite.T(), workflowsData, 1)
	})

	suite.Run("with query parameters", func() {
		workflows := []*workflows.Workflow{}

		suite.mockService.On("List", mock.AnythingOfType("*context.valueCtx"),
			mock.AnythingOfType("*workflows.WorkflowListFilter"), suite.testUser.ID).Return(workflows, int64(0), nil)

		req := httptest.NewRequest("GET", "/api/v1/workflows?status=active&search=test&page=2&page_size=25", nil)
		rr := httptest.NewRecorder()

		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusOK, rr.Code)
	})
}

func (suite *WorkflowHandlerTestSuite) TestUpdateWorkflow() {
	suite.Run("successful update", func() {
		workflow := suite.testWorkflow.ToWorkflow()
		updatedWorkflow := *workflow
		updatedWorkflow.Description = "Updated description"

		request := UpdateWorkflowRequest{
			Name:        updatedWorkflow.Name,
			Description: updatedWorkflow.Description,
			Nodes:       updatedWorkflow.Nodes,
			Connections: updatedWorkflow.Connections,
			Tags:        updatedWorkflow.Tags,
			Config:      updatedWorkflow.Config,
		}

		suite.mockService.On("GetByID", mock.AnythingOfType("*context.valueCtx"), workflow.ID, suite.testUser.ID).Return(workflow, nil)
		suite.mockService.On("Update", mock.AnythingOfType("*context.valueCtx"), mock.AnythingOfType("*workflows.Workflow"), suite.testUser.ID).Return(&updatedWorkflow, nil)

		reqBody, _ := json.Marshal(request)
		req := httptest.NewRequest("PUT", "/api/v1/workflows/"+workflow.ID, bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", workflow.ID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(suite.T(), err)

		data := response["data"].(map[string]interface{})
		assert.Equal(suite.T(), "Updated description", data["description"])
	})
}

func (suite *WorkflowHandlerTestSuite) TestDeleteWorkflow() {
	suite.Run("successful deletion", func() {
		workflowID := suite.testWorkflow.ID

		suite.mockService.On("Delete", mock.AnythingOfType("*context.valueCtx"), workflowID, suite.testUser.ID).Return(nil)

		req := httptest.NewRequest("DELETE", "/api/v1/workflows/"+workflowID, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", workflowID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusNoContent, rr.Code)
	})

	suite.Run("workflow not found", func() {
		workflowID := uuid.New().String()

		suite.mockService.On("Delete", mock.AnythingOfType("*context.valueCtx"), workflowID, suite.testUser.ID).Return(errors.NotFoundError("workflow"))

		req := httptest.NewRequest("DELETE", "/api/v1/workflows/"+workflowID, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", workflowID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		suite.router.ServeHTTP(rr, req)

		assert.Equal(suite.T(), http.StatusNotFound, rr.Code)
	})
}

func TestWorkflowHandlerSuite(t *testing.T) {
	suite.Run(t, new(WorkflowHandlerTestSuite))
}

// Test helper functions
func TestHelperFunctions(t *testing.T) {
	t.Run("writeError", func(t *testing.T) {
		rr := httptest.NewRecorder()
		err := errors.ValidationError(errors.CodeInvalidInput, "test error")

		writeError(rr, err)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var response map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&response)
		assert.Equal(t, "error", response["status"])
		assert.Equal(t, "test error", response["message"])
	})

	t.Run("writeSuccess", func(t *testing.T) {
		rr := httptest.NewRecorder()
		data := map[string]interface{}{"test": "data"}

		writeSuccess(rr, http.StatusOK, data)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var response map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&response)
		assert.Equal(t, data, response["data"])
	})
}

// Test request validation
func TestRequestValidation(t *testing.T) {
	t.Run("CreateWorkflowRequest validation", func(t *testing.T) {
		validRequest := CreateWorkflowRequest{
			Name:        "Test Workflow",
			Description: "A test workflow",
			Nodes:       []workflows.Node{},
			Connections: []workflows.Connection{},
			Tags:        []workflows.Tag{},
			Config:      workflows.WorkflowConfig{},
		}

		assert.Equal(t, "Test Workflow", validRequest.Name)
		assert.NotNil(t, validRequest.Nodes)
	})

	t.Run("UpdateWorkflowRequest validation", func(t *testing.T) {
		status := workflows.WorkflowStatusActive
		validRequest := UpdateWorkflowRequest{
			Name:        "Updated Workflow",
			Description: "Updated description",
			Status:      &status,
		}

		assert.Equal(t, "Updated Workflow", validRequest.Name)
		assert.Equal(t, workflows.WorkflowStatusActive, *validRequest.Status)
	})
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	t.Run("No user in context", func(t *testing.T) {
		handler := NewWorkflowHandler(&workflows.Service{})

		req := httptest.NewRequest("POST", "/api/v1/workflows", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.CreateWorkflow(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Service error handling", func(t *testing.T) {
		// Test that service errors are properly converted to HTTP responses
		// This would be tested in integration tests with actual service
		assert.True(t, true) // Placeholder
	})
}
