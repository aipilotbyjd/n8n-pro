package workflows

import (
	"context"
	"testing"

	"n8n-pro/internal/config"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockWorkflowRepository for testing
type MockWorkflowRepository struct {
	mock.Mock
}

func (m *MockWorkflowRepository) Create(ctx context.Context, workflow *Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetByID(ctx context.Context, id string) (*Workflow, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Workflow), args.Error(1)
}

func (m *MockWorkflowRepository) GetByIDWithDetails(ctx context.Context, id string) (*Workflow, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Workflow), args.Error(1)
}

func (m *MockWorkflowRepository) Update(ctx context.Context, workflow *Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockWorkflowRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) List(ctx context.Context, filter *WorkflowListFilter) ([]*Workflow, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*Workflow), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) CreateExecution(ctx context.Context, execution *WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetExecutionByID(ctx context.Context, id string) (*WorkflowExecution, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowExecution), args.Error(1)
}

func (m *MockWorkflowRepository) UpdateExecution(ctx context.Context, execution *WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockWorkflowRepository) ListExecutions(ctx context.Context, filter *ExecutionListFilter) ([]*WorkflowExecution, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*WorkflowExecution), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) DeleteExecution(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) CreateVersion(ctx context.Context, version *WorkflowVersion) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetVersions(ctx context.Context, workflowID string) ([]*WorkflowVersion, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*WorkflowVersion), args.Error(1)
}

func (m *MockWorkflowRepository) GetVersionByNumber(ctx context.Context, workflowID string, version int) (*WorkflowVersion, error) {
	args := m.Called(ctx, workflowID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowVersion), args.Error(1)
}

func (m *MockWorkflowRepository) CreateTemplate(ctx context.Context, template *WorkflowTemplate) error {
	args := m.Called(ctx, template)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetTemplateByID(ctx context.Context, id string) (*WorkflowTemplate, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowTemplate), args.Error(1)
}

func (m *MockWorkflowRepository) ListTemplates(ctx context.Context, filter *TemplateListFilter) ([]*WorkflowTemplate, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*WorkflowTemplate), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) CreateShare(ctx context.Context, share *WorkflowShare) error {
	args := m.Called(ctx, share)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetShares(ctx context.Context, workflowID string) ([]*WorkflowShare, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*WorkflowShare), args.Error(1)
}

func (m *MockWorkflowRepository) DeleteShare(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetExecutionSummary(ctx context.Context, workflowID string, period string) (*ExecutionSummary, error) {
	args := m.Called(ctx, workflowID, period)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ExecutionSummary), args.Error(1)
}

func (m *MockWorkflowRepository) GetWorkflowMetrics(ctx context.Context, workflowID string, period string) (*WorkflowMetrics, error) {
	args := m.Called(ctx, workflowID, period)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowMetrics), args.Error(1)
}

func (m *MockWorkflowRepository) GetTeamMetrics(ctx context.Context, teamID string, period string) (*TeamMetrics, error) {
	args := m.Called(ctx, teamID, period)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TeamMetrics), args.Error(1)
}

func (m *MockWorkflowRepository) CreateTag(ctx context.Context, tag *Tag) error {
	args := m.Called(ctx, tag)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetTagsByWorkflow(ctx context.Context, workflowID string) ([]*Tag, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*Tag), args.Error(1)
}

func (m *MockWorkflowRepository) ListTags(ctx context.Context, teamID string) ([]*Tag, error) {
	args := m.Called(ctx, teamID)
	return args.Get(0).([]*Tag), args.Error(1)
}

// MockValidator for testing
type MockValidator struct {
	mock.Mock
}

func (m *MockValidator) ValidateWorkflow(ctx context.Context, workflow *Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockValidator) ValidateExecution(ctx context.Context, execution *WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockValidator) ValidatePermissions(ctx context.Context, userID, teamID, workflowID string, action string) error {
	args := m.Called(ctx, userID, teamID, workflowID, action)
	return args.Error(0)
}

// MockExecutor for testing
type MockExecutor struct {
	mock.Mock
}

func (m *MockExecutor) Execute(ctx context.Context, execution *WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockExecutor) Cancel(ctx context.Context, executionID string) error {
	args := m.Called(ctx, executionID)
	return args.Error(0)
}

func (m *MockExecutor) Pause(ctx context.Context, executionID string) error {
	args := m.Called(ctx, executionID)
	return args.Error(0)
}

func (m *MockExecutor) Resume(ctx context.Context, executionID string) error {
	args := m.Called(ctx, executionID)
	return args.Error(0)
}

func (m *MockExecutor) Retry(ctx context.Context, executionID string) (*WorkflowExecution, error) {
	args := m.Called(ctx, executionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowExecution), args.Error(1)
}

// MockTemplateService for testing
type MockTemplateService struct {
	mock.Mock
}

func (m *MockTemplateService) CreateFromWorkflow(ctx context.Context, workflowID string, template *WorkflowTemplate) (*WorkflowTemplate, error) {
	args := m.Called(ctx, workflowID, template)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowTemplate), args.Error(1)
}

func (m *MockTemplateService) InstantiateTemplate(ctx context.Context, templateID, teamID, ownerID string) (*Workflow, error) {
	args := m.Called(ctx, templateID, teamID, ownerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Workflow), args.Error(1)
}

// MockCredentialService for testing
type MockCredentialService struct {
	mock.Mock
}

func (m *MockCredentialService) ValidateCredentials(ctx context.Context, credentialIDs []string, teamID string) error {
	args := m.Called(ctx, credentialIDs, teamID)
	return args.Error(0)
}

func (m *MockCredentialService) GetCredentialsByIDs(ctx context.Context, credentialIDs []string) (map[string]interface{}, error) {
	args := m.Called(ctx, credentialIDs)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func TestWorkflowService(t *testing.T) {
	mockRepo := &MockWorkflowRepository{}
	mockValidator := &MockValidator{}
	mockExecutor := &MockExecutor{}
	mockTemplateService := &MockTemplateService{}
	mockCredService := &MockCredentialService{}

	testConfig := &config.Config{
		Database: &config.DatabaseConfig{Host: "localhost", Port: 5432},
	}

	service := &Service{
		repo:        mockRepo,
		config:      testConfig,
		logger:      logger.New("test-service"),
		metrics:     metrics.GetGlobal(),
		validator:   mockValidator,
		executor:    mockExecutor,
		templateSvc: mockTemplateService,
		credSvc:     mockCredService,
	}

	ctx := context.Background()
	userID := uuid.New().String()
	teamID := uuid.New().String()

	t.Run("GetByID successful", func(t *testing.T) {
		workflowID := uuid.New().String()
		expectedWorkflow := NewWorkflow("Test Workflow", teamID, userID)
		expectedWorkflow.ID = workflowID

		mockRepo.On("GetByIDWithDetails", ctx, workflowID).Return(expectedWorkflow, nil)
		mockValidator.On("ValidatePermissions", ctx, userID, teamID, workflowID, "read").Return(nil)

		result, err := service.GetByID(ctx, workflowID, userID)

		require.NoError(t, err)
		assert.Equal(t, workflowID, result.ID)
		assert.Equal(t, "Test Workflow", result.Name)

		mockRepo.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})

	t.Run("GetByID not found", func(t *testing.T) {
		workflowID := uuid.New().String()

		mockRepo.On("GetByIDWithDetails", ctx, workflowID).Return((*Workflow)(nil), nil)

		result, err := service.GetByID(ctx, workflowID, userID)

		assert.Error(t, err)
		assert.Nil(t, result)
		
		appErr := errors.GetAppError(err)
		require.NotNil(t, appErr)
		assert.Equal(t, errors.ErrorTypeNotFound, appErr.Type)

		mockRepo.AssertExpectations(t)
	})

	t.Run("hasDefinitionChanged", func(t *testing.T) {
		old := &Workflow{
			Nodes: []Node{{ID: "1", Name: "Node 1"}},
			Config: WorkflowConfig{Timeout: 60},
		}

		// Same workflow should not have changed
		new1 := &Workflow{
			Nodes: []Node{{ID: "1", Name: "Node 1"}},
			Config: WorkflowConfig{Timeout: 60},
		}
		assert.False(t, service.hasDefinitionChanged(old, new1))

		// Different nodes should have changed
		new2 := &Workflow{
			Nodes: []Node{{ID: "2", Name: "Node 2"}},
			Config: WorkflowConfig{Timeout: 60},
		}
		assert.True(t, service.hasDefinitionChanged(old, new2))
	})
}

func TestConcurrentExecutionLimits(t *testing.T) {
	mockRepo := &MockWorkflowRepository{}
	service := &Service{repo: mockRepo}

	ctx := context.Background()
	workflowID := uuid.New().String()
	maxConcurrent := 2

	t.Run("within limits", func(t *testing.T) {
		mockRepo.On("ListExecutions", ctx, mock.MatchedBy(func(filter *ExecutionListFilter) bool {
			return *filter.WorkflowID == workflowID && filter.Limit == maxConcurrent+1
		})).Return([]*WorkflowExecution{{ID: "1"}}, int64(1), nil)

		err := service.checkConcurrentExecutionLimits(ctx, workflowID, maxConcurrent)
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
	})

	t.Run("exceeds limits", func(t *testing.T) {
		mockRepo = &MockWorkflowRepository{}
		service.repo = mockRepo

		runningExecutions := []*WorkflowExecution{{ID: "1"}, {ID: "2"}}
		mockRepo.On("ListExecutions", ctx, mock.MatchedBy(func(filter *ExecutionListFilter) bool {
			return *filter.WorkflowID == workflowID && filter.Limit == maxConcurrent+1
		})).Return(runningExecutions, int64(2), nil)

		err := service.checkConcurrentExecutionLimits(ctx, workflowID, maxConcurrent)
		assert.Error(t, err)
		
		appErr := errors.GetAppError(err)
		require.NotNil(t, appErr)
		assert.Equal(t, errors.ErrorTypeValidation, appErr.Type)
		assert.Equal(t, errors.CodeRateLimit, appErr.Code)

		mockRepo.AssertExpectations(t)
	})
}