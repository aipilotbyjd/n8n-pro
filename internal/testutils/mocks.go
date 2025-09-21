package testutils

import (
	"context"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/logger"

	"github.com/stretchr/testify/mock"
)

// MockWorkflowRepository is a mock implementation of workflows.Repository
type MockWorkflowRepository struct {
	mock.Mock
}

func (m *MockWorkflowRepository) Create(ctx context.Context, workflow *workflows.Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetByID(ctx context.Context, id string) (*workflows.Workflow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

func (m *MockWorkflowRepository) GetByIDWithDetails(ctx context.Context, id string) (*workflows.Workflow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

func (m *MockWorkflowRepository) Update(ctx context.Context, workflow *workflows.Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockWorkflowRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) List(ctx context.Context, filter *workflows.WorkflowListFilter) ([]*workflows.Workflow, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*workflows.Workflow), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) CreateExecution(ctx context.Context, execution *workflows.WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetExecutionByID(ctx context.Context, id string) (*workflows.WorkflowExecution, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*workflows.WorkflowExecution), args.Error(1)
}

func (m *MockWorkflowRepository) UpdateExecution(ctx context.Context, execution *workflows.WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockWorkflowRepository) ListExecutions(ctx context.Context, filter *workflows.ExecutionListFilter) ([]*workflows.WorkflowExecution, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*workflows.WorkflowExecution), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) DeleteExecution(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) CreateVersion(ctx context.Context, version *workflows.WorkflowVersion) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetVersions(ctx context.Context, workflowID string) ([]*workflows.WorkflowVersion, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*workflows.WorkflowVersion), args.Error(1)
}

func (m *MockWorkflowRepository) GetVersionByNumber(ctx context.Context, workflowID string, version int) (*workflows.WorkflowVersion, error) {
	args := m.Called(ctx, workflowID, version)
	return args.Get(0).(*workflows.WorkflowVersion), args.Error(1)
}

func (m *MockWorkflowRepository) CreateTemplate(ctx context.Context, template *workflows.WorkflowTemplate) error {
	args := m.Called(ctx, template)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetTemplateByID(ctx context.Context, id string) (*workflows.WorkflowTemplate, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*workflows.WorkflowTemplate), args.Error(1)
}

func (m *MockWorkflowRepository) ListTemplates(ctx context.Context, filter *workflows.TemplateListFilter) ([]*workflows.WorkflowTemplate, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*workflows.WorkflowTemplate), args.Get(1).(int64), args.Error(2)
}

func (m *MockWorkflowRepository) CreateShare(ctx context.Context, share *workflows.WorkflowShare) error {
	args := m.Called(ctx, share)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetShares(ctx context.Context, workflowID string) ([]*workflows.WorkflowShare, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*workflows.WorkflowShare), args.Error(1)
}

func (m *MockWorkflowRepository) DeleteShare(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetExecutionSummary(ctx context.Context, workflowID string, period string) (*workflows.ExecutionSummary, error) {
	args := m.Called(ctx, workflowID, period)
	return args.Get(0).(*workflows.ExecutionSummary), args.Error(1)
}

func (m *MockWorkflowRepository) GetWorkflowMetrics(ctx context.Context, workflowID string, period string) (*workflows.WorkflowMetrics, error) {
	args := m.Called(ctx, workflowID, period)
	return args.Get(0).(*workflows.WorkflowMetrics), args.Error(1)
}

func (m *MockWorkflowRepository) GetTeamMetrics(ctx context.Context, teamID string, period string) (*workflows.TeamMetrics, error) {
	args := m.Called(ctx, teamID, period)
	return args.Get(0).(*workflows.TeamMetrics), args.Error(1)
}

func (m *MockWorkflowRepository) CreateTag(ctx context.Context, tag *workflows.Tag) error {
	args := m.Called(ctx, tag)
	return args.Error(0)
}

func (m *MockWorkflowRepository) GetTagsByWorkflow(ctx context.Context, workflowID string) ([]*workflows.Tag, error) {
	args := m.Called(ctx, workflowID)
	return args.Get(0).([]*workflows.Tag), args.Error(1)
}

func (m *MockWorkflowRepository) ListTags(ctx context.Context, teamID string) ([]*workflows.Tag, error) {
	args := m.Called(ctx, teamID)
	return args.Get(0).([]*workflows.Tag), args.Error(1)
}

// MockValidator is a mock implementation of workflows.Validator
type MockValidator struct {
	mock.Mock
}

func (m *MockValidator) ValidateWorkflow(ctx context.Context, workflow *workflows.Workflow) error {
	args := m.Called(ctx, workflow)
	return args.Error(0)
}

func (m *MockValidator) ValidateExecution(ctx context.Context, execution *workflows.WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func (m *MockValidator) ValidatePermissions(ctx context.Context, userID, teamID, workflowID string, action string) error {
	args := m.Called(ctx, userID, teamID, workflowID, action)
	return args.Error(0)
}

// MockExecutor is a mock implementation of workflows.Executor
type MockExecutor struct {
	mock.Mock
}

func (m *MockExecutor) Execute(ctx context.Context, execution *workflows.WorkflowExecution) error {
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

func (m *MockExecutor) Retry(ctx context.Context, executionID string) (*workflows.WorkflowExecution, error) {
	args := m.Called(ctx, executionID)
	return args.Get(0).(*workflows.WorkflowExecution), args.Error(1)
}

// MockTemplateService is a mock implementation of workflows.TemplateService
type MockTemplateService struct {
	mock.Mock
}

func (m *MockTemplateService) CreateFromWorkflow(ctx context.Context, workflowID string, template *workflows.WorkflowTemplate) (*workflows.WorkflowTemplate, error) {
	args := m.Called(ctx, workflowID, template)
	return args.Get(0).(*workflows.WorkflowTemplate), args.Error(1)
}

func (m *MockTemplateService) InstantiateTemplate(ctx context.Context, templateID, teamID, ownerID string) (*workflows.Workflow, error) {
	args := m.Called(ctx, templateID, teamID, ownerID)
	return args.Get(0).(*workflows.Workflow), args.Error(1)
}

// MockCredentialService is a mock implementation of workflows.CredentialService
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

// MockAuthRepository is a mock implementation of auth.Repository
type MockAuthRepository struct {
	mock.Mock
}

func (m *MockAuthRepository) CreateUser(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthRepository) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthRepository) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthRepository) UpdateUser(ctx context.Context, user *auth.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthRepository) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockAuthRepository) ListUsers(ctx context.Context, teamID string) ([]*auth.User, error) {
	args := m.Called(ctx, teamID)
	return args.Get(0).([]*auth.User), args.Error(1)
}

// MockLogger is a mock implementation of logger.Logger
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(message string, args ...interface{}) {
	m.Called(message, args)
}

func (m *MockLogger) Info(message string, args ...interface{}) {
	m.Called(message, args)
}

func (m *MockLogger) Warn(message string, args ...interface{}) {
	m.Called(message, args)
}

func (m *MockLogger) Error(message string, args ...interface{}) {
	m.Called(message, args)
}

func (m *MockLogger) Fatal(message string, args ...interface{}) {
	m.Called(message, args)
}

func (m *MockLogger) DebugContext(ctx context.Context, message string, args ...interface{}) {
	m.Called(ctx, message, args)
}

func (m *MockLogger) InfoContext(ctx context.Context, message string, args ...interface{}) {
	m.Called(ctx, message, args)
}

func (m *MockLogger) WarnContext(ctx context.Context, message string, args ...interface{}) {
	m.Called(ctx, message, args)
}

func (m *MockLogger) ErrorContext(ctx context.Context, message string, args ...interface{}) {
	m.Called(ctx, message, args)
}

func (m *MockLogger) FatalContext(ctx context.Context, message string, args ...interface{}) {
	m.Called(ctx, message, args)
}

func (m *MockLogger) With(args ...interface{}) logger.Logger {
	mockArgs := m.Called(args)
	return mockArgs.Get(0).(logger.Logger)
}

// MockNodeExecutor simulates node execution
type MockNodeExecutor struct {
	mock.Mock
}

func (m *MockNodeExecutor) ExecuteNode(ctx context.Context, node *workflows.Node, inputData map[string]interface{}) (map[string]interface{}, error) {
	args := m.Called(ctx, node, inputData)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockNodeExecutor) ValidateNodeConfig(node *workflows.Node) error {
	args := m.Called(node)
	return args.Error(0)
}

// MockWebhookService simulates webhook operations
type MockWebhookService struct {
	mock.Mock
}

func (m *MockWebhookService) RegisterWebhook(ctx context.Context, workflowID, nodeID, path string) (string, error) {
	args := m.Called(ctx, workflowID, nodeID, path)
	return args.String(0), args.Error(1)
}

func (m *MockWebhookService) UnregisterWebhook(ctx context.Context, webhookID string) error {
	args := m.Called(ctx, webhookID)
	return args.Error(0)
}

func (m *MockWebhookService) TriggerWebhook(ctx context.Context, path string, data map[string]interface{}) error {
	args := m.Called(ctx, path, data)
	return args.Error(0)
}

// MockSchedulerService simulates scheduling operations
type MockSchedulerService struct {
	mock.Mock
}

func (m *MockSchedulerService) ScheduleWorkflow(ctx context.Context, workflowID string, cronExpression string) error {
	args := m.Called(ctx, workflowID, cronExpression)
	return args.Error(0)
}

func (m *MockSchedulerService) UnscheduleWorkflow(ctx context.Context, workflowID string) error {
	args := m.Called(ctx, workflowID)
	return args.Error(0)
}

func (m *MockSchedulerService) UpdateSchedule(ctx context.Context, workflowID string, cronExpression string) error {
	args := m.Called(ctx, workflowID, cronExpression)
	return args.Error(0)
}

// MockNotificationService simulates notification operations
type MockNotificationService struct {
	mock.Mock
}

func (m *MockNotificationService) SendNotification(ctx context.Context, notification *NotificationRequest) error {
	args := m.Called(ctx, notification)
	return args.Error(0)
}

func (m *MockNotificationService) SendSlackMessage(ctx context.Context, channel, message string) error {
	args := m.Called(ctx, channel, message)
	return args.Error(0)
}

func (m *MockNotificationService) SendEmail(ctx context.Context, to []string, subject, body string) error {
	args := m.Called(ctx, to, subject, body)
	return args.Error(0)
}

// NotificationRequest represents a notification request
type NotificationRequest struct {
	Type      string                 `json:"type"`
	Recipient string                 `json:"recipient"`
	Subject   string                 `json:"subject"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data"`
}

// TestWorkflowExecutor provides a test implementation of workflow execution
type TestWorkflowExecutor struct {
	ExecutionResults map[string]*workflows.WorkflowExecution
	ExecutionErrors  map[string]error
	ExecutionDelay   time.Duration
}

func NewTestWorkflowExecutor() *TestWorkflowExecutor {
	return &TestWorkflowExecutor{
		ExecutionResults: make(map[string]*workflows.WorkflowExecution),
		ExecutionErrors:  make(map[string]error),
		ExecutionDelay:   100 * time.Millisecond,
	}
}

func (t *TestWorkflowExecutor) Execute(ctx context.Context, execution *workflows.WorkflowExecution) error {
	if t.ExecutionDelay > 0 {
		time.Sleep(t.ExecutionDelay)
	}

	if err, exists := t.ExecutionErrors[execution.ID]; exists {
		return err
	}

	// Simulate successful execution
	execution.Status = workflows.ExecutionStatusCompleted
	now := time.Now()
	execution.EndTime = &now
	execution.OutputData = map[string]interface{}{
		"result": "success",
		"processed_nodes": len(execution.NodeExecutions),
	}

	if result, exists := t.ExecutionResults[execution.ID]; exists {
		*execution = *result
	}

	return nil
}

func (t *TestWorkflowExecutor) Cancel(ctx context.Context, executionID string) error {
	if err, exists := t.ExecutionErrors[executionID]; exists {
		return err
	}
	return nil
}

func (t *TestWorkflowExecutor) Pause(ctx context.Context, executionID string) error {
	if err, exists := t.ExecutionErrors[executionID]; exists {
		return err
	}
	return nil
}

func (t *TestWorkflowExecutor) Resume(ctx context.Context, executionID string) error {
	if err, exists := t.ExecutionErrors[executionID]; exists {
		return err
	}
	return nil
}

func (t *TestWorkflowExecutor) Retry(ctx context.Context, executionID string) (*workflows.WorkflowExecution, error) {
	if err, exists := t.ExecutionErrors[executionID]; exists {
		return nil, err
	}

	if result, exists := t.ExecutionResults[executionID]; exists {
		return result, nil
	}

	// Return a default retry execution
	return &workflows.WorkflowExecution{
		ID:         executionID + "-retry",
		Status:     workflows.ExecutionStatusPending,
		RetryCount: 1,
	}, nil
}

// SetExecutionResult sets a predefined result for an execution
func (t *TestWorkflowExecutor) SetExecutionResult(executionID string, result *workflows.WorkflowExecution) {
	t.ExecutionResults[executionID] = result
}

// SetExecutionError sets a predefined error for an execution
func (t *TestWorkflowExecutor) SetExecutionError(executionID string, err error) {
	t.ExecutionErrors[executionID] = err
}

// ClearResults clears all execution results and errors
func (t *TestWorkflowExecutor) ClearResults() {
	t.ExecutionResults = make(map[string]*workflows.WorkflowExecution)
	t.ExecutionErrors = make(map[string]error)
}