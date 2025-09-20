package state

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/google/uuid"
)

// ExecutionStatus represents the current state of an execution
type ExecutionStatus string

const (
	ExecutionStatusQueued    ExecutionStatus = "queued"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCanceled  ExecutionStatus = "canceled"
	ExecutionStatusPaused    ExecutionStatus = "paused"
	ExecutionStatusRetrying  ExecutionStatus = "retrying"
	ExecutionStatusWaiting   ExecutionStatus = "waiting"
	ExecutionStatusTimedOut  ExecutionStatus = "timed_out"
	ExecutionStatusSkipped   ExecutionStatus = "skipped"
)

// NodeExecutionStatus represents the status of individual node executions
type NodeExecutionStatus string

const (
	NodeExecutionStatusPending   NodeExecutionStatus = "pending"
	NodeExecutionStatusRunning   NodeExecutionStatus = "running"
	NodeExecutionStatusCompleted NodeExecutionStatus = "completed"
	NodeExecutionStatusFailed    NodeExecutionStatus = "failed"
	NodeExecutionStatusSkipped   NodeExecutionStatus = "skipped"
	NodeExecutionStatusRetrying  NodeExecutionStatus = "retrying"
	NodeExecutionStatusCanceled  NodeExecutionStatus = "canceled"
)

// ExecutionTrigger represents what triggered the execution
type ExecutionTrigger string

const (
	ExecutionTriggerManual     ExecutionTrigger = "manual"
	ExecutionTriggerScheduled  ExecutionTrigger = "scheduled"
	ExecutionTriggerWebhook    ExecutionTrigger = "webhook"
	ExecutionTriggerAPI        ExecutionTrigger = "api"
	ExecutionTriggerRetry      ExecutionTrigger = "retry"
	ExecutionTriggerTest       ExecutionTrigger = "test"
	ExecutionTriggerProduction ExecutionTrigger = "production"
)

// ExecutionMode represents how the execution should run
type ExecutionMode string

const (
	ExecutionModeSync  ExecutionMode = "sync"
	ExecutionModeAsync ExecutionMode = "async"
)

// NodeExecution represents the execution state of a single node
type NodeExecution struct {
	NodeID     string              `json:"node_id"`
	NodeName   string              `json:"node_name"`
	NodeType   string              `json:"node_type"`
	Status     NodeExecutionStatus `json:"status"`
	StartTime  *time.Time          `json:"start_time"`
	EndTime    *time.Time          `json:"end_time"`
	Duration   time.Duration       `json:"duration"`
	RetryCount int                 `json:"retry_count"`
	MaxRetries int                 `json:"max_retries"`
	Error      *ExecutionError     `json:"error,omitempty"`
	InputData  json.RawMessage     `json:"input_data,omitempty"`
	OutputData json.RawMessage     `json:"output_data,omitempty"`
	Metadata   map[string]string   `json:"metadata,omitempty"`
}

// ExecutionError represents an error that occurred during execution
type ExecutionError struct {
	Type      string            `json:"type"`
	Message   string            `json:"message"`
	Details   string            `json:"details,omitempty"`
	NodeID    string            `json:"node_id,omitempty"`
	Code      string            `json:"code,omitempty"`
	Stack     string            `json:"stack,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Retryable bool              `json:"retryable"`
}

// ExecutionProgress represents the progress of an execution
type ExecutionProgress struct {
	TotalNodes      int                       `json:"total_nodes"`
	CompletedNodes  int                       `json:"completed_nodes"`
	FailedNodes     int                       `json:"failed_nodes"`
	SkippedNodes    int                       `json:"skipped_nodes"`
	RunningNodes    int                       `json:"running_nodes"`
	PendingNodes    int                       `json:"pending_nodes"`
	PercentComplete float64                   `json:"percent_complete"`
	CurrentNodes    []string                  `json:"current_nodes"`
	NodeExecutions  map[string]*NodeExecution `json:"node_executions"`
	LastUpdated     time.Time                 `json:"last_updated"`
}

// ExecutionContext contains context information for an execution
type ExecutionContext struct {
	WorkflowID        string                 `json:"workflow_id"`
	WorkflowName      string                 `json:"workflow_name"`
	WorkflowVersion   int                    `json:"workflow_version"`
	ExecutionID       string                 `json:"execution_id"`
	ParentExecutionID string                 `json:"parent_execution_id,omitempty"`
	UserID            string                 `json:"user_id"`
	TeamID            string                 `json:"team_id"`
	TriggerType       ExecutionTrigger       `json:"trigger_type"`
	TriggerData       json.RawMessage        `json:"trigger_data,omitempty"`
	Mode              ExecutionMode          `json:"mode"`
	Variables         map[string]interface{} `json:"variables,omitempty"`
	Settings          map[string]interface{} `json:"settings,omitempty"`
	Timeout           time.Duration          `json:"timeout"`
	MaxRetries        int                    `json:"max_retries"`
	Tags              []string               `json:"tags,omitempty"`
}

// ExecutionState represents the complete state of a workflow execution
type ExecutionState struct {
	ID           string             `json:"id"`
	Context      *ExecutionContext  `json:"context"`
	Status       ExecutionStatus    `json:"status"`
	Progress     *ExecutionProgress `json:"progress"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      *time.Time         `json:"end_time"`
	Duration     time.Duration      `json:"duration"`
	TotalRetries int                `json:"total_retries"`
	LastRetryAt  *time.Time         `json:"last_retry_at,omitempty"`
	PausedAt     *time.Time         `json:"paused_at,omitempty"`
	ResumedAt    *time.Time         `json:"resumed_at,omitempty"`
	CanceledAt   *time.Time         `json:"canceled_at,omitempty"`
	Error        *ExecutionError    `json:"error,omitempty"`
	FinalData    json.RawMessage    `json:"final_data,omitempty"`
	Metadata     map[string]string  `json:"metadata"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`

	// Internal state management
	mutex        sync.RWMutex  `json:"-"`
	eventChannel chan *Event   `json:"-"`
	subscribers  []Subscriber  `json:"-"`
	logger       logger.Logger `json:"-"`
}

// Event represents a state change event
type Event struct {
	Type        string                 `json:"type"`
	ExecutionID string                 `json:"execution_id"`
	NodeID      string                 `json:"node_id,omitempty"`
	Status      string                 `json:"status"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Subscriber is a function that handles state change events
type Subscriber func(*Event)

// Manager handles execution state management
type Manager struct {
	states      map[string]*ExecutionState
	mutex       sync.RWMutex
	logger      logger.Logger
	subscribers []Subscriber
	persistence PersistenceLayer
}

// PersistenceLayer defines interface for persisting execution state
type PersistenceLayer interface {
	Save(ctx context.Context, state *ExecutionState) error
	Load(ctx context.Context, executionID string) (*ExecutionState, error)
	Delete(ctx context.Context, executionID string) error
	List(ctx context.Context, filter *StateFilter) ([]*ExecutionState, error)
	Update(ctx context.Context, executionID string, updates map[string]interface{}) error
}

// StateFilter represents filters for querying execution states
type StateFilter struct {
	WorkflowID  string
	UserID      string
	TeamID      string
	Status      ExecutionStatus
	TriggerType ExecutionTrigger
	StartTime   *time.Time
	EndTime     *time.Time
	Limit       int
	Offset      int
}

// Config holds configuration for state manager
type Config struct {
	MaxStatesInMemory int           `json:"max_states_in_memory"`
	StateTimeout      time.Duration `json:"state_timeout"`
	EnablePersistence bool          `json:"enable_persistence"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxStatesInMemory: 1000,
		StateTimeout:      24 * time.Hour,
		EnablePersistence: true,
		CleanupInterval:   1 * time.Hour,
	}
}

// NewManager creates a new state manager
func NewManager(config *Config, persistence PersistenceLayer, log logger.Logger) *Manager {
	if config == nil {
		config = DefaultConfig()
	}

	manager := &Manager{
		states:      make(map[string]*ExecutionState),
		logger:      log,
		subscribers: make([]Subscriber, 0),
		persistence: persistence,
	}

	// Start cleanup routine
	go manager.startCleanupRoutine(config.CleanupInterval)

	return manager
}

// CreateExecution creates a new execution state
func (m *Manager) CreateExecution(ctx context.Context, execCtx *ExecutionContext) (*ExecutionState, error) {
	if execCtx.ExecutionID == "" {
		execCtx.ExecutionID = uuid.New().String()
	}

	now := time.Now()
	state := &ExecutionState{
		ID:      execCtx.ExecutionID,
		Context: execCtx,
		Status:  ExecutionStatusQueued,
		Progress: &ExecutionProgress{
			NodeExecutions: make(map[string]*NodeExecution),
			LastUpdated:    now,
		},
		StartTime:    now,
		Metadata:     make(map[string]string),
		CreatedAt:    now,
		UpdatedAt:    now,
		eventChannel: make(chan *Event, 100),
		subscribers:  make([]Subscriber, 0),
		logger:       m.logger.With("execution_id", execCtx.ExecutionID),
	}

	// Start event processing for this state
	go state.processEvents()

	// Store in memory
	m.mutex.Lock()
	m.states[state.ID] = state
	m.mutex.Unlock()

	// Persist if enabled
	if m.persistence != nil {
		if err := m.persistence.Save(ctx, state); err != nil {
			m.logger.Error("Failed to persist execution state", "error", err, "execution_id", state.ID)
		}
	}

	// Notify subscribers
	m.publishEvent(&Event{
		Type:        "execution_created",
		ExecutionID: state.ID,
		Status:      string(state.Status),
		Timestamp:   now,
	})

	m.logger.Info("Execution state created",
		"execution_id", state.ID,
		"workflow_id", execCtx.WorkflowID,
		"user_id", execCtx.UserID,
	)

	return state, nil
}

// GetExecution retrieves an execution state
func (m *Manager) GetExecution(ctx context.Context, executionID string) (*ExecutionState, error) {
	// Try memory first
	m.mutex.RLock()
	state, exists := m.states[executionID]
	m.mutex.RUnlock()

	if exists {
		return state, nil
	}

	// Try persistence
	if m.persistence != nil {
		state, err := m.persistence.Load(ctx, executionID)
		if err != nil {
			return nil, fmt.Errorf("failed to load execution state: %w", err)
		}

		// Add to memory cache
		m.mutex.Lock()
		m.states[executionID] = state
		m.mutex.Unlock()

		return state, nil
	}

	return nil, errors.NewNotFoundError("Execution not found")
}

// UpdateStatus updates the execution status
func (m *Manager) UpdateStatus(ctx context.Context, executionID string, status ExecutionStatus) error {
	state, err := m.GetExecution(ctx, executionID)
	if err != nil {
		return err
	}

	return state.UpdateStatus(status)
}

// UpdateNodeStatus updates the status of a specific node execution
func (m *Manager) UpdateNodeStatus(ctx context.Context, executionID, nodeID string, status NodeExecutionStatus) error {
	state, err := m.GetExecution(ctx, executionID)
	if err != nil {
		return err
	}

	return state.UpdateNodeStatus(nodeID, status)
}

// SetNodeData sets input/output data for a node
func (m *Manager) SetNodeData(ctx context.Context, executionID, nodeID string, inputData, outputData json.RawMessage) error {
	state, err := m.GetExecution(ctx, executionID)
	if err != nil {
		return err
	}

	return state.SetNodeData(nodeID, inputData, outputData)
}

// Subscribe adds a subscriber for state change events
func (m *Manager) Subscribe(subscriber Subscriber) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.subscribers = append(m.subscribers, subscriber)
}

// publishEvent publishes an event to all subscribers
func (m *Manager) publishEvent(event *Event) {
	m.mutex.RLock()
	subscribers := make([]Subscriber, len(m.subscribers))
	copy(subscribers, m.subscribers)
	m.mutex.RUnlock()

	for _, subscriber := range subscribers {
		go func(sub Subscriber) {
			defer func() {
				if r := recover(); r != nil {
					m.logger.Error("Panic in event subscriber", "error", r)
				}
			}()
			sub(event)
		}(subscriber)
	}
}

// startCleanupRoutine starts the background cleanup routine
func (m *Manager) startCleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

// cleanup removes old execution states from memory
func (m *Manager) cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for id, state := range m.states {
		if state.UpdatedAt.Before(cutoff) {
			delete(m.states, id)
			m.logger.Debug("Cleaned up old execution state", "execution_id", id)
		}
	}
}

// ExecutionState methods

// UpdateStatus updates the execution status with proper state transitions
func (s *ExecutionState) UpdateStatus(status ExecutionStatus) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate state transition
	if !s.isValidTransition(s.Status, status) {
		return errors.NewValidationError(fmt.Sprintf("Invalid status transition from %s to %s", s.Status, status))
	}

	oldStatus := s.Status
	s.Status = status
	s.UpdatedAt = time.Now()

	// Handle specific status changes
	switch status {
	case ExecutionStatusRunning:
		if s.StartTime.IsZero() {
			s.StartTime = time.Now()
		}
	case ExecutionStatusCompleted, ExecutionStatusFailed, ExecutionStatusCanceled, ExecutionStatusTimedOut:
		if s.EndTime == nil {
			now := time.Now()
			s.EndTime = &now
			s.Duration = now.Sub(s.StartTime)
		}
	case ExecutionStatusPaused:
		now := time.Now()
		s.PausedAt = &now
	case ExecutionStatusCanceled:
		now := time.Now()
		s.CanceledAt = &now
	}

	// Publish event
	s.publishEvent(&Event{
		Type:        "status_changed",
		ExecutionID: s.ID,
		Status:      string(status),
		Data: map[string]interface{}{
			"old_status": string(oldStatus),
			"new_status": string(status),
		},
		Timestamp: time.Now(),
	})

	s.logger.Info("Execution status updated",
		"old_status", oldStatus,
		"new_status", status,
	)

	return nil
}

// UpdateNodeStatus updates the status of a specific node
func (s *ExecutionState) UpdateNodeStatus(nodeID string, status NodeExecutionStatus) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	nodeExec, exists := s.Progress.NodeExecutions[nodeID]
	if !exists {
		nodeExec = &NodeExecution{
			NodeID: nodeID,
			Status: NodeExecutionStatusPending,
		}
		s.Progress.NodeExecutions[nodeID] = nodeExec
	}

	oldStatus := nodeExec.Status
	nodeExec.Status = status

	now := time.Now()
	switch status {
	case NodeExecutionStatusRunning:
		if nodeExec.StartTime == nil {
			nodeExec.StartTime = &now
		}
	case NodeExecutionStatusCompleted, NodeExecutionStatusFailed, NodeExecutionStatusSkipped:
		if nodeExec.EndTime == nil {
			nodeExec.EndTime = &now
			if nodeExec.StartTime != nil {
				nodeExec.Duration = now.Sub(*nodeExec.StartTime)
			}
		}
	}

	// Update progress
	s.updateProgress()

	// Publish event
	s.publishEvent(&Event{
		Type:        "node_status_changed",
		ExecutionID: s.ID,
		NodeID:      nodeID,
		Status:      string(status),
		Data: map[string]interface{}{
			"old_status": string(oldStatus),
			"new_status": string(status),
		},
		Timestamp: now,
	})

	return nil
}

// SetNodeData sets input/output data for a node
func (s *ExecutionState) SetNodeData(nodeID string, inputData, outputData json.RawMessage) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	nodeExec, exists := s.Progress.NodeExecutions[nodeID]
	if !exists {
		nodeExec = &NodeExecution{
			NodeID: nodeID,
			Status: NodeExecutionStatusPending,
		}
		s.Progress.NodeExecutions[nodeID] = nodeExec
	}

	if inputData != nil {
		nodeExec.InputData = inputData
	}
	if outputData != nil {
		nodeExec.OutputData = outputData
	}

	return nil
}

// SetError sets an execution error
func (s *ExecutionState) SetError(err *ExecutionError) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Error = err
	if s.Status != ExecutionStatusFailed {
		s.Status = ExecutionStatusFailed
	}

	s.publishEvent(&Event{
		Type:        "error_occurred",
		ExecutionID: s.ID,
		NodeID:      err.NodeID,
		Status:      string(s.Status),
		Data: map[string]interface{}{
			"error_type":    err.Type,
			"error_message": err.Message,
		},
		Timestamp: time.Now(),
	})
}

// updateProgress recalculates execution progress
func (s *ExecutionState) updateProgress() {
	total := len(s.Progress.NodeExecutions)
	if total == 0 {
		return
	}

	completed := 0
	failed := 0
	skipped := 0
	running := 0
	pending := 0
	currentNodes := make([]string, 0)

	for nodeID, nodeExec := range s.Progress.NodeExecutions {
		switch nodeExec.Status {
		case NodeExecutionStatusCompleted:
			completed++
		case NodeExecutionStatusFailed:
			failed++
		case NodeExecutionStatusSkipped:
			skipped++
		case NodeExecutionStatusRunning:
			running++
			currentNodes = append(currentNodes, nodeID)
		case NodeExecutionStatusPending:
			pending++
		}
	}

	s.Progress.TotalNodes = total
	s.Progress.CompletedNodes = completed
	s.Progress.FailedNodes = failed
	s.Progress.SkippedNodes = skipped
	s.Progress.RunningNodes = running
	s.Progress.PendingNodes = pending
	s.Progress.CurrentNodes = currentNodes
	s.Progress.PercentComplete = float64(completed+failed+skipped) / float64(total) * 100
	s.Progress.LastUpdated = time.Now()
}

// isValidTransition checks if a status transition is valid
func (s *ExecutionState) isValidTransition(from, to ExecutionStatus) bool {
	validTransitions := map[ExecutionStatus][]ExecutionStatus{
		ExecutionStatusQueued: {ExecutionStatusRunning, ExecutionStatusCanceled},
		ExecutionStatusRunning: {ExecutionStatusCompleted, ExecutionStatusFailed, ExecutionStatusCanceled,
			ExecutionStatusPaused, ExecutionStatusRetrying, ExecutionStatusTimedOut},
		ExecutionStatusPaused:   {ExecutionStatusRunning, ExecutionStatusCanceled},
		ExecutionStatusRetrying: {ExecutionStatusRunning, ExecutionStatusFailed, ExecutionStatusCanceled},
		ExecutionStatusWaiting:  {ExecutionStatusRunning, ExecutionStatusCanceled, ExecutionStatusTimedOut},
	}

	transitions, exists := validTransitions[from]
	if !exists {
		return false
	}

	for _, validTo := range transitions {
		if validTo == to {
			return true
		}
	}
	return false
}

// publishEvent publishes an event for this execution
func (s *ExecutionState) publishEvent(event *Event) {
	select {
	case s.eventChannel <- event:
	default:
		// Channel is full, log warning
		s.logger.Warn("Event channel full, dropping event", "event_type", event.Type)
	}
}

// processEvents processes events for this execution state
func (s *ExecutionState) processEvents() {
	for event := range s.eventChannel {
		for _, subscriber := range s.subscribers {
			go func(sub Subscriber, evt *Event) {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("Panic in event subscriber", "error", r)
					}
				}()
				sub(evt)
			}(subscriber, event)
		}
	}
}

// Subscribe adds a subscriber for events on this execution
func (s *ExecutionState) Subscribe(subscriber Subscriber) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.subscribers = append(s.subscribers, subscriber)
}

// GetSummary returns a summary of the execution state
func (s *ExecutionState) GetSummary() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	summary := map[string]interface{}{
		"id":               s.ID,
		"status":           string(s.Status),
		"workflow_id":      s.Context.WorkflowID,
		"user_id":          s.Context.UserID,
		"trigger_type":     string(s.Context.TriggerType),
		"start_time":       s.StartTime,
		"duration":         s.Duration,
		"total_nodes":      s.Progress.TotalNodes,
		"completed_nodes":  s.Progress.CompletedNodes,
		"failed_nodes":     s.Progress.FailedNodes,
		"percent_complete": s.Progress.PercentComplete,
	}

	if s.EndTime != nil {
		summary["end_time"] = *s.EndTime
	}

	if s.Error != nil {
		summary["error"] = s.Error
	}

	return summary
}
