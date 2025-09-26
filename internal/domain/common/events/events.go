package events

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DomainEvent represents something that happened in the domain that you want other parts of the system to be aware of
type DomainEvent interface {
	GetID() string
	GetType() string
	GetAggregateID() string
	GetAggregateType() string
	GetOccurredAt() time.Time
	GetData() map[string]interface{}
	GetVersion() int
}

// BaseDomainEvent provides a base implementation for domain events
type BaseDomainEvent struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	AggregateID   string                 `json:"aggregate_id"`
	AggregateType string                 `json:"aggregate_type"`
	OccurredAt    time.Time              `json:"occurred_at"`
	Data          map[string]interface{} `json:"data"`
	Version       int                    `json:"version"`
}

func (e *BaseDomainEvent) GetID() string                        { return e.ID }
func (e *BaseDomainEvent) GetType() string                      { return e.Type }
func (e *BaseDomainEvent) GetAggregateID() string               { return e.AggregateID }
func (e *BaseDomainEvent) GetAggregateType() string             { return e.AggregateType }
func (e *BaseDomainEvent) GetOccurredAt() time.Time             { return e.OccurredAt }
func (e *BaseDomainEvent) GetData() map[string]interface{}      { return e.Data }
func (e *BaseDomainEvent) GetVersion() int                      { return e.Version }

// NewBaseDomainEvent creates a new base domain event
func NewBaseDomainEvent(eventType, aggregateID, aggregateType string, data map[string]interface{}) *BaseDomainEvent {
	return &BaseDomainEvent{
		ID:            uuid.New().String(),
		Type:          eventType,
		AggregateID:   aggregateID,
		AggregateType: aggregateType,
		OccurredAt:    time.Now().UTC(),
		Data:          data,
		Version:       1,
	}
}

// EventHandler handles domain events
type EventHandler interface {
	Handle(ctx context.Context, event DomainEvent) error
	CanHandle(eventType string) bool
}

// EventPublisher publishes domain events
type EventPublisher interface {
	Publish(ctx context.Context, events ...DomainEvent) error
}

// EventStore stores domain events
type EventStore interface {
	SaveEvents(ctx context.Context, aggregateID string, events []DomainEvent, expectedVersion int) error
	GetEvents(ctx context.Context, aggregateID string) ([]DomainEvent, error)
}

// Common event types
const (
	UserCreated     = "user.created"
	UserUpdated     = "user.updated"
	UserDeleted     = "user.deleted"
	UserActivated   = "user.activated"
	UserDeactivated = "user.deactivated"

	WorkflowCreated   = "workflow.created"
	WorkflowUpdated   = "workflow.updated"
	WorkflowDeleted   = "workflow.deleted"
	WorkflowExecuted  = "workflow.executed"
	WorkflowPublished = "workflow.published"

	CredentialCreated = "credential.created"
	CredentialUpdated = "credential.updated"
	CredentialDeleted = "credential.deleted"
	CredentialUsed    = "credential.used"

	TeamCreated      = "team.created"
	TeamUpdated      = "team.updated"
	TeamDeleted      = "team.deleted"
	TeamMemberAdded  = "team.member.added"
	TeamMemberRemoved = "team.member.removed"

	ExecutionStarted   = "execution.started"
	ExecutionCompleted = "execution.completed"
	ExecutionFailed    = "execution.failed"
	ExecutionCancelled = "execution.cancelled"

	AuditEventRecorded = "audit.event.recorded"
)

// Specific event implementations
type UserCreatedEvent struct {
	*BaseDomainEvent
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TeamID   string `json:"team_id,omitempty"`
}

func NewUserCreatedEvent(userID, email, role string, teamID *string) *UserCreatedEvent {
	data := map[string]interface{}{
		"user_id": userID,
		"email":   email,
		"role":    role,
	}
	if teamID != nil {
		data["team_id"] = *teamID
	}

	return &UserCreatedEvent{
		BaseDomainEvent: NewBaseDomainEvent(UserCreated, userID, "user", data),
		UserID:          userID,
		Email:           email,
		Role:            role,
		TeamID:          *teamID,
	}
}

type WorkflowExecutedEvent struct {
	*BaseDomainEvent
	WorkflowID   string                 `json:"workflow_id"`
	ExecutionID  string                 `json:"execution_id"`
	Status       string                 `json:"status"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	TriggerData  map[string]interface{} `json:"trigger_data"`
	ExecutedBy   string                 `json:"executed_by"`
}

func NewWorkflowExecutedEvent(workflowID, executionID, status, executedBy string, 
	startedAt time.Time, completedAt *time.Time, triggerData map[string]interface{}) *WorkflowExecutedEvent {
	
	data := map[string]interface{}{
		"workflow_id":   workflowID,
		"execution_id":  executionID,
		"status":        status,
		"started_at":    startedAt,
		"trigger_data":  triggerData,
		"executed_by":   executedBy,
	}
	if completedAt != nil {
		data["completed_at"] = *completedAt
	}

	return &WorkflowExecutedEvent{
		BaseDomainEvent: NewBaseDomainEvent(WorkflowExecuted, workflowID, "workflow", data),
		WorkflowID:      workflowID,
		ExecutionID:     executionID,
		Status:          status,
		StartedAt:       startedAt,
		CompletedAt:     completedAt,
		TriggerData:     triggerData,
		ExecutedBy:      executedBy,
	}
}