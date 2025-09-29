package workflow

import (
	"context"
)

// Repository defines the workflow repository interface
type Repository interface {
	Create(ctx context.Context, workflow *Workflow) error
	Update(ctx context.Context, workflow *Workflow) error
	Delete(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (*Workflow, error)
	GetByOwner(ctx context.Context, ownerID string) ([]*Workflow, error)
	GetByTeam(ctx context.Context, teamID string) ([]*Workflow, error)
	List(ctx context.Context, filters map[string]interface{}) ([]*Workflow, error)
}