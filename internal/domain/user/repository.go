package user

import (
	"context"
	
	"n8n-pro/internal/domain/common/value_objects"
)

// Repository defines the contract for user persistence
type Repository interface {
	// Core CRUD operations
	Save(ctx context.Context, user *User) error
	FindByID(ctx context.Context, id value_objects.ID) (*User, error)
	FindByEmail(ctx context.Context, email value_objects.Email) (*User, error)
	FindByOrganization(ctx context.Context, organizationID value_objects.ID) ([]*User, error)
	Delete(ctx context.Context, id value_objects.ID) error
	
	// Query operations
	FindAll(ctx context.Context, filter *ListFilter) ([]*User, int64, error)
	ExistsByEmail(ctx context.Context, email value_objects.Email) (bool, error)
	ExistsByID(ctx context.Context, id value_objects.ID) (bool, error)
	
	// Bulk operations
	SaveMany(ctx context.Context, users []*User) error
	DeleteMany(ctx context.Context, ids []value_objects.ID) error
	
	// Advanced queries
	FindActiveUsersInOrganization(ctx context.Context, organizationID value_objects.ID) ([]*User, error)
	FindByRoleInOrganization(ctx context.Context, organizationID value_objects.ID, role value_objects.Role) ([]*User, error)
	CountByStatus(ctx context.Context, organizationID value_objects.ID, status Status) (int64, error)
	FindUsersWithMFAEnabled(ctx context.Context, organizationID value_objects.ID) ([]*User, error)
	FindInactiveUsersSince(ctx context.Context, since int) ([]*User, error) // days
}

// ListFilter represents filtering options for user queries
type ListFilter struct {
	OrganizationID *value_objects.ID
	Status         *Status
	Role           *value_objects.Role
	Search         string // Search in name or email
	MFAEnabled     *bool
	EmailVerified  *bool
	
	// Pagination
	Limit  int
	Offset int
	
	// Sorting
	SortBy    string // "created_at", "updated_at", "email", "name", "last_login"
	SortOrder string // "asc", "desc"
}

// Specification pattern for complex queries
type Specification interface {
	IsSatisfiedBy(user *User) bool
	And(other Specification) Specification
	Or(other Specification) Specification
	Not() Specification
}

// Common specifications
type ActiveUserSpecification struct{}

func (s ActiveUserSpecification) IsSatisfiedBy(user *User) bool {
	return user.IsActive() && !user.IsLocked()
}

func (s ActiveUserSpecification) And(other Specification) Specification {
	return &AndSpecification{left: s, right: other}
}

func (s ActiveUserSpecification) Or(other Specification) Specification {
	return &OrSpecification{left: s, right: other}
}

func (s ActiveUserSpecification) Not() Specification {
	return &NotSpecification{spec: s}
}

// Composite specifications
type AndSpecification struct {
	left, right Specification
}

func (s *AndSpecification) IsSatisfiedBy(user *User) bool {
	return s.left.IsSatisfiedBy(user) && s.right.IsSatisfiedBy(user)
}

func (s *AndSpecification) And(other Specification) Specification {
	return &AndSpecification{left: s, right: other}
}

func (s *AndSpecification) Or(other Specification) Specification {
	return &OrSpecification{left: s, right: other}
}

func (s *AndSpecification) Not() Specification {
	return &NotSpecification{spec: s}
}

type OrSpecification struct {
	left, right Specification
}

func (s *OrSpecification) IsSatisfiedBy(user *User) bool {
	return s.left.IsSatisfiedBy(user) || s.right.IsSatisfiedBy(user)
}

func (s *OrSpecification) And(other Specification) Specification {
	return &AndSpecification{left: s, right: other}
}

func (s *OrSpecification) Or(other Specification) Specification {
	return &OrSpecification{left: s, right: other}
}

func (s *OrSpecification) Not() Specification {
	return &NotSpecification{spec: s}
}

type NotSpecification struct {
	spec Specification
}

func (s *NotSpecification) IsSatisfiedBy(user *User) bool {
	return !s.spec.IsSatisfiedBy(user)
}

func (s *NotSpecification) And(other Specification) Specification {
	return &AndSpecification{left: s, right: other}
}

func (s *NotSpecification) Or(other Specification) Specification {
	return &OrSpecification{left: s, right: other}
}

func (s *NotSpecification) Not() Specification {
	return s.spec
}