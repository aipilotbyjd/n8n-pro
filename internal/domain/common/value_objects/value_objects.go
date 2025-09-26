package value_objects

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ID represents a domain entity identifier
type ID struct {
	value string
}

func NewID() ID {
	return ID{value: uuid.New().String()}
}

func NewIDFromString(value string) (ID, error) {
	if value == "" {
		return ID{}, fmt.Errorf("ID cannot be empty")
	}
	
	// Validate UUID format
	if _, err := uuid.Parse(value); err != nil {
		return ID{}, fmt.Errorf("invalid ID format: %w", err)
	}
	
	return ID{value: value}, nil
}

func (id ID) Value() string {
	return id.value
}

func (id ID) String() string {
	return id.value
}

func (id ID) IsEmpty() bool {
	return id.value == ""
}

func (id ID) Equals(other ID) bool {
	return id.value == other.value
}

// Email represents an email address value object
type Email struct {
	value string
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func NewEmail(value string) (Email, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	
	if value == "" {
		return Email{}, fmt.Errorf("email cannot be empty")
	}
	
	if !emailRegex.MatchString(value) {
		return Email{}, fmt.Errorf("invalid email format: %s", value)
	}
	
	if len(value) > 254 {
		return Email{}, fmt.Errorf("email too long: maximum 254 characters")
	}
	
	return Email{value: value}, nil
}

func (e Email) Value() string {
	return e.value
}

func (e Email) String() string {
	return e.value
}

func (e Email) Domain() string {
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func (e Email) LocalPart() string {
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// Password represents a password value object
type Password struct {
	value string
}

func NewPassword(value string) (Password, error) {
	if len(value) < 8 {
		return Password{}, fmt.Errorf("password must be at least 8 characters long")
	}
	
	if len(value) > 128 {
		return Password{}, fmt.Errorf("password too long: maximum 128 characters")
	}
	
	// Check for at least one uppercase, lowercase, digit, and special character
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	
	for _, char := range value {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*(),.?\":{}|<>", char):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		return Password{}, fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return Password{}, fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return Password{}, fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return Password{}, fmt.Errorf("password must contain at least one special character")
	}
	
	return Password{value: value}, nil
}

func (p Password) Value() string {
	return p.value
}

// Never expose password in string representation for security
func (p Password) String() string {
	return "[REDACTED]"
}

// Role represents a user role
type Role string

const (
	RoleGuest       Role = "guest"
	RoleUser        Role = "user" 
	RoleMember      Role = "member"
	RoleAdmin       Role = "admin"
	RoleOwner       Role = "owner"
	RoleSuperAdmin  Role = "super_admin"
)

var validRoles = map[Role]bool{
	RoleGuest:      true,
	RoleUser:       true,
	RoleMember:     true,
	RoleAdmin:      true,
	RoleOwner:      true,
	RoleSuperAdmin: true,
}

func NewRole(value string) (Role, error) {
	role := Role(strings.ToLower(strings.TrimSpace(value)))
	
	if !validRoles[role] {
		return "", fmt.Errorf("invalid role: %s", value)
	}
	
	return role, nil
}

func (r Role) String() string {
	return string(r)
}

func (r Role) IsAdmin() bool {
	return r == RoleAdmin || r == RoleOwner || r == RoleSuperAdmin
}

func (r Role) HasPermission(requiredRole Role) bool {
	roleHierarchy := map[Role]int{
		RoleGuest:      0,
		RoleUser:       1,
		RoleMember:     2,
		RoleAdmin:      3,
		RoleOwner:      4,
		RoleSuperAdmin: 5,
	}
	
	userLevel := roleHierarchy[r]
	requiredLevel := roleHierarchy[requiredRole]
	
	return userLevel >= requiredLevel
}

// WorkflowStatus represents the status of a workflow
type WorkflowStatus string

const (
	WorkflowStatusDraft     WorkflowStatus = "draft"
	WorkflowStatusActive    WorkflowStatus = "active"
	WorkflowStatusInactive  WorkflowStatus = "inactive"
	WorkflowStatusArchived  WorkflowStatus = "archived"
)

var validWorkflowStatuses = map[WorkflowStatus]bool{
	WorkflowStatusDraft:    true,
	WorkflowStatusActive:   true,
	WorkflowStatusInactive: true,
	WorkflowStatusArchived: true,
}

func NewWorkflowStatus(value string) (WorkflowStatus, error) {
	status := WorkflowStatus(strings.ToLower(strings.TrimSpace(value)))
	
	if !validWorkflowStatuses[status] {
		return "", fmt.Errorf("invalid workflow status: %s", value)
	}
	
	return status, nil
}

func (ws WorkflowStatus) String() string {
	return string(ws)
}

func (ws WorkflowStatus) IsExecutable() bool {
	return ws == WorkflowStatusActive
}

// ExecutionStatus represents the status of a workflow execution
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCancelled ExecutionStatus = "cancelled"
)

// DateTimeRange represents a date/time range
type DateTimeRange struct {
	Start time.Time
	End   time.Time
}

func NewDateTimeRange(start, end time.Time) (DateTimeRange, error) {
	if end.Before(start) {
		return DateTimeRange{}, fmt.Errorf("end time cannot be before start time")
	}
	
	return DateTimeRange{
		Start: start,
		End:   end,
	}, nil
}

func (dtr DateTimeRange) Duration() time.Duration {
	return dtr.End.Sub(dtr.Start)
}

func (dtr DateTimeRange) Contains(t time.Time) bool {
	return !t.Before(dtr.Start) && !t.After(dtr.End)
}

func (dtr DateTimeRange) Overlaps(other DateTimeRange) bool {
	return dtr.Start.Before(other.End) && other.Start.Before(dtr.End)
}

// Version represents a version number
type Version struct {
	Major int
	Minor int
	Patch int
}

func NewVersion(major, minor, patch int) (Version, error) {
	if major < 0 || minor < 0 || patch < 0 {
		return Version{}, fmt.Errorf("version numbers cannot be negative")
	}
	
	return Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) IsGreaterThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}