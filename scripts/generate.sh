#!/bin/bash

# n8n Pro - Code Generation Script
# This script generates boilerplate code for rapid development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Templates directory
TEMPLATES_DIR="$PROJECT_ROOT/scripts/templates"

# Function to print colored output
print_info() { echo -e "${BLUE}$1${NC}"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }

# Function to convert string to different cases
to_snake_case() {
    echo "$1" | sed 's/\([A-Z]\)/_\1/g' | tr '[:upper:]' '[:lower:]' | sed 's/^_//'
}

to_camel_case() {
    echo "$1" | sed 's/_\([a-z]\)/\U\1/g' | sed 's/^./\U&/'
}

to_lower_camel_case() {
    echo "$1" | sed 's/_\([a-z]\)/\U\1/g'
}

to_kebab_case() {
    echo "$1" | sed 's/_/-/g' | tr '[:upper:]' '[:lower:]'
}

# Function to generate timestamp
timestamp() {
    date +"%Y%m%d%H%M%S"
}

# Function to generate domain entity
generate_domain() {
    local name=$1
    local snake_name=$(to_snake_case "$name")
    local camel_name=$(to_camel_case "$name")
    local lower_name=$(echo "$name" | tr '[:upper:]' '[:lower:]')

    print_info "Generating domain entity: $name"

    # Create directory structure
    mkdir -p "internal/domain/$lower_name"

    # Generate model
    cat > "internal/domain/$lower_name/models.go" << EOF
package $lower_name

import (
    "time"

    "github.com/google/uuid"
)

// $camel_name represents a $lower_name in the system
type $camel_name struct {
    ID          uuid.UUID  \`json:"id" db:"id"\`
    Name        string     \`json:"name" db:"name" validate:"required,min=1,max=255"\`
    Description string     \`json:"description,omitempty" db:"description"\`
    Status      Status     \`json:"status" db:"status"\`
    Metadata    Metadata   \`json:"metadata,omitempty" db:"metadata"\`
    CreatedAt   time.Time  \`json:"created_at" db:"created_at"\`
    UpdatedAt   time.Time  \`json:"updated_at" db:"updated_at"\`
    DeletedAt   *time.Time \`json:"deleted_at,omitempty" db:"deleted_at"\`
}

// Status represents the status of a $lower_name
type Status string

const (
    StatusActive   Status = "active"
    StatusInactive Status = "inactive"
    StatusPending  Status = "pending"
    StatusArchived Status = "archived"
)

// Metadata contains additional information about the $lower_name
type Metadata map[string]interface{}

// Validate validates the $lower_name
func (${lower_name:0:1} *$camel_name) Validate() error {
    if ${lower_name:0:1}.Name == "" {
        return ErrInvalidName
    }
    if ${lower_name:0:1}.ID == uuid.Nil {
        ${lower_name:0:1}.ID = uuid.New()
    }
    if ${lower_name:0:1}.CreatedAt.IsZero() {
        ${lower_name:0:1}.CreatedAt = time.Now()
    }
    ${lower_name:0:1}.UpdatedAt = time.Now()
    return nil
}

// IsActive checks if the $lower_name is active
func (${lower_name:0:1} *$camel_name) IsActive() bool {
    return ${lower_name:0:1}.Status == StatusActive && ${lower_name:0:1}.DeletedAt == nil
}
EOF

    # Generate repository interface
    cat > "internal/domain/$lower_name/repository.go" << EOF
package $lower_name

import (
    "context"

    "github.com/google/uuid"
)

// Repository defines the interface for $lower_name data access
type Repository interface {
    // Create creates a new $lower_name
    Create(ctx context.Context, $lower_name *$camel_name) error

    // GetByID retrieves a $lower_name by ID
    GetByID(ctx context.Context, id uuid.UUID) (*$camel_name, error)

    // GetAll retrieves all ${lower_name}s with pagination
    GetAll(ctx context.Context, offset, limit int) ([]*$camel_name, int64, error)

    // Update updates an existing $lower_name
    Update(ctx context.Context, $lower_name *$camel_name) error

    // Delete soft deletes a $lower_name
    Delete(ctx context.Context, id uuid.UUID) error

    // HardDelete permanently deletes a $lower_name
    HardDelete(ctx context.Context, id uuid.UUID) error

    // Search searches for ${lower_name}s based on criteria
    Search(ctx context.Context, criteria SearchCriteria) ([]*$camel_name, int64, error)
}

// SearchCriteria defines search parameters for ${lower_name}s
type SearchCriteria struct {
    Query  string
    Status Status
    Offset int
    Limit  int
}
EOF

    # Generate errors
    cat > "internal/domain/$lower_name/errors.go" << EOF
package $lower_name

import "errors"

var (
    // ErrNotFound is returned when a $lower_name is not found
    ErrNotFound = errors.New("$lower_name not found")

    // ErrAlreadyExists is returned when a $lower_name already exists
    ErrAlreadyExists = errors.New("$lower_name already exists")

    // ErrInvalidName is returned when the name is invalid
    ErrInvalidName = errors.New("invalid $lower_name name")

    // ErrInvalidStatus is returned when the status is invalid
    ErrInvalidStatus = errors.New("invalid $lower_name status")
)
EOF

    # Generate service
    cat > "internal/domain/$lower_name/service.go" << EOF
package $lower_name

import (
    "context"

    "github.com/google/uuid"
)

// Service provides business logic for ${lower_name}s
type Service struct {
    repo Repository
}

// NewService creates a new $lower_name service
func NewService(repo Repository) *Service {
    return &Service{
        repo: repo,
    }
}

// Create creates a new $lower_name
func (s *Service) Create(ctx context.Context, $lower_name *$camel_name) error {
    if err := ${lower_name}.Validate(); err != nil {
        return err
    }

    return s.repo.Create(ctx, $lower_name)
}

// GetByID retrieves a $lower_name by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*$camel_name, error) {
    return s.repo.GetByID(ctx, id)
}

// GetAll retrieves all ${lower_name}s
func (s *Service) GetAll(ctx context.Context, offset, limit int) ([]*$camel_name, int64, error) {
    if limit <= 0 {
        limit = 10
    }
    if limit > 100 {
        limit = 100
    }

    return s.repo.GetAll(ctx, offset, limit)
}

// Update updates a $lower_name
func (s *Service) Update(ctx context.Context, $lower_name *$camel_name) error {
    if err := ${lower_name}.Validate(); err != nil {
        return err
    }

    return s.repo.Update(ctx, $lower_name)
}

// Delete deletes a $lower_name
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
    return s.repo.Delete(ctx, id)
}
EOF

    print_success "Domain entity '$name' generated"
}

# Function to generate repository implementation
generate_repository() {
    local name=$1
    local snake_name=$(to_snake_case "$name")
    local camel_name=$(to_camel_case "$name")
    local lower_name=$(echo "$name" | tr '[:upper:]' '[:lower:]')

    print_info "Generating repository for: $name"

    mkdir -p "internal/repository"

    cat > "internal/repository/${snake_name}_repository.go" << EOF
package repository

import (
    "context"
    "database/sql"
    "fmt"

    "github.com/google/uuid"
    "github.com/jmoiron/sqlx"

    "n8n-pro/internal/domain/$lower_name"
)

// ${camel_name}Repository implements the $lower_name.Repository interface
type ${camel_name}Repository struct {
    db *sqlx.DB
}

// New${camel_name}Repository creates a new repository instance
func New${camel_name}Repository(db *sqlx.DB) $lower_name.Repository {
    return &${camel_name}Repository{
        db: db,
    }
}

// Create creates a new $lower_name
func (r *${camel_name}Repository) Create(ctx context.Context, item *$lower_name.$camel_name) error {
    query := \`
        INSERT INTO ${snake_name}s (id, name, description, status, metadata, created_at, updated_at)
        VALUES (:id, :name, :description, :status, :metadata, :created_at, :updated_at)
    \`

    _, err := r.db.NamedExecContext(ctx, query, item)
    if err != nil {
        return fmt.Errorf("failed to create $lower_name: %w", err)
    }

    return nil
}

// GetByID retrieves a $lower_name by ID
func (r *${camel_name}Repository) GetByID(ctx context.Context, id uuid.UUID) (*$lower_name.$camel_name, error) {
    var item $lower_name.$camel_name

    query := \`
        SELECT id, name, description, status, metadata, created_at, updated_at, deleted_at
        FROM ${snake_name}s
        WHERE id = \$1 AND deleted_at IS NULL
    \`

    err := r.db.GetContext(ctx, &item, query, id)
    if err == sql.ErrNoRows {
        return nil, $lower_name.ErrNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get $lower_name: %w", err)
    }

    return &item, nil
}

// GetAll retrieves all ${lower_name}s with pagination
func (r *${camel_name}Repository) GetAll(ctx context.Context, offset, limit int) ([]*$lower_name.$camel_name, int64, error) {
    var items []*$lower_name.$camel_name
    var total int64

    // Count total
    countQuery := \`SELECT COUNT(*) FROM ${snake_name}s WHERE deleted_at IS NULL\`
    if err := r.db.GetContext(ctx, &total, countQuery); err != nil {
        return nil, 0, fmt.Errorf("failed to count ${lower_name}s: %w", err)
    }

    // Get items
    query := \`
        SELECT id, name, description, status, metadata, created_at, updated_at, deleted_at
        FROM ${snake_name}s
        WHERE deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT \$1 OFFSET \$2
    \`

    if err := r.db.SelectContext(ctx, &items, query, limit, offset); err != nil {
        return nil, 0, fmt.Errorf("failed to get ${lower_name}s: %w", err)
    }

    return items, total, nil
}

// Update updates a $lower_name
func (r *${camel_name}Repository) Update(ctx context.Context, item *$lower_name.$camel_name) error {
    query := \`
        UPDATE ${snake_name}s
        SET name = :name,
            description = :description,
            status = :status,
            metadata = :metadata,
            updated_at = :updated_at
        WHERE id = :id AND deleted_at IS NULL
    \`

    result, err := r.db.NamedExecContext(ctx, query, item)
    if err != nil {
        return fmt.Errorf("failed to update $lower_name: %w", err)
    }

    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to check affected rows: %w", err)
    }

    if rows == 0 {
        return $lower_name.ErrNotFound
    }

    return nil
}

// Delete soft deletes a $lower_name
func (r *${camel_name}Repository) Delete(ctx context.Context, id uuid.UUID) error {
    query := \`
        UPDATE ${snake_name}s
        SET deleted_at = NOW()
        WHERE id = \$1 AND deleted_at IS NULL
    \`

    result, err := r.db.ExecContext(ctx, query, id)
    if err != nil {
        return fmt.Errorf("failed to delete $lower_name: %w", err)
    }

    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to check affected rows: %w", err)
    }

    if rows == 0 {
        return $lower_name.ErrNotFound
    }

    return nil
}

// HardDelete permanently deletes a $lower_name
func (r *${camel_name}Repository) HardDelete(ctx context.Context, id uuid.UUID) error {
    query := \`DELETE FROM ${snake_name}s WHERE id = \$1\`

    result, err := r.db.ExecContext(ctx, query, id)
    if err != nil {
        return fmt.Errorf("failed to hard delete $lower_name: %w", err)
    }

    rows, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to check affected rows: %w", err)
    }

    if rows == 0 {
        return $lower_name.ErrNotFound
    }

    return nil
}

// Search searches for ${lower_name}s based on criteria
func (r *${camel_name}Repository) Search(ctx context.Context, criteria $lower_name.SearchCriteria) ([]*$lower_name.$camel_name, int64, error) {
    var items []*$lower_name.$camel_name
    var total int64
    var args []interface{}

    baseQuery := \`FROM ${snake_name}s WHERE deleted_at IS NULL\`
    whereClause := ""
    argCount := 0

    if criteria.Query != "" {
        argCount++
        whereClause += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argCount, argCount)
        searchTerm := "%" + criteria.Query + "%"
        args = append(args, searchTerm)
    }

    if criteria.Status != "" {
        argCount++
        whereClause += fmt.Sprintf(" AND status = $%d", argCount)
        args = append(args, criteria.Status)
    }

    // Count total
    countQuery := "SELECT COUNT(*) " + baseQuery + whereClause
    if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
        return nil, 0, fmt.Errorf("failed to count search results: %w", err)
    }

    // Get items
    selectQuery := \`
        SELECT id, name, description, status, metadata, created_at, updated_at, deleted_at \` +
        baseQuery + whereClause + \`
        ORDER BY created_at DESC
        LIMIT \$\` + fmt.Sprintf("%d", argCount+1) + \` OFFSET \$\` + fmt.Sprintf("%d", argCount+2)

    args = append(args, criteria.Limit, criteria.Offset)

    if err := r.db.SelectContext(ctx, &items, selectQuery, args...); err != nil {
        return nil, 0, fmt.Errorf("failed to search ${lower_name}s: %w", err)
    }

    return items, total, nil
}
EOF

    print_success "Repository for '$name' generated"
}

# Function to generate API handler
generate_handler() {
    local name=$1
    local snake_name=$(to_snake_case "$name")
    local camel_name=$(to_camel_case "$name")
    local lower_name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    local kebab_name=$(to_kebab_case "$name")

    print_info "Generating API handler for: $name"

    mkdir -p "internal/presentation/http/handlers"

    cat > "internal/presentation/http/handlers/${snake_name}_handler.go" << EOF
package handlers

import (
    "encoding/json"
    "net/http"
    "strconv"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    "n8n-pro/internal/domain/$lower_name"
    "n8n-pro/pkg/utils"
)

// ${camel_name}Handler handles HTTP requests for ${lower_name}s
type ${camel_name}Handler struct {
    service *$lower_name.Service
}

// New${camel_name}Handler creates a new handler instance
func New${camel_name}Handler(service *$lower_name.Service) *${camel_name}Handler {
    return &${camel_name}Handler{
        service: service,
    }
}

// Routes registers the handler routes
func (h *${camel_name}Handler) Routes(r chi.Router) {
    r.Route("/${kebab_name}s", func(r chi.Router) {
        r.Post("/", h.Create)
        r.Get("/", h.GetAll)

        r.Route("/{id}", func(r chi.Router) {
            r.Get("/", h.GetByID)
            r.Put("/", h.Update)
            r.Delete("/", h.Delete)
        })
    })
}

// Create handles POST /${kebab_name}s
func (h *${camel_name}Handler) Create(w http.ResponseWriter, r *http.Request) {
    var req Create${camel_name}Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        utils.RespondError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    item := &$lower_name.$camel_name{
        Name:        req.Name,
        Description: req.Description,
        Status:      $lower_name.StatusActive,
        Metadata:    req.Metadata,
    }

    if err := h.service.Create(r.Context(), item); err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    utils.RespondJSON(w, http.StatusCreated, item)
}

// GetByID handles GET /${kebab_name}s/{id}
func (h *${camel_name}Handler) GetByID(w http.ResponseWriter, r *http.Request) {
    idStr := chi.URLParam(r, "id")
    id, err := uuid.Parse(idStr)
    if err != nil {
        utils.RespondError(w, http.StatusBadRequest, "Invalid ID format")
        return
    }

    item, err := h.service.GetByID(r.Context(), id)
    if err == $lower_name.ErrNotFound {
        utils.RespondError(w, http.StatusNotFound, "$camel_name not found")
        return
    }
    if err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    utils.RespondJSON(w, http.StatusOK, item)
}

// GetAll handles GET /${kebab_name}s
func (h *${camel_name}Handler) GetAll(w http.ResponseWriter, r *http.Request) {
    offset := 0
    limit := 10

    if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
        if val, err := strconv.Atoi(offsetStr); err == nil {
            offset = val
        }
    }

    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
        if val, err := strconv.Atoi(limitStr); err == nil {
            limit = val
        }
    }

    items, total, err := h.service.GetAll(r.Context(), offset, limit)
    if err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    response := map[string]interface{}{
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
    }

    utils.RespondJSON(w, http.StatusOK, response)
}

// Update handles PUT /${kebab_name}s/{id}
func (h *${camel_name}Handler) Update(w http.ResponseWriter, r *http.Request) {
    idStr := chi.URLParam(r, "id")
    id, err := uuid.Parse(idStr)
    if err != nil {
        utils.RespondError(w, http.StatusBadRequest, "Invalid ID format")
        return
    }

    var req Update${camel_name}Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        utils.RespondError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    item, err := h.service.GetByID(r.Context(), id)
    if err == $lower_name.ErrNotFound {
        utils.RespondError(w, http.StatusNotFound, "$camel_name not found")
        return
    }
    if err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Update fields
    if req.Name != "" {
        item.Name = req.Name
    }
    if req.Description != "" {
        item.Description = req.Description
    }
    if req.Status != "" {
        item.Status = req.Status
    }
    if req.Metadata != nil {
        item.Metadata = req.Metadata
    }

    if err := h.service.Update(r.Context(), item); err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    utils.RespondJSON(w, http.StatusOK, item)
}

// Delete handles DELETE /${kebab_name}s/{id}
func (h *${camel_name}Handler) Delete(w http.ResponseWriter, r *http.Request) {
    idStr := chi.URLParam(r, "id")
    id, err := uuid.Parse(idStr)
    if err != nil {
        utils.RespondError(w, http.StatusBadRequest, "Invalid ID format")
        return
    }

    if err := h.service.Delete(r.Context(), id); err == $lower_name.ErrNotFound {
        utils.RespondError(w, http.StatusNotFound, "$camel_name not found")
        return
    } else if err != nil {
        utils.RespondError(w, http.StatusInternalServerError, err.Error())
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// Request DTOs

// Create${camel_name}Request represents a request to create a $lower_name
type Create${camel_name}Request struct {
    Name        string                 \`json:"name" validate:"required,min=1,max=255"\`
    Description string                 \`json:"description,omitempty"\`
    Metadata    $lower_name.Metadata   \`json:"metadata,omitempty"\`
}

// Update${camel_name}Request represents a request to update a $lower_name
type Update${camel_name}Request struct {
    Name        string                 \`json:"name,omitempty"\`
    Description string                 \`json:"description,omitempty"\`
    Status      $lower_name.Status     \`json:"status,omitempty"\`
    Metadata    $lower_name.Metadata   \`json:"metadata,omitempty"\`
}
EOF

    print_success "API handler for '$name' generated"
}

# Function to generate migration
generate_migration() {
    local name=$1
    local snake_name=$(to_snake_case "$name")
    local timestamp=$(date +"%Y%m%d%H%M%S")
    local seq_num=$(find migrations -name "*.sql" 2>/dev/null | wc -l | xargs)
    seq_num=$((seq_num / 2 + 1))
    seq_num=$(printf "%03d" $seq_num)

    print_info "Generating migration for: $name"

    mkdir -p migrations

    # Up migration
    cat > "migrations/${seq_num}_create_${snake_name}_table.up.sql" << EOF
-- Create ${snake_name}s table
CREATE TABLE IF NOT EXISTS ${snake_name}s (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,

    CONSTRAINT ${snake_name}s_name_unique UNIQUE (name, deleted_at)
);

-- Create indexes
CREATE INDEX idx_${snake_name}s_status ON ${snake_name}s(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_${snake_name}s_created_at ON ${snake_name}s(created_at DESC);
CREATE INDEX idx_${snake_name}s_deleted_at ON ${snake_name}s(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_${snake_name}s_name_search ON ${snake_name}s USING gin(to_tsvector('english', name));

-- Create updated_at trigger
CREATE TRIGGER update_${snake_name}s_updated_at
    BEFORE UPDATE ON ${snake_name}s
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
EOF

    # Down migration
    cat > "migrations/${seq_num}_create_${snake_name}_table.down.sql" << EOF
-- Drop ${snake_name}s table
DROP TRIGGER IF EXISTS update_${snake_name}s_updated_at ON ${snake_name}s;
DROP TABLE IF EXISTS ${snake_name}s;
EOF

    print_success "Migration for '$name' generated"
}

# Function to generate tests
generate_tests() {
    local name=$1
    local snake_name=$(to_snake_case "$name")
    local camel_name=$(to_camel_case "$name")
    local lower_name=$(echo "$name" | tr '[:upper:]' '[:lower:]')

    print_info "Generating tests for: $name"

    # Domain tests
    cat > "internal/domain/$lower_name/models_test.go" << EOF
package ${lower_name}_test

import (
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "n8n-pro/internal/domain/$lower_name"
)

func Test${camel_name}_Validate(t *testing.T) {
    tests := []struct {
        name    string
        item    *$lower_name.$camel_name
        wantErr bool
    }{
        {
            name: "valid $lower_name",
            item: &$lower_name.$camel_name{
                Name:        "Test $camel_name",
                Description: "Test description",
                Status:      $lower_name.StatusActive,
            },
            wantErr: false,
        },
        {
            name: "empty name",
            item: &$lower_name.$camel_name{
                Name:   "",
                Status: $lower_name.StatusActive,
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.item.Validate()
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.NotEqual(t, uuid.Nil, tt.item.ID)
                assert.False(t, tt.item.CreatedAt.IsZero())
                assert.False(t, tt.item.UpdatedAt.IsZero())
            }
        })
    }
}

func Test${camel_name}_IsActive(t *testing.T) {
    now := time.Now()

    tests := []struct {
        name string
        item *$lower_name.$camel_name
        want bool
    }{
        {
            name: "active $lower_name",
            item: &$lower_name.$camel_name{
                Status:    $lower_name.StatusActive,
                DeletedAt: nil,
            },
            want: true,
        },
        {
            name: "inactive $lower_name",
            item: &$lower_name.$camel_name{
                Status:    $lower_name.StatusInactive,
                DeletedAt: nil,
            },
            want: false,
        },
        {
            name: "deleted $lower_name",
            item: &$lower_name.$camel_name{
                Status:    $lower_name.StatusActive,
                DeletedAt: &now,
            },
            want: false,
        },
    }
