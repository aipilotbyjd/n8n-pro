package repository

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"time"

	"n8n-pro/internal/models"
	
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Repository interface that all repositories should implement
type Repository[T any] interface {
	// Basic CRUD operations
	Create(ctx context.Context, entity *T) error
	GetByID(ctx context.Context, id string) (*T, error)
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id string) error
	SoftDelete(ctx context.Context, id string) error
	Restore(ctx context.Context, id string) error
	
	// List operations
	List(ctx context.Context, filter models.ListFilter) (*models.PaginatedResponse[T], error)
	Count(ctx context.Context, conditions map[string]interface{}) (int, error)
	Exists(ctx context.Context, conditions map[string]interface{}) (bool, error)
	
	// Batch operations
	CreateBatch(ctx context.Context, entities []T) error
	UpdateBatch(ctx context.Context, entities []T) error
	DeleteBatch(ctx context.Context, ids []string) error
	
	// Transaction support
	WithTx(tx *sqlx.Tx) Repository[T]
}

// BaseRepository provides common database operations
type BaseRepository[T any] struct {
	db        *sqlx.DB
	tx        *sqlx.Tx
	tableName string
	tracer    trace.Tracer
}

// NewBaseRepository creates a new base repository
func NewBaseRepository[T any](db *sqlx.DB, tableName string) *BaseRepository[T] {
	return &BaseRepository[T]{
		db:        db,
		tableName: tableName,
		tracer:    otel.Tracer("n8n-pro/repository"),
	}
}

// WithTx returns a new repository instance with transaction support
func (r *BaseRepository[T]) WithTx(tx *sqlx.Tx) Repository[T] {
	return &BaseRepository[T]{
		db:        r.db,
		tx:        tx,
		tableName: r.tableName,
		tracer:    r.tracer,
	}
}

// getDB returns the database connection (transaction or regular)
func (r *BaseRepository[T]) getDB() sqlx.Ext {
	if r.tx != nil {
		return r.tx
	}
	return r.db
}

// Create inserts a new entity into the database
func (r *BaseRepository[T]) Create(ctx context.Context, entity *T) error {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.Create", r.tableName))
	defer span.End()

	// Set created/updated timestamps if entity has BaseModel
	if auditable, ok := any(entity).(interface{ SetAuditInfo(string) }); ok {
		// Try to get user ID from context
		if userID, exists := ctx.Value("user_id").(string); exists {
			auditable.SetAuditInfo(userID)
		}
	}

	query, args, err := r.buildInsertQuery(entity)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to build insert query: %w", err)
	}

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "create"),
	)

	_, err = r.getDB().ExecContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create entity in %s: %w", r.tableName, err)
	}

	return nil
}

// GetByID retrieves an entity by its ID
func (r *BaseRepository[T]) GetByID(ctx context.Context, id string) (*T, error) {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.GetByID", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "get_by_id"),
		attribute.String("id", id),
	)

	var entity T
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1 AND deleted_at IS NULL", r.tableName)
	
	err := r.getDB().GetContext(ctx, &entity, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.ErrNotFound
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get entity from %s: %w", r.tableName, err)
	}

	return &entity, nil
}

// Update updates an existing entity
func (r *BaseRepository[T]) Update(ctx context.Context, entity *T) error {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.Update", r.tableName))
	defer span.End()

	// Update the updated_at timestamp if entity has BaseModel
	if auditable, ok := any(entity).(interface{ SetAuditInfo(string) }); ok {
		if userID, exists := ctx.Value("user_id").(string); exists {
			auditable.SetAuditInfo(userID)
		}
	}

	query, args, err := r.buildUpdateQuery(entity)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to build update query: %w", err)
	}

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "update"),
	)

	result, err := r.getDB().ExecContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update entity in %s: %w", r.tableName, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return models.ErrNotFound
	}

	return nil
}

// Delete permanently deletes an entity
func (r *BaseRepository[T]) Delete(ctx context.Context, id string) error {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.Delete", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "delete"),
		attribute.String("id", id),
	)

	query := fmt.Sprintf("DELETE FROM %s WHERE id = $1", r.tableName)
	result, err := r.getDB().ExecContext(ctx, query, id)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete entity from %s: %w", r.tableName, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return models.ErrNotFound
	}

	return nil
}

// SoftDelete marks an entity as deleted without removing it
func (r *BaseRepository[T]) SoftDelete(ctx context.Context, id string) error {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.SoftDelete", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "soft_delete"),
		attribute.String("id", id),
	)

	now := time.Now()
	query := fmt.Sprintf("UPDATE %s SET deleted_at = $1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL", r.tableName)
	
	result, err := r.getDB().ExecContext(ctx, query, now, id)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to soft delete entity from %s: %w", r.tableName, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return models.ErrNotFound
	}

	return nil
}

// Restore restores a soft-deleted entity
func (r *BaseRepository[T]) Restore(ctx context.Context, id string) error {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.Restore", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "restore"),
		attribute.String("id", id),
	)

	now := time.Now()
	query := fmt.Sprintf("UPDATE %s SET deleted_at = NULL, updated_at = $1 WHERE id = $2 AND deleted_at IS NOT NULL", r.tableName)
	
	result, err := r.getDB().ExecContext(ctx, query, now, id)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to restore entity in %s: %w", r.tableName, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return models.ErrNotFound
	}

	return nil
}

// List retrieves a paginated list of entities
func (r *BaseRepository[T]) List(ctx context.Context, filter models.ListFilter) (*models.PaginatedResponse[T], error) {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.List", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "list"),
		attribute.Int("limit", filter.Limit),
		attribute.Int("offset", filter.Offset),
	)

	// Build base query
	baseQuery := fmt.Sprintf("FROM %s WHERE deleted_at IS NULL", r.tableName)
	
	// Add search if provided
	if filter.Search != "" {
		// This is a simple implementation - you might want to customize search fields per model
		baseQuery += " AND (name ILIKE $1 OR description ILIKE $1)"
	}

	// Add sorting
	if filter.SortBy != "" {
		order := "ASC"
		if strings.ToUpper(filter.SortOrder) == "DESC" {
			order = "DESC"
		}
		baseQuery += fmt.Sprintf(" ORDER BY %s %s", filter.SortBy, order)
	} else {
		baseQuery += " ORDER BY created_at DESC"
	}

	// Count query
	countQuery := "SELECT COUNT(*) " + baseQuery
	var total int
	
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		err := r.getDB().GetContext(ctx, &total, countQuery, searchTerm)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to count entities in %s: %w", r.tableName, err)
		}
	} else {
		err := r.getDB().GetContext(ctx, &total, countQuery)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to count entities in %s: %w", r.tableName, err)
		}
	}

	// Data query with pagination
	dataQuery := fmt.Sprintf("SELECT * %s LIMIT $%d OFFSET $%d", baseQuery, getNextParamIndex(filter.Search), getNextParamIndex(filter.Search)+1)
	var entities []T
	
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		err := r.getDB().SelectContext(ctx, &entities, dataQuery, searchTerm, filter.Limit, filter.Offset)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to list entities from %s: %w", r.tableName, err)
		}
	} else {
		err := r.getDB().SelectContext(ctx, &entities, dataQuery, filter.Limit, filter.Offset)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to list entities from %s: %w", r.tableName, err)
		}
	}

	response := models.NewPaginatedResponse(entities, total, filter.Limit, filter.Offset)
	return &response, nil
}

// Count counts entities matching the given conditions
func (r *BaseRepository[T]) Count(ctx context.Context, conditions map[string]interface{}) (int, error) {
	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.Count", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "count"),
	)

	query, args := r.buildCountQuery(conditions)
	
	var count int
	err := r.getDB().GetContext(ctx, &count, query, args...)
	if err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("failed to count entities in %s: %w", r.tableName, err)
	}

	return count, nil
}

// Exists checks if an entity exists matching the given conditions
func (r *BaseRepository[T]) Exists(ctx context.Context, conditions map[string]interface{}) (bool, error) {
	count, err := r.Count(ctx, conditions)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateBatch creates multiple entities in a single transaction
func (r *BaseRepository[T]) CreateBatch(ctx context.Context, entities []T) error {
	if len(entities) == 0 {
		return nil
	}

	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.CreateBatch", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "create_batch"),
		attribute.Int("count", len(entities)),
	)

	// If we already have a transaction, use it; otherwise create one
	if r.tx != nil {
		return r.createBatchWithTx(ctx, entities, r.tx)
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	err = r.createBatchWithTx(ctx, entities, tx)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateBatch updates multiple entities
func (r *BaseRepository[T]) UpdateBatch(ctx context.Context, entities []T) error {
	if len(entities) == 0 {
		return nil
	}

	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.UpdateBatch", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "update_batch"),
		attribute.Int("count", len(entities)),
	)

	// If we already have a transaction, use it; otherwise create one
	if r.tx != nil {
		return r.updateBatchWithTx(ctx, entities, r.tx)
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	err = r.updateBatchWithTx(ctx, entities, tx)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteBatch deletes multiple entities by IDs
func (r *BaseRepository[T]) DeleteBatch(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("%s.DeleteBatch", r.tableName))
	defer span.End()

	span.SetAttributes(
		attribute.String("table", r.tableName),
		attribute.String("operation", "delete_batch"),
		attribute.Int("count", len(ids)),
	)

	// Build placeholders for IN clause
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", r.tableName, strings.Join(placeholders, ","))
	
	_, err := r.getDB().ExecContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete batch from %s: %w", r.tableName, err)
	}

	return nil
}

// Helper methods

func (r *BaseRepository[T]) buildInsertQuery(entity *T) (string, []interface{}, error) {
	v := reflect.ValueOf(entity).Elem()
	t := v.Type()

	var columns []string
	var placeholders []string
	var args []interface{}
	paramIndex := 1

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag := field.Tag.Get("db")
		
		if dbTag == "" || dbTag == "-" {
			continue
		}

		fieldValue := v.Field(i)
		if !fieldValue.IsValid() || (fieldValue.Kind() == reflect.Ptr && fieldValue.IsNil()) {
			continue
		}

		columns = append(columns, dbTag)
		placeholders = append(placeholders, fmt.Sprintf("$%d", paramIndex))
		args = append(args, fieldValue.Interface())
		paramIndex++
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		r.tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "))

	return query, args, nil
}

func (r *BaseRepository[T]) buildUpdateQuery(entity *T) (string, []interface{}, error) {
	v := reflect.ValueOf(entity).Elem()
	t := v.Type()

	var setParts []string
	var args []interface{}
	paramIndex := 1
	var entityID interface{}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		dbTag := field.Tag.Get("db")
		
		if dbTag == "" || dbTag == "-" || dbTag == "id" {
			if dbTag == "id" {
				entityID = v.Field(i).Interface()
			}
			continue
		}

		fieldValue := v.Field(i)
		if !fieldValue.IsValid() {
			continue
		}

		setParts = append(setParts, fmt.Sprintf("%s = $%d", dbTag, paramIndex))
		args = append(args, fieldValue.Interface())
		paramIndex++
	}

	if entityID == nil {
		return "", nil, fmt.Errorf("entity ID is required for update")
	}

	query := fmt.Sprintf("UPDATE %s SET %s WHERE id = $%d AND deleted_at IS NULL",
		r.tableName,
		strings.Join(setParts, ", "),
		paramIndex)
	
	args = append(args, entityID)

	return query, args, nil
}

func (r *BaseRepository[T]) buildCountQuery(conditions map[string]interface{}) (string, []interface{}) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE deleted_at IS NULL", r.tableName)
	var args []interface{}
	paramIndex := 1

	if len(conditions) > 0 {
		var whereParts []string
		for column, value := range conditions {
			whereParts = append(whereParts, fmt.Sprintf("%s = $%d", column, paramIndex))
			args = append(args, value)
			paramIndex++
		}
		query += " AND " + strings.Join(whereParts, " AND ")
	}

	return query, args
}

func (r *BaseRepository[T]) createBatchWithTx(ctx context.Context, entities []T, tx *sqlx.Tx) error {
	for _, entity := range entities {
		query, args, err := r.buildInsertQuery(&entity)
		if err != nil {
			return fmt.Errorf("failed to build insert query: %w", err)
		}

		_, err = tx.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to create entity in batch: %w", err)
		}
	}
	return nil
}

func (r *BaseRepository[T]) updateBatchWithTx(ctx context.Context, entities []T, tx *sqlx.Tx) error {
	for _, entity := range entities {
		query, args, err := r.buildUpdateQuery(&entity)
		if err != nil {
			return fmt.Errorf("failed to build update query: %w", err)
		}

		_, err = tx.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to update entity in batch: %w", err)
		}
	}
	return nil
}

// Helper function for parameter indexing
func getNextParamIndex(hasSearch string) int {
	if hasSearch != "" {
		return 2 // search term is $1, so next is $2
	}
	return 1 // no search term, so start with $1
}