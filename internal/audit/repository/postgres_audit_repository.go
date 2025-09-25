package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/audit"
	"n8n-pro/internal/database"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// PostgresAuditRepository implements audit repository using PostgreSQL
type PostgresAuditRepository struct {
	db     *sqlx.DB
	logger logger.Logger
}

// NewPostgresAuditRepository creates a new PostgreSQL audit repository
func NewPostgresAuditRepository(db *sqlx.DB, logger logger.Logger) *PostgresAuditRepository {
	return &PostgresAuditRepository{
		db:     db,
		logger: logger,
	}
}

// Create inserts a new audit event into the database
func (r *PostgresAuditRepository) Create(ctx context.Context, event *audit.AuditEvent) error {
	query := `
		INSERT INTO audit_events (
			id, organization_id, actor_type, actor_id, event_type, 
			resource_type, resource_id, details, ip_address, user_agent, 
			success, error_message, created_at, session_id, request_id, severity
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)`

	// Convert details to JSON
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		event.ID,
		event.OrganizationID,
		event.ActorType,
		event.ActorID,
		string(event.EventType),
		event.ResourceType,
		event.ResourceID,
		detailsJSON,
		event.IPAddress,
		event.UserAgent,
		event.Success,
		event.ErrorMessage,
		event.CreatedAt,
		event.SessionID,
		event.RequestID,
		event.Severity,
	)

	if err != nil {
		r.logger.Error("Failed to create audit event", "error", err, "event_id", event.ID)
		return fmt.Errorf("failed to create audit event: %w", err)
	}

	r.logger.Debug("Audit event created", "event_id", event.ID, "type", event.EventType)
	return nil
}

// GetByID retrieves an audit event by its ID
func (r *PostgresAuditRepository) GetByID(ctx context.Context, id string) (*audit.AuditEvent, error) {
	query := `
		SELECT id, organization_id, actor_type, actor_id, event_type, 
		       resource_type, resource_id, details, ip_address, user_agent, 
		       success, error_message, created_at, session_id, request_id, severity
		FROM audit_events 
		WHERE id = $1`

	var event audit.AuditEvent
	var detailsJSON []byte
	var eventType string

	err := r.db.GetContext(ctx, &struct {
		ID             string          `db:"id"`
		OrganizationID string          `db:"organization_id"`
		ActorType      string          `db:"actor_type"`
		ActorID        *string         `db:"actor_id"`
		EventType      string          `db:"event_type"`
		ResourceType   string          `db:"resource_type"`
		ResourceID     string          `db:"resource_id"`
		Details        []byte          `db:"details"`
		IPAddress      string          `db:"ip_address"`
		UserAgent      string          `db:"user_agent"`
		Success        bool            `db:"success"`
		ErrorMessage   *string         `db:"error_message"`
		CreatedAt      time.Time       `db:"created_at"`
		SessionID      *string         `db:"session_id"`
		RequestID      *string         `db:"request_id"`
		Severity       string          `db:"severity"`
	}{
		ID:             event.ID,
		OrganizationID: event.OrganizationID,
		ActorType:      event.ActorType,
		ActorID:        event.ActorID,
		EventType:      eventType,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		Details:        detailsJSON,
		IPAddress:      event.IPAddress,
		UserAgent:      event.UserAgent,
		Success:        event.Success,
		ErrorMessage:   event.ErrorMessage,
		CreatedAt:      event.CreatedAt,
		SessionID:      event.SessionID,
		RequestID:      event.RequestID,
		Severity:       event.Severity,
	}, query, id)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFoundError("Audit event not found")
		}
		return nil, fmt.Errorf("failed to get audit event: %w", err)
	}

	// Convert JSON details back to map
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
			r.logger.Warn("Failed to unmarshal audit event details", "event_id", id, "error", err)
			event.Details = make(map[string]interface{})
		}
	} else {
		event.Details = make(map[string]interface{})
	}

	event.EventType = audit.AuditEventType(eventType)

	return &event, nil
}

// Query retrieves audit events based on query parameters with efficient filtering
func (r *PostgresAuditRepository) Query(ctx context.Context, query *audit.AuditQuery) ([]*audit.AuditEvent, int, error) {
	// Build WHERE clause
	whereConditions := []string{"1=1"}
	args := []interface{}{}
	argIndex := 1

	// Organization filter (always required for security)
	whereConditions = append(whereConditions, fmt.Sprintf("organization_id = $%d", argIndex))
	args = append(args, query.OrganizationID)
	argIndex++

	// Event types filter
	if len(query.EventTypes) > 0 {
		eventTypeStrs := make([]string, len(query.EventTypes))
		for i, et := range query.EventTypes {
			eventTypeStrs[i] = string(et)
		}
		whereConditions = append(whereConditions, fmt.Sprintf("event_type = ANY($%d)", argIndex))
		args = append(args, pq.Array(eventTypeStrs))
		argIndex++
	}

	// Actor ID filter
	if query.ActorID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("actor_id = $%d", argIndex))
		args = append(args, *query.ActorID)
		argIndex++
	}

	// Resource type filter
	if query.ResourceType != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("resource_type = $%d", argIndex))
		args = append(args, *query.ResourceType)
		argIndex++
	}

	// Resource ID filter
	if query.ResourceID != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("resource_id = $%d", argIndex))
		args = append(args, *query.ResourceID)
		argIndex++
	}

	// IP Address filter
	if query.IPAddress != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("ip_address = $%d", argIndex))
		args = append(args, *query.IPAddress)
		argIndex++
	}

	// Success filter
	if query.Success != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("success = $%d", argIndex))
		args = append(args, *query.Success)
		argIndex++
	}

	// Severity filter
	if query.Severity != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("severity = $%d", argIndex))
		args = append(args, *query.Severity)
		argIndex++
	}

	// Date range filters
	if query.StartDate != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *query.StartDate)
		argIndex++
	}

	if query.EndDate != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *query.EndDate)
		argIndex++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Get total count for pagination
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_events WHERE %s", whereClause)
	var totalCount int
	err := r.db.GetContext(ctx, &totalCount, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit events count: %w", err)
	}

	// Build main query with ordering and pagination
	orderBy := "created_at DESC" // Default ordering
	if query.SortBy != "" {
		direction := "DESC"
		if query.SortOrder == "asc" {
			direction = "ASC"
		}
		orderBy = fmt.Sprintf("%s %s", query.SortBy, direction)
	}

	mainQuery := fmt.Sprintf(`
		SELECT id, organization_id, actor_type, actor_id, event_type, 
		       resource_type, resource_id, details, ip_address, user_agent, 
		       success, error_message, created_at, session_id, request_id, severity
		FROM audit_events 
		WHERE %s 
		ORDER BY %s 
		LIMIT $%d OFFSET $%d`,
		whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, query.Limit, query.Offset)

	rows, err := r.db.QueryxContext(ctx, mainQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []*audit.AuditEvent
	for rows.Next() {
		var event audit.AuditEvent
		var detailsJSON []byte
		var eventType string

		err := rows.Scan(
			&event.ID,
			&event.OrganizationID,
			&event.ActorType,
			&event.ActorID,
			&eventType,
			&event.ResourceType,
			&event.ResourceID,
			&detailsJSON,
			&event.IPAddress,
			&event.UserAgent,
			&event.Success,
			&event.ErrorMessage,
			&event.CreatedAt,
			&event.SessionID,
			&event.RequestID,
			&event.Severity,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit event: %w", err)
		}

		// Convert JSON details back to map
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
				r.logger.Warn("Failed to unmarshal audit event details", "event_id", event.ID, "error", err)
				event.Details = make(map[string]interface{})
			}
		} else {
			event.Details = make(map[string]interface{})
		}

		event.EventType = audit.AuditEventType(eventType)
		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("row iteration error: %w", err)
	}

	return events, totalCount, nil
}

// DeleteOldEvents removes audit events older than the specified time
func (r *PostgresAuditRepository) DeleteOldEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM audit_events WHERE created_at < $1`
	
	result, err := r.db.ExecContext(ctx, query, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit events: %w", err)
	}

	deletedCount, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get deleted rows count: %w", err)
	}

	r.logger.Info("Deleted old audit events", "count", deletedCount, "cutoff_date", olderThan)
	return deletedCount, nil
}

// GetEventsByDateRange retrieves audit events within a specific date range
func (r *PostgresAuditRepository) GetEventsByDateRange(ctx context.Context, organizationID string, startDate, endDate time.Time) ([]*audit.AuditEvent, error) {
	query := `
		SELECT id, organization_id, actor_type, actor_id, event_type, 
		       resource_type, resource_id, details, ip_address, user_agent, 
		       success, error_message, created_at, session_id, request_id, severity
		FROM audit_events 
		WHERE organization_id = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY created_at DESC`

	rows, err := r.db.QueryxContext(ctx, query, organizationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit events by date range: %w", err)
	}
	defer rows.Close()

	var events []*audit.AuditEvent
	for rows.Next() {
		var event audit.AuditEvent
		var detailsJSON []byte
		var eventType string

		err := rows.Scan(
			&event.ID,
			&event.OrganizationID,
			&event.ActorType,
			&event.ActorID,
			&eventType,
			&event.ResourceType,
			&event.ResourceID,
			&detailsJSON,
			&event.IPAddress,
			&event.UserAgent,
			&event.Success,
			&event.ErrorMessage,
			&event.CreatedAt,
			&event.SessionID,
			&event.RequestID,
			&event.Severity,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit event: %w", err)
		}

		// Convert JSON details back to map
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
				r.logger.Warn("Failed to unmarshal audit event details", "event_id", event.ID, "error", err)
				event.Details = make(map[string]interface{})
			}
		} else {
			event.Details = make(map[string]interface{})
		}

		event.EventType = audit.AuditEventType(eventType)
		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return events, nil
}

// GetEventStatistics returns aggregated statistics for audit events
func (r *PostgresAuditRepository) GetEventStatistics(ctx context.Context, organizationID string, startDate, endDate time.Time) (*AuditStatistics, error) {
	// Get event counts by type
	typeQuery := `
		SELECT event_type, COUNT(*) as count
		FROM audit_events 
		WHERE organization_id = $1 AND created_at >= $2 AND created_at <= $3
		GROUP BY event_type`

	typeRows, err := r.db.QueryContext(ctx, typeQuery, organizationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get event type statistics: %w", err)
	}
	defer typeRows.Close()

	eventsByType := make(map[string]int)
	for typeRows.Next() {
		var eventType string
		var count int
		if err := typeRows.Scan(&eventType, &count); err != nil {
			return nil, err
		}
		eventsByType[eventType] = count
	}

	// Get event counts by severity
	severityQuery := `
		SELECT severity, COUNT(*) as count
		FROM audit_events 
		WHERE organization_id = $1 AND created_at >= $2 AND created_at <= $3
		GROUP BY severity`

	severityRows, err := r.db.QueryContext(ctx, severityQuery, organizationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get event severity statistics: %w", err)
	}
	defer severityRows.Close()

	eventsBySeverity := make(map[string]int)
	for severityRows.Next() {
		var severity string
		var count int
		if err := severityRows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		eventsBySeverity[severity] = count
	}

	// Get success/failure counts
	successQuery := `
		SELECT success, COUNT(*) as count
		FROM audit_events 
		WHERE organization_id = $1 AND created_at >= $2 AND created_at <= $3
		GROUP BY success`

	successRows, err := r.db.QueryContext(ctx, successQuery, organizationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get success statistics: %w", err)
	}
	defer successRows.Close()

	var successfulEvents, failedEvents int
	for successRows.Next() {
		var success bool
		var count int
		if err := successRows.Scan(&success, &count); err != nil {
			return nil, err
		}
		if success {
			successfulEvents = count
		} else {
			failedEvents = count
		}
	}

	// Get unique users and IPs count
	uniqueQuery := `
		SELECT 
			COUNT(DISTINCT actor_id) as unique_users,
			COUNT(DISTINCT ip_address) as unique_ips
		FROM audit_events 
		WHERE organization_id = $1 AND created_at >= $2 AND created_at <= $3
		AND actor_id IS NOT NULL`

	var uniqueUsers, uniqueIPs int
	err = r.db.QueryRowContext(ctx, uniqueQuery, organizationID, startDate, endDate).Scan(&uniqueUsers, &uniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique counts: %w", err)
	}

	totalEvents := successfulEvents + failedEvents

	return &AuditStatistics{
		OrganizationID:   organizationID,
		Period:           fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		StartDate:        startDate,
		EndDate:          endDate,
		TotalEvents:      totalEvents,
		SuccessfulEvents: successfulEvents,
		FailedEvents:     failedEvents,
		EventsByType:     eventsByType,
		EventsBySeverity: eventsBySeverity,
		UniqueUserCount:  uniqueUsers,
		UniqueIPCount:    uniqueIPs,
	}, nil
}

// CreateIndexes creates optimized database indexes for audit events
func (r *PostgresAuditRepository) CreateIndexes(ctx context.Context) error {
	indexes := []string{
		// Primary index on organization and created_at for time-based queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_org_created_at 
		 ON audit_events (organization_id, created_at DESC)`,

		// Index for event type filtering
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_event_type 
		 ON audit_events (organization_id, event_type, created_at DESC)`,

		// Index for actor-based queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_actor 
		 ON audit_events (organization_id, actor_id, created_at DESC) 
		 WHERE actor_id IS NOT NULL`,

		// Index for resource-based queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_resource 
		 ON audit_events (organization_id, resource_type, resource_id, created_at DESC)`,

		// Index for success/failure analysis
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_success 
		 ON audit_events (organization_id, success, created_at DESC)`,

		// Index for severity-based queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_severity 
		 ON audit_events (organization_id, severity, created_at DESC)`,

		// Index for IP-based queries (security analysis)
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_ip 
		 ON audit_events (organization_id, ip_address, created_at DESC)`,

		// Composite index for complex queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_composite 
		 ON audit_events (organization_id, event_type, success, severity, created_at DESC)`,

		// Index for cleanup operations (retention policy)
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_cleanup 
		 ON audit_events (created_at) 
		 WHERE created_at < NOW() - INTERVAL '1 year'`,
	}

	for _, indexSQL := range indexes {
		if _, err := r.db.ExecContext(ctx, indexSQL); err != nil {
			r.logger.Error("Failed to create audit index", "sql", indexSQL, "error", err)
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	r.logger.Info("All audit event indexes created successfully")
	return nil
}

// ArchiveOldEvents moves old events to an archive table for long-term storage
func (r *PostgresAuditRepository) ArchiveOldEvents(ctx context.Context, archiveBefore time.Time) (int64, error) {
	// Create archive table if it doesn't exist
	createArchiveTableSQL := `
		CREATE TABLE IF NOT EXISTS audit_events_archive (
			LIKE audit_events INCLUDING ALL
		)`
	
	if _, err := r.db.ExecContext(ctx, createArchiveTableSQL); err != nil {
		return 0, fmt.Errorf("failed to create archive table: %w", err)
	}

	// Start transaction
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert old records into archive
	insertArchiveSQL := `
		INSERT INTO audit_events_archive 
		SELECT * FROM audit_events 
		WHERE created_at < $1`
	
	result, err := tx.ExecContext(ctx, insertArchiveSQL, archiveBefore)
	if err != nil {
		return 0, fmt.Errorf("failed to archive events: %w", err)
	}

	archivedCount, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get archived rows count: %w", err)
	}

	// Delete old records from main table
	deleteSQL := `DELETE FROM audit_events WHERE created_at < $1`
	
	_, err = tx.ExecContext(ctx, deleteSQL, archiveBefore)
	if err != nil {
		return 0, fmt.Errorf("failed to delete archived events: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit archive transaction: %w", err)
	}

	r.logger.Info("Archived old audit events", "count", archivedCount, "cutoff_date", archiveBefore)
	return archivedCount, nil
}

// AuditStatistics represents aggregated audit statistics
type AuditStatistics struct {
	OrganizationID   string            `json:"organization_id"`
	Period           string            `json:"period"`
	StartDate        time.Time         `json:"start_date"`
	EndDate          time.Time         `json:"end_date"`
	TotalEvents      int               `json:"total_events"`
	SuccessfulEvents int               `json:"successful_events"`
	FailedEvents     int               `json:"failed_events"`
	EventsByType     map[string]int    `json:"events_by_type"`
	EventsBySeverity map[string]int    `json:"events_by_severity"`
	UniqueUserCount  int               `json:"unique_user_count"`
	UniqueIPCount    int               `json:"unique_ip_count"`
}