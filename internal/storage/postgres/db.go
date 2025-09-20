package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"n8n-pro/internal/config"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/metrics"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DB represents a PostgreSQL database connection
type DB struct {
	pool      *pgxpool.Pool
	config    *config.DatabaseConfig
	logger    logger.Logger
	metrics   *metrics.Metrics
	mu        sync.RWMutex
	connected bool
	stats     *ConnectionStats
}

// ConnectionStats holds database connection statistics
type ConnectionStats struct {
	OpenConnections   int32
	IdleConnections   int32
	InUseConnections  int32
	WaitCount         int64
	WaitDuration      time.Duration
	MaxIdleClosed     int64
	MaxIdleTimeClosed int64
	MaxLifetimeClosed int64
}

// QueryResult represents the result of a database query
type QueryResult struct {
	Rows    pgx.Rows
	Columns []string
	Error   error
}

// TransactionFunc represents a function that executes within a transaction
type TransactionFunc func(tx pgx.Tx) error

// New creates a new PostgreSQL database connection
func New(config *config.DatabaseConfig) (*DB, error) {
	if config == nil {
		return nil, errors.ValidationError(errors.CodeMissingField, "database config is required")
	}

	log := logger.New("postgres")

	db := &DB{
		config:  config,
		logger:  log,
		metrics: metrics.GetGlobal(),
		stats:   &ConnectionStats{},
	}

	if err := db.Connect(context.Background()); err != nil {
		return nil, err
	}

	return db, nil
}

// Connect establishes a connection to the PostgreSQL database
func (db *DB) Connect(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.connected {
		return nil
	}

	// Build connection configuration
	poolConfig, err := db.buildPoolConfig()
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseConnection,
			"failed to build pool configuration")
	}

	// Create connection pool with retry
	pool, err := db.connectWithRetry(ctx, poolConfig)
	if err != nil {
		return err
	}

	db.pool = pool
	db.connected = true

	db.logger.Info("Connected to PostgreSQL database",
		"host", db.config.Host,
		"port", db.config.Port,
		"database", db.config.Database,
		"max_connections", db.config.MaxOpenConnections,
	)

	// Start connection monitoring
	go db.monitorConnections()

	return nil
}

// buildPoolConfig creates a pgxpool configuration
func (db *DB) buildPoolConfig() (*pgxpool.Config, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		db.config.Host,
		db.config.Port,
		db.config.Username,
		db.config.Password,
		db.config.Database,
		db.config.SSLMode,
	)

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	config.MaxConns = int32(db.config.MaxOpenConnections)
	config.MinConns = int32(db.config.MaxIdleConnections)
	config.MaxConnLifetime = db.config.ConnectionLifetime
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	// Configure connection timeouts
	config.ConnConfig.ConnectTimeout = db.config.ConnectionTimeout
	config.ConnConfig.Config.ConnectTimeout = db.config.ConnectionTimeout

	// Add connection hooks for logging and metrics
	config.BeforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
		db.logger.Debug("Establishing new database connection",
			"host", config.Host,
			"database", config.Database,
		)
		return nil
	}

	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		db.logger.Debug("Database connection established")
		db.metrics.UpdateDBStats(
			int(db.pool.Stat().TotalConns()),
			int(db.pool.Stat().IdleConns()),
			int(db.pool.Stat().AcquiredConns()),
		)
		return nil
	}

	config.BeforeClose = func(conn *pgx.Conn) {
		db.logger.Debug("Closing database connection")
	}

	return config, nil
}

// connectWithRetry attempts to connect with retry logic
func (db *DB) connectWithRetry(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	var pool *pgxpool.Pool
	var lastErr error

	for i := 0; i < db.config.RetryAttempts; i++ {
		if i > 0 {
			db.logger.Warn("Retrying database connection",
				"attempt", i+1,
				"max_attempts", db.config.RetryAttempts,
				"last_error", lastErr.Error(),
			)
			time.Sleep(db.config.RetryDelay)
		}

		var err error
		pool, err = pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			lastErr = err
			continue
		}

		// Test the connection
		if err = pool.Ping(ctx); err != nil {
			pool.Close()
			lastErr = err
			continue
		}

		return pool, nil
	}

	return nil, errors.Wrap(lastErr, errors.ErrorTypeDatabase, errors.CodeDatabaseConnection,
		fmt.Sprintf("failed to connect after %d attempts", db.config.RetryAttempts))
}

// Close closes the database connection
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.connected || db.pool == nil {
		return nil
	}

	db.pool.Close()
	db.connected = false

	db.logger.Info("Database connection closed")
	return nil
}

// Ping checks if the database connection is alive
func (db *DB) Ping(ctx context.Context) error {
	if !db.connected || db.pool == nil {
		return errors.New(errors.ErrorTypeDatabase, errors.CodeDatabaseConnection,
			"database not connected")
	}

	return db.pool.Ping(ctx)
}

// Query executes a query and returns rows
func (db *DB) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return db.QueryWithMetrics(ctx, "query", query, args...)
}

// QueryRow executes a query that is expected to return at most one row
func (db *DB) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		db.metrics.RecordDBQuery("query_row", "unknown", "success", duration)

		if duration > db.config.SlowQueryThreshold {
			db.logger.Warn("Slow query detected",
				"query", query,
				"duration", duration,
				"threshold", db.config.SlowQueryThreshold,
			)
		}

		if db.config.EnableQueryLogging {
			db.logger.Debug("Query executed",
				"query", query,
				"duration", duration,
				"args", args,
			)
		}
	}()

	return db.pool.QueryRow(ctx, query, args...)
}

// Exec executes a query without returning any rows
func (db *DB) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.ExecWithMetrics(ctx, "exec", query, args...)
}

// QueryWithMetrics executes a query with metrics collection
func (db *DB) QueryWithMetrics(ctx context.Context, operation, query string, args ...interface{}) (pgx.Rows, error) {
	start := time.Now()
	status := "success"

	defer func() {
		duration := time.Since(start)
		db.metrics.RecordDBQuery(operation, "unknown", status, duration)

		if duration > db.config.SlowQueryThreshold {
			db.logger.Warn("Slow query detected",
				"operation", operation,
				"query", query,
				"duration", duration,
				"threshold", db.config.SlowQueryThreshold,
			)
		}

		if db.config.EnableQueryLogging {
			db.logger.Debug("Query executed",
				"operation", operation,
				"query", query,
				"duration", duration,
				"args", args,
			)
		}
	}()

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		status = "error"
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			fmt.Sprintf("query failed: %s", operation))
	}

	return rows, nil
}

// ExecWithMetrics executes a command with metrics collection
func (db *DB) ExecWithMetrics(ctx context.Context, operation, query string, args ...interface{}) (pgconn.CommandTag, error) {
	start := time.Now()
	status := "success"

	defer func() {
		duration := time.Since(start)
		db.metrics.RecordDBQuery(operation, "unknown", status, duration)

		if duration > db.config.SlowQueryThreshold {
			db.logger.Warn("Slow query detected",
				"operation", operation,
				"query", query,
				"duration", duration,
				"threshold", db.config.SlowQueryThreshold,
			)
		}

		if db.config.EnableQueryLogging {
			db.logger.Debug("Query executed",
				"operation", operation,
				"query", query,
				"duration", duration,
				"args", args,
			)
		}
	}()

	result, err := db.pool.Exec(ctx, query, args...)
	if err != nil {
		status = "error"
		return pgconn.CommandTag{}, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			fmt.Sprintf("exec failed: %s", operation))
	}

	return result, nil
}

// BeginTx starts a transaction with the given options
func (db *DB) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if !db.connected || db.pool == nil {
		return nil, errors.New(errors.ErrorTypeDatabase, errors.CodeDatabaseConnection,
			"database not connected")
	}

	tx, err := db.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to begin transaction")
	}

	db.logger.Debug("Transaction started")
	return tx, nil
}

// Begin starts a transaction with default options
func (db *DB) Begin(ctx context.Context) (pgx.Tx, error) {
	return db.BeginTx(ctx, pgx.TxOptions{})
}

// RunInTransaction executes a function within a transaction
func (db *DB) RunInTransaction(ctx context.Context, fn TransactionFunc) error {
	return db.RunInTransactionWithOptions(ctx, pgx.TxOptions{}, fn)
}

// RunInTransactionWithOptions executes a function within a transaction with options
func (db *DB) RunInTransactionWithOptions(ctx context.Context, options pgx.TxOptions, fn TransactionFunc) error {
	tx, err := db.BeginTx(ctx, options)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback(ctx)
			panic(r)
		}
	}()

	err = fn(tx)
	if err != nil {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			db.logger.Error("Failed to rollback transaction",
				"error", rollbackErr,
				"original_error", err,
			)
		}
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"failed to commit transaction")
	}

	db.logger.Debug("Transaction committed")
	return nil
}

// GetPool returns the underlying connection pool
func (db *DB) GetPool() *pgxpool.Pool {
	return db.pool
}

// Stats returns connection statistics
func (db *DB) Stats() *ConnectionStats {
	if !db.connected || db.pool == nil {
		return &ConnectionStats{}
	}

	stats := db.pool.Stat()

	db.mu.RLock()
	defer db.mu.RUnlock()

	return &ConnectionStats{
		OpenConnections:  stats.TotalConns(),
		IdleConnections:  stats.IdleConns(),
		InUseConnections: stats.AcquiredConns(),
		WaitCount:        stats.EmptyAcquireCount(),
		WaitDuration:     stats.AcquireDuration(),
	}
}

// Health returns the health status of the database
func (db *DB) Health(ctx context.Context) error {
	if !db.connected {
		return errors.New(errors.ErrorTypeDatabase, errors.CodeDatabaseConnection,
			"database not connected")
	}

	// Test with a simple query
	var result int
	err := db.pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"database health check failed")
	}

	if result != 1 {
		return errors.New(errors.ErrorTypeDatabase, errors.CodeDatabaseQuery,
			"database health check returned unexpected result")
	}

	return nil
}

// monitorConnections monitors connection pool statistics
func (db *DB) monitorConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !db.connected || db.pool == nil {
				return
			}

			stats := db.Stats()
			db.metrics.UpdateDBStats(
				int(stats.OpenConnections),
				int(stats.IdleConnections),
				int(stats.InUseConnections),
			)

			// Log warnings for connection pool issues
			if stats.OpenConnections >= int32(db.config.MaxOpenConnections)*80/100 {
				db.logger.Warn("High connection pool usage",
					"open_connections", stats.OpenConnections,
					"max_connections", db.config.MaxOpenConnections,
					"usage_percent", (stats.OpenConnections*100)/int32(db.config.MaxOpenConnections),
				)
			}

			if stats.WaitCount > 0 {
				db.logger.Warn("Connection pool wait detected",
					"wait_count", stats.WaitCount,
					"wait_duration", stats.WaitDuration,
				)
			}
		}
	}
}

// IsConnected returns true if the database is connected
func (db *DB) IsConnected() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.connected
}

// Config returns the database configuration
func (db *DB) Config() *config.DatabaseConfig {
	return db.config
}

// DatabaseInfo returns information about the connected database
type DatabaseInfo struct {
	Version    string           `json:"version"`
	Name       string           `json:"name"`
	Host       string           `json:"host"`
	Port       int              `json:"port"`
	Connected  bool             `json:"connected"`
	Uptime     string           `json:"uptime"`
	Statistics *ConnectionStats `json:"statistics"`
}

// GetDatabaseInfo returns detailed information about the database connection
func (db *DB) GetDatabaseInfo(ctx context.Context) (*DatabaseInfo, error) {
	info := &DatabaseInfo{
		Name:       db.config.Database,
		Host:       db.config.Host,
		Port:       db.config.Port,
		Connected:  db.IsConnected(),
		Statistics: db.Stats(),
	}

	if db.connected && db.pool != nil {
		// Get database version
		var version string
		err := db.pool.QueryRow(ctx, "SELECT version()").Scan(&version)
		if err == nil {
			info.Version = version
		}

		// Get database uptime
		var uptime string
		err = db.pool.QueryRow(ctx, "SELECT date_trunc('second', current_timestamp - pg_postmaster_start_time()) as uptime").Scan(&uptime)
		if err == nil {
			info.Uptime = uptime
		}
	}

	return info, nil
}

// Backup creates a logical backup of the database (placeholder)
func (db *DB) Backup(ctx context.Context, options BackupOptions) error {
	// This would implement database backup functionality
	// For now, this is a placeholder
	return errors.New(errors.ErrorTypeConfiguration, errors.CodeInternal,
		"database backup not implemented")
}

// BackupOptions holds backup configuration
type BackupOptions struct {
	Path          string
	Format        string
	CompressLevel int
	IncludeSchema bool
	IncludeData   bool
	ExcludeTables []string
}

// Restore restores a database from a backup (placeholder)
func (db *DB) Restore(ctx context.Context, backupPath string, options RestoreOptions) error {
	// This would implement database restore functionality
	// For now, this is a placeholder
	return errors.New(errors.ErrorTypeConfiguration, errors.CodeInternal,
		"database restore not implemented")
}

// RestoreOptions holds restore configuration
type RestoreOptions struct {
	CleanFirst    bool
	DataOnly      bool
	SchemaOnly    bool
	ExcludeTables []string
}
