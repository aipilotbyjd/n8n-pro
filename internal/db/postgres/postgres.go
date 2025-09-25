package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"n8n-pro/pkg/logger"
)

// DB represents a PostgreSQL database connection
type DB struct {
	pool   *pgxpool.Pool
	logger logger.Logger
}

// Config holds database configuration
type Config struct {
	Host         string
	Port         int
	Database     string
	Username     string
	Password     string
	SSLMode      string
	MaxConns     int32
	MinConns     int32
	MaxConnLife  time.Duration
	MaxConnIdle  time.Duration
	HealthCheck  time.Duration
}

// New creates a new database connection
func New(cfg *Config, log logger.Logger) (*DB, error) {
	if log == nil {
		log = logger.New("postgres")
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.SSLMode,
	)

	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Configure connection pool
	if cfg.MaxConns > 0 {
		poolConfig.MaxConns = cfg.MaxConns
	} else {
		poolConfig.MaxConns = 25
	}
	
	if cfg.MinConns > 0 {
		poolConfig.MinConns = cfg.MinConns
	} else {
		poolConfig.MinConns = 5
	}

	if cfg.MaxConnLife > 0 {
		poolConfig.MaxConnLifetime = cfg.MaxConnLife
	} else {
		poolConfig.MaxConnLifetime = time.Hour
	}

	if cfg.MaxConnIdle > 0 {
		poolConfig.MaxConnIdleTime = cfg.MaxConnIdle
	} else {
		poolConfig.MaxConnIdleTime = time.Minute * 30
	}

	if cfg.HealthCheck > 0 {
		poolConfig.HealthCheckPeriod = cfg.HealthCheck
	} else {
		poolConfig.HealthCheckPeriod = time.Minute
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("Database connection established", 
		"host", cfg.Host, 
		"database", cfg.Database,
		"max_conns", poolConfig.MaxConns,
		"min_conns", poolConfig.MinConns,
	)

	return &DB{
		pool:   pool,
		logger: log,
	}, nil
}

// Close closes the database connection
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
		db.logger.Info("Database connection closed")
	}
}

// Query executes a query that returns rows
func (db *DB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return db.pool.Query(ctx, sql, args...)
}

// QueryRow executes a query that returns a single row
func (db *DB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

// Exec executes a query without returning rows
func (db *DB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.pool.Exec(ctx, sql, args...)
}

// Begin starts a new transaction
func (db *DB) Begin(ctx context.Context) (pgx.Tx, error) {
	return db.pool.Begin(ctx)
}

// BeginTx starts a new transaction with options
func (db *DB) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	return db.pool.BeginTx(ctx, txOptions)
}

// Ping tests database connectivity
func (db *DB) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}

// Stats returns connection pool statistics
func (db *DB) Stats() *pgxpool.Stat {
	return db.pool.Stat()
}

// Health checks database health
func (db *DB) Health(ctx context.Context) error {
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Test a simple query
	var result int
	if err := db.QueryRow(ctx, "SELECT 1").Scan(&result); err != nil {
		return fmt.Errorf("database query test failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("database query returned unexpected result: %d", result)
	}

	return nil
}

// DefaultConfig returns a default database configuration
func DefaultConfig() *Config {
	return &Config{
		Host:        "localhost",
		Port:        5432,
		Database:    "n8n_pro",
		Username:    "postgres",
		Password:    "password",
		SSLMode:     "disable",
		MaxConns:    25,
		MinConns:    5,
		MaxConnLife: time.Hour,
		MaxConnIdle: time.Minute * 30,
		HealthCheck: time.Minute,
	}
}