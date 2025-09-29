package database

import (
	"context"
	"fmt"
	"time"

	"n8n-pro/pkg/logger"

	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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

// Service provides database operations
type Service struct {
	gormDB *gorm.DB
	pgxPool *pgxpool.Pool
	config *Config
	logger logger.Logger
}

// New creates a new database service
func New(config *Config, log logger.Logger) (*Service, error) {
	if log == nil {
		log = logger.New("database")
	}

	// GORM connection string
	gormConnStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.Database,
		config.SSLMode,
	)

	// Initialize GORM
	gormDB, err := gorm.Open(postgres.Open(gormConnStr), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool for GORM
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	if config.MaxConns > 0 {
		sqlDB.SetMaxOpenConns(int(config.MaxConns))
	} else {
		sqlDB.SetMaxOpenConns(25)
	}

	if config.MinConns > 0 {
		sqlDB.SetMaxIdleConns(int(config.MinConns))
	} else {
		sqlDB.SetMaxIdleConns(5)
	}

	if config.MaxConnLife > 0 {
		sqlDB.SetConnMaxLifetime(config.MaxConnLife)
	} else {
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	if config.MaxConnIdle > 0 {
		sqlDB.SetConnMaxIdleTime(config.MaxConnIdle)
	} else {
		sqlDB.SetConnMaxIdleTime(time.Minute * 30)
	}

	// Pgx connection string
	pgxConnStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
		config.SSLMode,
	)

	// Initialize Pgx pool
	pgxPool, err := pgxpool.New(context.Background(), pgxConnStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}

	// Test connection
	if err := pgxPool.Ping(context.Background()); err != nil {
		pgxPool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("Database service initialized",
		"host", config.Host,
		"database", config.Database,
		"max_conns", config.MaxConns,
		"min_conns", config.MinConns,
	)

	return &Service{
		gormDB:  gormDB,
		pgxPool: pgxPool,
		config:  config,
		logger:  log,
	}, nil
}

// GetGormDB returns the GORM database instance
func (s *Service) GetGormDB() *gorm.DB {
	return s.gormDB
}

// GetPgxPool returns the Pgx connection pool
func (s *Service) GetPgxPool() *pgxpool.Pool {
	return s.pgxPool
}

// Close closes the database connections
func (s *Service) Close() error {
	errs := []error{}

	// Close GORM connections
	if sqlDB, err := s.gormDB.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close gorm db: %w", err))
		}
	}

	// Close Pgx pool
	s.pgxPool.Close()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing database: %v", errs)
	}

	s.logger.Info("Database connections closed")

	return nil
}

// Health checks database health
func (s *Service) Health(ctx context.Context) error {
	// Test GORM connection
	var result int64
	if err := s.gormDB.Raw("SELECT 1").Scan(&result).Error; err != nil {
		return fmt.Errorf("gorm health check failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("gorm health check returned unexpected result: %d", result)
	}

	// Test Pgx connection
	if err := s.pgxPool.Ping(ctx); err != nil {
		return fmt.Errorf("pgx health check failed: %w", err)
	}

	return nil
}

// Migrate runs database migrations
func (s *Service) Migrate(ctx context.Context, models ...interface{}) error {
	s.logger.Info("Running database migrations")

	if err := s.gormDB.WithContext(ctx).AutoMigrate(models...); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	s.logger.Info("Database migrations completed successfully")

	return nil
}

// Ping tests database connectivity
func (s *Service) Ping(ctx context.Context) error {
	// Test GORM connection
	var result int64
	if err := s.gormDB.Raw("SELECT 1").Scan(&result).Error; err != nil {
		return err
	}

	if result != 1 {
		return fmt.Errorf("ping returned unexpected result: %d", result)
	}

	return nil
}

// Transaction executes a function within a transaction
func (s *Service) Transaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return s.gormDB.WithContext(ctx).Transaction(fn)
}

// DefaultConfig returns default database configuration
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