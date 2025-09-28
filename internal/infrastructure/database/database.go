// Package database provides database connection and configuration for n8n-pro
package database

import (
	"context"
	"fmt"
	"log"
	"os"

	"n8n-pro/internal/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// Database wraps GORM database instance with additional functionality
type Database struct {
	*gorm.DB
	config *config.DatabaseConfig
}

// DB is the global database instance
var DB *Database

// Initialize initializes the database connection
func Initialize(cfg *config.DatabaseConfig) (*Database, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		cfg.Host,
		cfg.Username,
		cfg.Password,
		cfg.Database,
		cfg.Port,
		cfg.SSLMode,
	)

	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	if cfg.EnableQueryLogging {
		gormLogger = logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold:             cfg.SlowQueryThreshold,
				LogLevel:                  getLogLevel(cfg),
				IgnoreRecordNotFoundError: true,
				Colorful:                  true,
			},
		)
	} else {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	// GORM configuration
	gormConfig := &gorm.Config{
		Logger: gormLogger,
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "",
			SingularTable: false,
			NameReplacer:  nil,
		},
		DisableForeignKeyConstraintWhenMigrating: false,
		SkipDefaultTransaction:                   true, // Better performance
		PrepareStmt:                              true, // Prepared statements
		CreateBatchSize:                          1000, // Batch size for bulk operations
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL database for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConnections)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConnections)
	sqlDB.SetConnMaxLifetime(cfg.ConnectionLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectionTimeout)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{
		DB:     db,
		config: cfg,
	}

	// Auto-migrate if enabled
	if cfg.EnableMigrations {
		if err := database.AutoMigrate(); err != nil {
			return nil, fmt.Errorf("failed to run auto-migration: %w", err)
		}
	}

	// Set global database instance
	DB = database

	return database, nil
}

// Close closes the database connection
func (db *Database) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Health returns database health status
func (db *Database) Health(ctx context.Context) map[string]interface{} {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return map[string]interface{}{
			"status": "unhealthy",
			"error":  err.Error(),
		}
	}

	stats := sqlDB.Stats()
	
	// Test connection
	if err := sqlDB.PingContext(ctx); err != nil {
		return map[string]interface{}{
			"status": "unhealthy",
			"error":  err.Error(),
			"stats":  stats,
		}
	}

	return map[string]interface{}{
		"status":                "healthy",
		"open_connections":      stats.OpenConnections,
		"idle_connections":      stats.Idle,
		"in_use_connections":    stats.InUse,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration,
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}

// Transaction executes a function within a database transaction
func (db *Database) Transaction(fn func(*gorm.DB) error) error {
	return db.DB.Transaction(fn)
}

// WithContext returns a new DB instance with context
func (db *Database) WithContext(ctx context.Context) *gorm.DB {
	return db.DB.WithContext(ctx)
}

// AutoMigrate runs database migrations using the production-ready migration system
func (db *Database) AutoMigrate() error {
	log.Println("Running GORM migrations...")
	
	// Use the new migration manager
	migrationManager := NewMigrationManager(db)
	
	// Run all migrations in proper order
	err := migrationManager.RunMigrations()
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	
	log.Println("GORM migrations completed successfully")
	return nil
}

// getLogLevel converts config log level to GORM log level
func getLogLevel(cfg *config.DatabaseConfig) logger.LogLevel {
	if !cfg.EnableQueryLogging {
		return logger.Silent
	}
	
	// You can make this configurable based on your config
	return logger.Info
}

// Seed runs database seeders
func (db *Database) Seed() error {
	log.Println("Running database seeders...")
	
	// Add your seeders here
	// Example:
	// if err := seedOrganizations(db.DB); err != nil {
	//     return fmt.Errorf("failed to seed organizations: %w", err)
	// }
	
	log.Println("Database seeding completed successfully")
	return nil
}

// GetDB returns the global database instance
func GetDB() *Database {
	if DB == nil {
		panic("Database not initialized. Call Initialize() first.")
	}
	return DB
}

// Must panics if database operation fails (use sparingly, mainly for initialization)
func Must(err error) {
	if err != nil {
		panic(fmt.Sprintf("Database error: %v", err))
	}
}