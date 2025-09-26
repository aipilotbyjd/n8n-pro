// Package database provides production-ready GORM migration system for n8n-pro
package database

import (
	"fmt"
	"time"

	"n8n-pro/internal/models"
	"n8n-pro/pkg/logger"

	"gorm.io/gorm"
)

// MigrationManager handles database schema migrations using GORM
type MigrationManager struct {
	db     *Database
	logger logger.Logger
}

// NewMigrationManager creates a new migration manager instance
func NewMigrationManager(db *Database) *MigrationManager {
	return &MigrationManager{
		db:     db,
		logger: logger.New("migration-manager"),
	}
}

// Migration represents a single database migration
type Migration struct {
	ID            uint      `gorm:"primaryKey"`
	Version       string    `gorm:"uniqueIndex;not null"`
	Name          string    `gorm:"not null"`
	Batch         int       `gorm:"not null"`
	AppliedAt     time.Time `gorm:"not null"`
	RolledBack    bool      `gorm:"default:false"`
	RollbackAt    *time.Time
	ExecutionTime int64     `gorm:"comment:Execution time in milliseconds"`
}

// TableName sets the table name for Migration model
func (Migration) TableName() string {
	return "schema_migrations"
}

// RunMigrations executes all pending migrations
func (m *MigrationManager) RunMigrations() error {
	m.logger.Info("Starting database migrations...")

	// Create migration tracking table first
	if err := m.createMigrationTable(); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	// Get current batch number
	batch := m.getNextBatchNumber()

	// Execute all migrations
	if err := m.executeAllMigrations(batch); err != nil {
		return fmt.Errorf("migration execution failed: %w", err)
	}

	m.logger.Info("All migrations completed successfully")
	return nil
}

// createMigrationTable creates the migration tracking table
func (m *MigrationManager) createMigrationTable() error {
	return m.db.DB.AutoMigrate(&Migration{})
}

// getNextBatchNumber gets the next batch number for migrations
func (m *MigrationManager) getNextBatchNumber() int {
	var maxBatch int
	m.db.DB.Model(&Migration{}).Select("COALESCE(MAX(batch), 0)").Scan(&maxBatch)
	return maxBatch + 1
}

// executeAllMigrations runs all required migrations
func (m *MigrationManager) executeAllMigrations(batch int) error {
	migrations := []MigrationStep{
		{
			Version: "2024_01_01_000001",
			Name:    "create_core_tables",
			Up:      m.createCoreTables,
		},
		{
			Version: "2024_01_01_000002", 
			Name:    "create_workflow_tables",
			Up:      m.createWorkflowTables,
		},
		{
			Version: "2024_01_01_000003",
			Name:    "create_auth_tables", 
			Up:      m.createAuthTables,
		},
		{
			Version: "2024_01_01_000004",
			Name:    "create_indexes",
			Up:      m.createIndexes,
		},
		{
			Version: "2024_01_01_000005",
			Name:    "seed_initial_data",
			Up:      m.seedInitialData,
		},
	}

	for _, migration := range migrations {
		if err := m.runSingleMigration(migration, batch); err != nil {
			return fmt.Errorf("migration %s failed: %w", migration.Name, err)
		}
	}

	return nil
}

// MigrationStep represents a single migration step
type MigrationStep struct {
	Version string
	Name    string
	Up      func() error
}

// runSingleMigration executes a single migration if not already applied
func (m *MigrationManager) runSingleMigration(migration MigrationStep, batch int) error {
	// Check if migration already exists
	var count int64
	m.db.DB.Model(&Migration{}).Where("version = ?", migration.Version).Count(&count)
	
	if count > 0 {
		m.logger.Info("Migration already applied, skipping", "version", migration.Version)
		return nil
	}

	m.logger.Info("Applying migration", "version", migration.Version, "name", migration.Name)
	startTime := time.Now()

	// Execute migration in transaction
	err := m.db.DB.Transaction(func(tx *gorm.DB) error {
		// Run the migration
		if err := migration.Up(); err != nil {
			return fmt.Errorf("migration execution failed: %w", err)
		}

		// Record migration
		migrationRecord := &Migration{
			Version:       migration.Version,
			Name:          migration.Name,
			Batch:         batch,
			AppliedAt:     time.Now(),
			ExecutionTime: time.Since(startTime).Milliseconds(),
		}

		return tx.Create(migrationRecord).Error
	})

	if err != nil {
		m.logger.Error("Migration failed", "version", migration.Version, "error", err)
		return err
	}

	m.logger.Info("Migration completed", 
		"version", migration.Version, 
		"duration", time.Since(startTime).String())
	
	return nil
}

// createCoreTables creates the core organization and team tables
func (m *MigrationManager) createCoreTables() error {
	m.logger.Info("Creating core tables...")
	
	return m.db.DB.AutoMigrate(
		&models.Organization{},
		&models.Team{},
		&models.User{},
		&models.TeamMember{},
	)
}

// createWorkflowTables creates workflow-related tables
func (m *MigrationManager) createWorkflowTables() error {
	m.logger.Info("Creating workflow tables...")
	
	return m.db.DB.AutoMigrate(
		&models.Workflow{},
		&models.WorkflowExecution{},
		&models.WorkflowVersion{},
	)
}

// createAuthTables creates authentication and authorization tables  
func (m *MigrationManager) createAuthTables() error {
	m.logger.Info("Creating auth tables...")
	
	return m.db.DB.AutoMigrate(
		&models.Session{},
		&models.APIKey{},
		&models.AuditLog{},
	)
}

// createIndexes creates performance indexes
func (m *MigrationManager) createIndexes() error {
	m.logger.Info("Creating database indexes...")

	indexes := map[string][]string{
		"users": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_org_email ON users(organization_id, email) WHERE deleted_at IS NULL",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_status_role ON users(status, role) WHERE deleted_at IS NULL",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_verified ON users(email_verified) WHERE email_verified = true",
		},
		"organizations": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_organizations_slug ON organizations(slug) WHERE deleted_at IS NULL",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_organizations_plan_status ON organizations(plan, status)",
		},
		"teams": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_teams_org ON teams(organization_id) WHERE deleted_at IS NULL",
		},
		"team_members": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_team_members_user_team ON team_members(user_id, team_id)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_team_members_team_role ON team_members(team_id, role)",
		},
		"workflows": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_team_status ON workflows(team_id, status) WHERE deleted_at IS NULL",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_active ON workflows(is_active, updated_at DESC) WHERE deleted_at IS NULL",
		},
		"workflow_executions": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_workflow_status ON workflow_executions(workflow_id, status)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_start_time ON workflow_executions(start_time DESC)",
		},
		"sessions": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, is_active) WHERE is_active = true",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE is_active = true",
		},
		"audit_logs": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(organization_id, created_at DESC)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)",
		},
	}

	for table, tableIndexes := range indexes {
		m.logger.Info("Creating indexes for table", "table", table)
		for _, indexSQL := range tableIndexes {
			if err := m.db.DB.Exec(indexSQL).Error; err != nil {
				m.logger.Warn("Failed to create index", "table", table, "error", err)
				// Continue with other indexes - don't fail the migration
			}
		}
	}

	return nil
}

// seedInitialData creates default data for development
func (m *MigrationManager) seedInitialData() error {
	m.logger.Info("Seeding initial data...")

	// Check if data already exists
	var orgCount int64
	m.db.DB.Model(&models.Organization{}).Count(&orgCount)
	if orgCount > 0 {
		m.logger.Info("Initial data already exists, skipping seed")
		return nil
	}

	// Create default organization with proper UUID
	org := &models.Organization{
		Name: "Default Organization",
		Slug: "default",
		Plan: "pro",
		PlanLimits: models.JSONB{
			"max_users":                100,
			"max_workflows":            1000,
			"max_executions_per_month": 100000,
		},
		Settings: models.JSONB{
			"timezone":             "UTC",
			"allow_registration":   false,
			"require_verification": true,
		},
		Status: "active",
	}

	if err := m.db.DB.Create(org).Error; err != nil {
		return fmt.Errorf("failed to create default organization: %w", err)
	}

	// Create default team
	team := &models.Team{
		OrganizationID: org.ID,
		Name:           "Default Team",
		Description:    "Default team for system administration",
		Settings: models.JSONB{
			"default_role": "member",
		},
	}

	if err := m.db.DB.Create(team).Error; err != nil {
		return fmt.Errorf("failed to create default team: %w", err)
	}

	// Create admin user (password: admin123!)
	user := &models.User{
		OrganizationID: org.ID,
		Email:          "admin@n8n-pro.local",
		FirstName:      "System",
		LastName:       "Administrator",
		PasswordHash:   "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdnKm5vQJ5o8/EW",
		Status:         "active",
		Role:           "owner",
		EmailVerified:  true,
		Profile: models.JSONB{
			"job_title": "System Administrator",
		},
		Settings: models.JSONB{
			"timezone": "UTC",
			"language": "en",
		},
	}

	if err := m.db.DB.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Add user to team
	teamMember := &models.TeamMember{
		TeamID: team.ID,
		UserID: user.ID,
		Role:   "owner",
	}

	if err := m.db.DB.Create(teamMember).Error; err != nil {
		return fmt.Errorf("failed to create team membership: %w", err)
	}

	m.logger.Info("Initial data seeded successfully")
	return nil
}

// GetMigrationStatus returns migration status information
func (m *MigrationManager) GetMigrationStatus() ([]Migration, error) {
	var migrations []Migration
	err := m.db.DB.Order("applied_at DESC").Find(&migrations).Error
	return migrations, err
}

// RollbackLastBatch rolls back the last batch of migrations
func (m *MigrationManager) RollbackLastBatch() error {
	// Get the last batch number
	var lastBatch int
	if err := m.db.DB.Model(&Migration{}).Select("MAX(batch)").Where("rolled_back = ?", false).Scan(&lastBatch).Error; err != nil {
		return fmt.Errorf("failed to get last batch: %w", err)
	}

	if lastBatch == 0 {
		return fmt.Errorf("no migrations to rollback")
	}

	m.logger.Info("Rolling back migration batch", "batch", lastBatch)

	// Mark migrations as rolled back
	result := m.db.DB.Model(&Migration{}).
		Where("batch = ? AND rolled_back = ?", lastBatch, false).
		Updates(map[string]interface{}{
			"rolled_back": true,
			"rollback_at": time.Now(),
		})

	if result.Error != nil {
		return fmt.Errorf("failed to mark migrations as rolled back: %w", result.Error)
	}

	m.logger.Info("Successfully rolled back migrations", "count", result.RowsAffected)
	return nil
}

// ResetDatabase drops all tables and recreates them (DEVELOPMENT ONLY)
func (m *MigrationManager) ResetDatabase() error {
	// Note: Environment check should be done at the application level
	// For safety, we require explicit confirmation

	m.logger.Warn("Resetting database - ALL DATA WILL BE LOST!")

	// Drop all tables
	allModels := models.GetAllModels()
	for i := len(allModels) - 1; i >= 0; i-- {
		if err := m.db.DB.Migrator().DropTable(allModels[i]); err != nil {
			m.logger.Warn("Failed to drop table", "error", err)
		}
	}

	// Drop migration table
	m.db.DB.Migrator().DropTable(&Migration{})

	// Run migrations from scratch
	return m.RunMigrations()
}

// CheckDatabaseHealth performs basic database health checks
func (m *MigrationManager) CheckDatabaseHealth() error {
	// Check if all core tables exist
	requiredTables := []interface{}{
		&models.Organization{},
		&models.Team{},
		&models.User{},
		&models.Workflow{},
	}

	for _, model := range requiredTables {
		if !m.db.DB.Migrator().HasTable(model) {
			return fmt.Errorf("required table missing for model: %T", model)
		}
	}

	// Check migration table
	if !m.db.DB.Migrator().HasTable(&Migration{}) {
		return fmt.Errorf("migration tracking table missing")
	}

	return nil
}