// Package database provides migration management for n8n-pro
// Following patterns used by GitHub, GitLab, and other large-scale applications
package database

import (
	"fmt"
	"log"
	"time"

	"n8n-pro/internal/models"

	"gorm.io/gorm"
)

// MigrationManager handles database migrations
type MigrationManager struct {
	db *Database
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *Database) *MigrationManager {
	return &MigrationManager{
		db: db,
	}
}

// RunMigrations executes all pending migrations
func (m *MigrationManager) RunMigrations() error {
	log.Println("🚀 Starting database migrations...")

	// Create migration tracking table
	if err := m.createMigrationTable(); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	// Run all migrations in order
	migrations := []Migration{
		{Version: "001", Name: "create_organizations", Up: m.createOrganizations},
		{Version: "002", Name: "create_teams", Up: m.createTeams},
		{Version: "003", Name: "create_users", Up: m.createUsers},
		{Version: "004", Name: "create_team_members", Up: m.createTeamMembers},
		{Version: "005", Name: "create_workflows", Up: m.createWorkflows},
		{Version: "006", Name: "create_workflow_executions", Up: m.createWorkflowExecutions},
		{Version: "007", Name: "create_workflow_versions", Up: m.createWorkflowVersions},
		{Version: "008", Name: "create_audit_logs", Up: m.createAuditLogs},
		{Version: "009", Name: "create_sessions", Up: m.createSessions},
		{Version: "010", Name: "create_indexes", Up: m.createIndexes},
		{Version: "011", Name: "seed_default_data", Up: m.seedDefaultData},
	}

	for _, migration := range migrations {
		if err := m.runMigration(migration); err != nil {
			return fmt.Errorf("failed to run migration %s: %w", migration.Name, err)
		}
	}

	log.Println("✅ Database migrations completed successfully")
	return nil
}

// Migration represents a database migration
type Migration struct {
	Version string
	Name    string
	Up      func() error
}

// MigrationRecord tracks applied migrations
type MigrationRecord struct {
	Version   string `gorm:"primaryKey"`
	Name      string
	AppliedAt string
}

func (m *MigrationManager) createMigrationTable() error {
	return m.db.DB.AutoMigrate(&MigrationRecord{})
}

func (m *MigrationManager) runMigration(migration Migration) error {
	// Check if migration already applied
	var count int64
	m.db.DB.Model(&MigrationRecord{}).Where("version = ?", migration.Version).Count(&count)
	if count > 0 {
		log.Printf("⏭️  Migration %s_%s already applied, skipping", migration.Version, migration.Name)
		return nil
	}

	log.Printf("🔄 Running migration %s_%s", migration.Version, migration.Name)

	// Run migration in transaction
	err := m.db.DB.Transaction(func(tx *gorm.DB) error {
		// Execute migration
		if err := migration.Up(); err != nil {
			return err
		}

		// Record migration
		record := &MigrationRecord{
			Version:   migration.Version,
			Name:      migration.Name,
			AppliedAt: fmt.Sprintf("%d", time.Now().Unix()),
		}
		return tx.Create(record).Error
	})

	if err != nil {
		return fmt.Errorf("migration %s failed: %w", migration.Name, err)
	}

	log.Printf("✅ Migration %s_%s completed", migration.Version, migration.Name)
	return nil
}

// Individual migration functions

func (m *MigrationManager) createOrganizations() error {
	return m.db.DB.AutoMigrate(&models.Organization{})
}

func (m *MigrationManager) createTeams() error {
	return m.db.DB.AutoMigrate(&models.Team{})
}

func (m *MigrationManager) createUsers() error {
	return m.db.DB.AutoMigrate(&models.User{})
}

func (m *MigrationManager) createTeamMembers() error {
	return m.db.DB.AutoMigrate(&models.TeamMember{})
}

func (m *MigrationManager) createWorkflows() error {
	return m.db.DB.AutoMigrate(&models.Workflow{})
}

func (m *MigrationManager) createWorkflowExecutions() error {
	return m.db.DB.AutoMigrate(&models.WorkflowExecution{})
}

func (m *MigrationManager) createWorkflowVersions() error {
	return m.db.DB.AutoMigrate(&models.WorkflowVersion{})
}

func (m *MigrationManager) createAuditLogs() error {
	return m.db.DB.AutoMigrate(&models.AuditLog{})
}

func (m *MigrationManager) createSessions() error {
	return m.db.DB.AutoMigrate(&models.Session{})
}

func (m *MigrationManager) createIndexes() error {
	// Create additional indexes for performance
	sql := `
	-- Performance indexes for common queries
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_org_email_active ON users(organization_id, email) WHERE deleted_at IS NULL;
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_team_status ON workflows(team_id, status) WHERE deleted_at IS NULL;
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_workflow_status ON workflow_executions(workflow_id, status);
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_start_time ON workflow_executions(start_time DESC);
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(organization_id, created_at DESC);
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, is_active) WHERE is_active = true;
	
	-- Full-text search indexes
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_search ON workflows USING gin(to_tsvector('english', name || ' ' || description)) WHERE deleted_at IS NULL;
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_search ON users USING gin(to_tsvector('english', first_name || ' ' || last_name || ' ' || email)) WHERE deleted_at IS NULL;
	
	-- JSONB indexes for better query performance
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_definition_gin ON workflows USING gin(definition);
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_metadata_gin ON workflow_executions USING gin(metadata);
	CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_settings_gin ON users USING gin(settings);
	`
	
	return m.db.DB.Exec(sql).Error
}

func (m *MigrationManager) seedDefaultData() error {
	log.Println("🌱 Seeding default data...")

	// Create default organization
	org := &models.Organization{
		BaseModel: models.BaseModel{ID: "org_default_development"},
		Name:      "Default Organization",
		Slug:      "default-org",
		Plan:      "pro",
		PlanLimits: models.JSONB{
			"max_users":                  100,
			"max_workflows":              500,
			"max_executions_per_month":   1000000,
			"max_execution_time_seconds": 1800,
			"api_calls_per_minute":       1000,
			"data_retention_days":        90,
			"custom_connections":         true,
			"sso_enabled":                true,
			"audit_logs_enabled":         true,
		},
		Settings: models.JSONB{
			"default_timezone":           "UTC",
			"allow_registration":         true,
			"require_email_verification": true,
			"enforce_password_policy":    true,
		},
		Status: "active",
	}

	if err := m.db.DB.FirstOrCreate(org, "id = ?", org.ID).Error; err != nil {
		return fmt.Errorf("failed to create default organization: %w", err)
	}

	// Create default team
	team := &models.Team{
		BaseModel:      models.BaseModel{ID: "team_default_development"},
		OrganizationID: org.ID,
		Name:           "Default Team",
		Description:    "Default team for development and testing",
		Settings: models.JSONB{
			"default_role":         "member",
			"allow_member_invite":  true,
			"require_approval":     false,
			"workflow_sharing":     "team",
			"credential_sharing":   "team",
		},
	}

	if err := m.db.DB.FirstOrCreate(team, "id = ?", team.ID).Error; err != nil {
		return fmt.Errorf("failed to create default team: %w", err)
	}

	// Create default admin user
	hashedPassword := "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdnKm5vQJ5o8/EW" // admin123!
	
	user := &models.User{
		BaseModel:      models.BaseModel{ID: "user_admin_development"},
		OrganizationID: org.ID,
		Email:          "admin@n8n-pro.local",
		FirstName:      "Admin",
		LastName:       "User",
		PasswordHash:   hashedPassword,
		Status:         "active",
		Role:           "owner",
		EmailVerified:  true,
		Profile: models.JSONB{
			"bio":        "Default admin user for n8n Pro",
			"job_title":  "System Administrator",
			"department": "IT",
		},
		Settings: models.JSONB{
			"timezone": "UTC",
			"language": "en",
			"theme":    "light",
		},
	}

	if err := m.db.DB.FirstOrCreate(user, "id = ?", user.ID).Error; err != nil {
		return fmt.Errorf("failed to create default user: %w", err)
	}

	// Add user to team
	teamMember := &models.TeamMember{
		ID:     "membership_admin_development",
		TeamID: team.ID,
		UserID: user.ID,
		Role:   "owner",
	}

	if err := m.db.DB.FirstOrCreate(teamMember, "id = ?", teamMember.ID).Error; err != nil {
		return fmt.Errorf("failed to create team membership: %w", err)
	}

	log.Println("✅ Default data seeded successfully")
	return nil
}

// RollbackMigration rolls back a specific migration
func (m *MigrationManager) RollbackMigration(version string) error {
	log.Printf("🔄 Rolling back migration %s", version)
	
	// Delete migration record
	result := m.db.DB.Where("version = ?", version).Delete(&MigrationRecord{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete migration record: %w", result.Error)
	}
	
	if result.RowsAffected == 0 {
		return fmt.Errorf("migration %s not found", version)
	}
	
	log.Printf("⚠️  Migration %s rolled back (manual cleanup may be required)", version)
	return nil
}

// GetAppliedMigrations returns list of applied migrations
func (m *MigrationManager) GetAppliedMigrations() ([]MigrationRecord, error) {
	var migrations []MigrationRecord
	err := m.db.DB.Order("version").Find(&migrations).Error
	return migrations, err
}