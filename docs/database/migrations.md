# Database Migrations

This document describes the production-ready GORM migration system for n8n-pro.

## Overview

The migration system provides:
- **Versioned migrations** with batch tracking
- **Rollback capabilities** for safe deployments  
- **Transaction safety** for migration consistency
- **Production safeguards** to prevent data loss
- **CLI tools** for easy migration management

## Migration Architecture

```
internal/database/
├── database.go          # Main database connection
├── migrations.go        # Migration manager and logic
```

## Migration System Features

### ✅ What's Included

- **Automated table creation** from GORM models
- **Performance indexes** for optimal query performance  
- **Data seeding** for development environments
- **Migration tracking** with execution time monitoring
- **Rollback support** for safe deployments
- **Health checks** to verify database state
- **CLI tools** for migration management

### 🚫 Removed Conflicts

The old conflicting migration systems have been removed:
- ~~SQL migrations (golang-migrate)~~
- ~~Multiple GORM AutoMigrate calls~~  
- ~~Inconsistent model definitions~~

## Usage

### Command Line Tool

```bash
# Run all pending migrations
./migrate up

# Check migration status
./migrate status

# Rollback last batch
./migrate rollback

# Check database health  
./migrate health

# Reset database (development only)
./migrate reset
```

### Programmatic Usage

```go
// Initialize database with migrations
db, err := database.Initialize(cfg.Database)
if err != nil {
    log.Fatal(err)
}

// Or run migrations manually
migrationManager := database.NewMigrationManager(db)
if err := migrationManager.RunMigrations(); err != nil {
    log.Fatal(err)
}
```

## Migration Structure

### Migration Steps

1. **Core Tables** - Organizations, Teams, Users
2. **Workflow Tables** - Workflows, Executions, Versions
3. **Auth Tables** - Sessions, API Keys, Audit Logs
4. **Indexes** - Performance optimization indexes
5. **Seed Data** - Default organization and admin user

### Model Organization

```go
// All models are defined in internal/models/gorm_models.go
models.GetAllModels() // Returns all models for migration
```

## Production Deployment

### Pre-deployment Checklist

- [ ] Backup database before migration
- [ ] Test migrations on staging environment
- [ ] Verify all required models are in `GetAllModels()`
- [ ] Check migration execution time estimates
- [ ] Ensure sufficient database privileges

### Deployment Process

```bash
# 1. Check current status
./migrate status

# 2. Run migrations
./migrate up

# 3. Verify health
./migrate health
```

### Rollback Process

```bash
# Rollback last batch if needed
./migrate rollback
```

## Adding New Models

1. **Define model** in `internal/models/gorm_models.go`
2. **Add to GetAllModels()** function
3. **Create new migration** in `internal/database/migrations.go`
4. **Test migration** on development environment

### Example: Adding a New Model

```go
// 1. Add model to gorm_models.go
type NewModel struct {
    BaseModel
    Name        string `gorm:"not null"`
    Description string
}

// 2. Update GetAllModels() function
func GetAllModels() []interface{} {
    return []interface{}{
        // ... existing models
        &NewModel{},
    }
}

// 3. Add migration step
{
    Version: "2024_01_01_000006",
    Name:    "create_new_model_table",
    Up:      m.createNewModelTable,
}

func (m *MigrationManager) createNewModelTable() error {
    return m.db.DB.AutoMigrate(&models.NewModel{})
}
```

## Migration Monitoring

### Tracking Information

Each migration records:
- **Version** - Unique migration identifier
- **Name** - Human-readable description  
- **Batch** - Group of migrations run together
- **Applied At** - Timestamp of execution
- **Execution Time** - Duration in milliseconds
- **Rollback Status** - Whether migration was rolled back

### Health Checks

The system performs automated checks for:
- Required tables exist
- Migration tracking table exists
- Database connectivity
- Schema integrity

## Configuration

### Database Settings

```go
// Enable migrations in database config
cfg.Database.EnableMigrations = true

// Configure logging
cfg.Database.EnableQueryLogging = true
cfg.Database.SlowQueryThreshold = 200 * time.Millisecond
```

### Environment Variables

```bash
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=password
DB_SSL_MODE=disable

# Enable migrations
DB_ENABLE_MIGRATIONS=true
```

## Troubleshooting

### Common Issues

**Migration fails with "table already exists"**
```bash
# Check current status
./migrate status

# If needed, mark migration as completed manually
# (Advanced: modify schema_migrations table)
```

**Performance issues during migration**
```bash
# Check execution times
./migrate status --json | jq '.[] | select(.execution_time > 1000)'

# Consider running migrations during maintenance window
```

**Rollback needed**
```bash
# Rollback last batch
./migrate rollback

# Check what was rolled back
./migrate status
```

### Debug Mode

```go
// Enable debug logging
logger := logger.New("migration-manager")
logger.SetLevel("debug")
```

## Security Considerations

- **Production Safety** - Database reset disabled in production
- **Transaction Safety** - All migrations run in transactions
- **Rollback Tracking** - Full audit trail of rollbacks
- **Access Control** - Migrations require database admin privileges

## Performance Considerations

- **Batch Processing** - Migrations grouped in batches
- **Index Creation** - Uses `CONCURRENTLY` for minimal downtime
- **Execution Monitoring** - Tracks timing for optimization
- **Connection Pooling** - Reuses database connections efficiently

## Best Practices

1. **Test First** - Always test migrations on staging
2. **Small Batches** - Keep migrations focused and small
3. **Backup Always** - Backup before running migrations
4. **Monitor Performance** - Watch execution times
5. **Document Changes** - Update docs when adding migrations
6. **Review Rollbacks** - Test rollback procedures regularly

## Migration History

| Version | Date | Description |
|---------|------|-------------|
| 2024_01_01_000001 | 2024-01-01 | Initial core tables |
| 2024_01_01_000002 | 2024-01-01 | Workflow tables |
| 2024_01_01_000003 | 2024-01-01 | Auth tables |
| 2024_01_01_000004 | 2024-01-01 | Performance indexes |
| 2024_01_01_000005 | 2024-01-01 | Initial seed data |