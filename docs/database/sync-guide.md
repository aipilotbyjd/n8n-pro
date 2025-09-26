# Database Synchronization Guide

This guide explains how to sync your database schema using migrations in the n8n-pro project.

## Overview

The n8n-pro project uses [golang-migrate](https://github.com/golang-migrate/migrate) for database migrations. Migrations are stored in two locations:
- `internal/storage/migrations/` - Main migration files (11 migrations)
- `migrations/` - Additional migration files (3 migrations)

## Migration Files Structure

Each migration consists of two files:
- `XXX_migration_name.up.sql` - Applied when migrating up
- `XXX_migration_name.down.sql` - Applied when migrating down (rollback)

### Current Migrations

**Main Storage Migrations (`internal/storage/migrations/`):**
```
001_initial_schema.up.sql         - Initial database setup
002_create_workflows_table.up.sql - Workflow management tables
003_complete_workflows_schema.up.sql - Complete workflow schema
004_enable_crypto.up.sql          - Cryptographic extensions
005_create_users_table.up.sql     - User management
006_create_credentials_table.up.sql - Credentials storage
007_create_webhooks_table.up.sql  - Webhook management
008_create_workflow_extensions.up.sql - Workflow extensions
009_create_system_tables.up.sql   - System tables
010_finalize_schema.up.sql        - Schema finalization
011_create_scheduler_tables.up.sql - Scheduler tables (recent addition)
```

**Additional Migrations (`migrations/`):**
```
001_create_audit_events_table.up.sql - Audit logging
002_create_enterprise_configs_table.up.sql - Enterprise features
004_comprehensive_auth_system.up.sql - Authentication system
```

## Database Sync Methods

### 1. Using Make Commands (Recommended)

#### Start Database Services
```bash
# Start PostgreSQL and Redis
make db-up
```

#### Run Migrations
```bash
# Apply all pending migrations
make db-migrate

# Rollback one migration
make db-migrate-down

# Reset database completely (down, up, seed)
make db-reset

# Seed database with test data
make db-seed
```

#### Database Shell Access
```bash
# Connect to PostgreSQL shell
make db-shell
```

### 2. Using Admin CLI Directly

#### Build Admin CLI
```bash
make build-admin
# or
go build -o bin/admin ./cmd/admin
```

#### Migration Commands
```bash
# Check current migration status
./bin/admin migrate status

# Apply all pending migrations
./bin/admin migrate up

# Rollback all migrations
./bin/admin migrate down

# Force a specific migration version (for recovery)
./bin/admin migrate force 5

# Check system health
./bin/admin system health
```

### 3. Docker Environment

#### Automatic Migrations (Production)
Migrations run automatically when starting the API service in Docker:

```bash
# Start all services (migrations run automatically)
docker-compose up -d

# Check migration status
docker-compose exec api /app/bin/admin migrate status

# Run migrations manually if needed
docker-compose exec api /app/bin/admin migrate up
```

#### Manual Migration Control
```bash
# Disable automatic migrations
RUN_MIGRATIONS=false docker-compose up -d

# Run migrations manually
docker-compose exec api /app/bin/admin migrate up
```

## Environment Configuration

### Database Connection Settings
Set these environment variables or update your `.env` file:

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=your_password
DB_SSL_MODE=disable

# Connection Pool
DB_MAX_CONNECTIONS=25
DB_MAX_IDLE_CONNECTIONS=5
DB_MAX_LIFETIME=1h
```

### Using Different Environments
```bash
# Development
cp .env.example .env
make db-migrate

# Testing
cp .env.example .env.test
DB_NAME=n8n_test make db-migrate

# Production
export DB_HOST=prod-postgres.example.com
export DB_SSL_MODE=require
make db-migrate
```

## Common Scenarios

### 1. Fresh Database Setup
```bash
# Start services
make db-up

# Run all migrations
make db-migrate

# Add test data
make db-seed

# Verify setup
./bin/admin system health
```

### 2. Updating Existing Database
```bash
# Check current status
./bin/admin migrate status

# Apply pending migrations
make db-migrate

# Verify update
./bin/admin migrate status
```

### 3. Team Development Sync
```bash
# Pull latest code
git pull origin main

# Update dependencies
make deps

# Apply any new migrations
make db-migrate

# Restart services
make restart
```

### 4. Rolling Back Changes
```bash
# Check current version
./bin/admin migrate status

# Rollback one migration
make db-migrate-down

# Or rollback to specific version
./bin/admin migrate force 5
```

### 5. Recovery from Failed Migration
```bash
# Check migration status (look for "dirty: true")
./bin/admin migrate status

# If dirty, force to a known good version
./bin/admin migrate force 10

# Then continue with normal migration
make db-migrate
```

## Troubleshooting

### Migration Errors

#### "Database is locked" or "dirty state"
```bash
# Check status
./bin/admin migrate status

# Force to last known good version
./bin/admin migrate force <version_number>

# Then try again
make db-migrate
```

#### "Migration file not found"
```bash
# Ensure you're in the project root
cd /path/to/n8n-pro

# Check migration files exist
ls -la internal/storage/migrations/

# Build admin binary
make build-admin
```

#### "Connection refused"
```bash
# Start database
make db-up

# Check database is running
docker-compose ps

# Test connection
make db-shell
```

### Database Issues

#### "Role does not exist"
```bash
# Create database and user manually
make db-shell

# In PostgreSQL shell:
CREATE USER postgres WITH PASSWORD 'password';
CREATE DATABASE n8n_pro OWNER postgres;
GRANT ALL PRIVILEGES ON DATABASE n8n_pro TO postgres;
```

#### "Database does not exist"
```bash
# Connect as superuser and create database
docker-compose exec postgres psql -U postgres

# Create database
CREATE DATABASE n8n_pro;
```

## Best Practices

### 1. Migration Development
```bash
# Always test migrations locally first
make db-migrate
make test

# Test rollback functionality
make db-migrate-down
make db-migrate
```

### 2. Production Deployment
```bash
# Backup before migration
pg_dump n8n_pro > backup_$(date +%Y%m%d_%H%M%S).sql

# Test migration on staging first
ENVIRONMENT=staging make db-migrate

# Apply to production
ENVIRONMENT=production make db-migrate
```

### 3. Team Collaboration
```bash
# Always check migration status after pull
git pull
./bin/admin migrate status

# Communicate breaking changes
# Document schema changes in commit messages
```

### 4. Monitoring
```bash
# Check database health regularly
./bin/admin system health

# Monitor migration status
./bin/admin migrate status

# Watch database logs
docker-compose logs -f postgres
```

## Scripts and Automation

### Development Workflow Script
```bash
#!/bin/bash
# dev-sync.sh - Sync database for development

echo "🔄 Syncing database..."

# Start services
make db-up

# Apply migrations
make db-migrate

# Add test data
make db-seed

# Check health
./bin/admin system health

echo "✅ Database sync complete!"
```

### Backup and Restore
```bash
#!/bin/bash
# backup-restore.sh

# Backup
docker-compose exec -T postgres pg_dump -U postgres n8n_pro > backup.sql

# Restore
docker-compose exec -T postgres psql -U postgres n8n_pro < backup.sql
```

## Migration File Locations

The project has migrations in two locations due to historical reasons:

1. **`internal/storage/migrations/`** - Main schema migrations (used by admin CLI)
2. **`migrations/`** - Additional feature-specific migrations

When running `make db-migrate`, it uses the `internal/storage/migrations/` path through the admin CLI.

## Environment-Specific Notes

### Development
- Automatic migrations on service start
- Seeding available via `make db-seed`
- Database reset available via `make db-reset`

### Testing
- Use separate test database
- Migrations run automatically before tests
- Database cleaned after test runs

### Production
- Manual migration control recommended
- Always backup before migrations
- Monitor migration logs carefully
- Use zero-downtime deployment strategies

## Support

If you encounter issues with database synchronization:

1. Check the logs: `docker-compose logs postgres`
2. Verify configuration: `./bin/admin system config`
3. Test connectivity: `make db-shell`
4. Check migration status: `./bin/admin migrate status`
5. Review recent changes: `git log --oneline -10`

For persistent issues, consider:
- Rebuilding from scratch: `make clean && make build-admin`
- Resetting database: `make db-reset`
- Checking for conflicting processes: `lsof -i :5432`