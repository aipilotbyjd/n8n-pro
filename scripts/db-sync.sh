#!/bin/bash

# db-sync.sh - Database synchronization helper for n8n-pro
# Usage: ./scripts/db-sync.sh [command] [options]

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to check if admin binary exists
check_admin_binary() {
    if [[ ! -f "./bin/admin" ]]; then
        log_warn "Admin binary not found, building..."
        make build-admin
    fi
}

# Function to check if database is running
check_database() {
    log_info "Checking database connection..."
    if ! docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        log_warn "Database not running, starting..."
        make db-up
        sleep 3
    fi
    log_success "Database is running"
}

# Show help
show_help() {
    cat << EOF
Database Sync Helper for n8n-pro

USAGE:
    ./scripts/db-sync.sh [COMMAND] [OPTIONS]

COMMANDS:
    status      Show current migration status
    sync        Apply all pending migrations
    reset       Reset database (down, up, seed)
    rollback    Rollback one migration
    seed        Add test data to database
    shell       Connect to database shell
    health      Check system health
    backup      Create database backup
    restore     Restore from backup file
    help        Show this help message

OPTIONS:
    --force     Force operation (skip confirmations)
    --verbose   Show detailed output
    --dry-run   Show what would be done without executing

EXAMPLES:
    ./scripts/db-sync.sh status
    ./scripts/db-sync.sh sync
    ./scripts/db-sync.sh reset --force
    ./scripts/db-sync.sh backup
    ./scripts/db-sync.sh restore backup.sql

EOF
}

# Status command
cmd_status() {
    log_info "Checking migration status..."
    check_admin_binary
    check_database
    
    echo ""
    ./bin/admin migrate status
    echo ""
    
    log_info "Database connection test:"
    ./bin/admin system health
}

# Sync command
cmd_sync() {
    local force_flag=${1:-false}
    
    log_info "Starting database sync..."
    check_admin_binary
    check_database
    
    if [[ "$force_flag" != "true" ]]; then
        echo ""
        log_warn "This will apply all pending migrations to the database."
        read -p "Continue? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Operation cancelled"
            exit 0
        fi
    fi
    
    echo ""
    log_info "Applying migrations..."
    make db-migrate
    
    echo ""
    log_success "Database sync complete!"
    cmd_status
}

# Reset command
cmd_reset() {
    local force_flag=${1:-false}
    
    log_warn "This will COMPLETELY RESET the database!"
    log_warn "All data will be lost and replaced with test data."
    
    if [[ "$force_flag" != "true" ]]; then
        echo ""
        read -p "Are you absolutely sure? Type 'RESET' to continue: " -r
        if [[ $REPLY != "RESET" ]]; then
            log_info "Operation cancelled"
            exit 0
        fi
    fi
    
    check_admin_binary
    check_database
    
    echo ""
    log_info "Resetting database..."
    make db-reset
    
    echo ""
    log_success "Database reset complete!"
    cmd_status
}

# Rollback command
cmd_rollback() {
    log_warn "Rolling back one migration..."
    check_admin_binary
    check_database
    
    echo ""
    log_info "Current status:"
    ./bin/admin migrate status
    
    echo ""
    read -p "Continue with rollback? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled"
        exit 0
    fi
    
    make db-migrate-down
    
    echo ""
    log_success "Rollback complete!"
    cmd_status
}

# Seed command
cmd_seed() {
    log_info "Seeding database with test data..."
    check_admin_binary
    check_database
    
    make db-seed
    log_success "Database seeded successfully!"
}

# Shell command
cmd_shell() {
    log_info "Connecting to database shell..."
    check_database
    make db-shell
}

# Health command
cmd_health() {
    log_info "Checking system health..."
    check_admin_binary
    check_database
    ./bin/admin system health
}

# Backup command
cmd_backup() {
    local backup_file="backup_$(date +%Y%m%d_%H%M%S).sql"
    
    log_info "Creating database backup..."
    check_database
    
    docker-compose exec -T postgres pg_dump -U postgres n8n_clone > "$backup_file"
    
    log_success "Backup created: $backup_file"
    
    # Show backup info
    local size=$(ls -lh "$backup_file" | awk '{print $5}')
    log_info "Backup size: $size"
}

# Restore command
cmd_restore() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        log_error "Backup file required"
        log_info "Usage: ./scripts/db-sync.sh restore <backup_file>"
        exit 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log_warn "This will restore the database from: $backup_file"
    log_warn "Current data will be overwritten!"
    
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled"
        exit 0
    fi
    
    check_database
    
    log_info "Restoring database..."
    docker-compose exec -T postgres psql -U postgres n8n_clone < "$backup_file"
    
    log_success "Database restored successfully!"
    cmd_status
}

# Main script logic
main() {
    local command="$1"
    shift || true
    
    # Parse options
    local force_flag=false
    local verbose_flag=false
    local dry_run_flag=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                force_flag=true
                shift
                ;;
            --verbose)
                verbose_flag=true
                set -x
                shift
                ;;
            --dry-run)
                dry_run_flag=true
                log_info "DRY RUN MODE - No changes will be made"
                shift
                ;;
            *)
                # Unknown option, might be a parameter for the command
                break
                ;;
        esac
    done
    
    # Handle dry run mode
    if [[ "$dry_run_flag" == "true" ]]; then
        log_info "Would execute: $command with remaining args: $*"
        exit 0
    fi
    
    case "$command" in
        status|st)
            cmd_status
            ;;
        sync|up)
            cmd_sync "$force_flag"
            ;;
        reset)
            cmd_reset "$force_flag"
            ;;
        rollback|down)
            cmd_rollback
            ;;
        seed)
            cmd_seed
            ;;
        shell|psql)
            cmd_shell
            ;;
        health|check)
            cmd_health
            ;;
        backup)
            cmd_backup
            ;;
        restore)
            cmd_restore "$1"
            ;;
        help|--help|-h)
            show_help
            ;;
        "")
            log_info "No command specified, showing status..."
            cmd_status
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"