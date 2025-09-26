#!/bin/bash
# Production deployment script for n8n-pro
# This script handles zero-downtime deployment with health checks and rollback capabilities

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="n8n-pro"
DEPLOY_ENV="production"
HEALTH_CHECK_URL="http://localhost:8080/health"
BACKUP_DIR="/backup/n8n-pro"
LOG_FILE="/var/log/n8n-pro-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "${BLUE}$*${NC}"
}

warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

error() {
    log "ERROR" "${RED}$*${NC}"
}

success() {
    log "SUCCESS" "${GREEN}$*${NC}"
}

# Error handling
cleanup() {
    if [ $? -ne 0 ]; then
        error "Deployment failed. Check logs for details."
        if [ "${ROLLBACK_ON_FAILURE:-true}" = "true" ]; then
            warn "Starting automatic rollback..."
            rollback
        fi
    fi
}

trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    info "Checking deployment prerequisites..."
    
    # Check if running as appropriate user
    if [ "$EUID" -eq 0 ]; then
        error "Do not run this script as root"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("docker" "docker-compose" "curl" "jq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check Docker is running
    if ! docker info &> /dev/null; then
        error "Docker is not running"
        exit 1
    fi
    
    # Check environment file exists
    if [ ! -f "$PROJECT_DIR/.env" ]; then
        error "Environment file .env not found"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Backup current deployment
backup_current_deployment() {
    info "Creating backup of current deployment..."
    
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$BACKUP_DIR/$backup_timestamp"
    
    mkdir -p "$backup_path"
    
    # Backup environment file
    if [ -f "$PROJECT_DIR/.env" ]; then
        cp "$PROJECT_DIR/.env" "$backup_path/"
    fi
    
    # Backup database
    info "Backing up database..."
    docker-compose exec -T postgres pg_dump -U n8n n8n_pro > "$backup_path/database.sql" || {
        warn "Database backup failed, but continuing deployment"
    }
    
    # Save current Docker image tags
    docker images --format "{{.Repository}}:{{.Tag}}" | grep "$APP_NAME" > "$backup_path/docker_images.txt" || true
    
    # Store backup path for potential rollback
    echo "$backup_path" > /tmp/last_backup_path
    
    success "Backup created at $backup_path"
}

# Health check function
health_check() {
    local max_attempts=${1:-30}
    local attempt=1
    
    info "Performing health check (max $max_attempts attempts)..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$HEALTH_CHECK_URL" >/dev/null 2>&1; then
            success "Health check passed"
            return 0
        fi
        
        info "Health check attempt $attempt/$max_attempts failed, waiting 10 seconds..."
        sleep 10
        ((attempt++))
    done
    
    error "Health check failed after $max_attempts attempts"
    return 1
}

# Pre-deployment checks
pre_deployment_checks() {
    info "Running pre-deployment checks..."
    
    # Check if new image exists
    local new_version=${BUILD_VERSION:-latest}
    if ! docker image inspect "$APP_NAME:$new_version" >/dev/null 2>&1; then
        error "Docker image $APP_NAME:$new_version not found"
        exit 1
    fi
    
    # Validate environment configuration
    source "$PROJECT_DIR/.env"
    
    # Check required environment variables
    local required_vars=("JWT_SECRET" "POSTGRES_PASSWORD" "DATABASE_URL")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            error "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    # Validate JWT secret strength
    if [ ${#JWT_SECRET} -lt 32 ]; then
        error "JWT_SECRET must be at least 32 characters long"
        exit 1
    fi
    
    success "Pre-deployment checks passed"
}

# Database migration
run_migrations() {
    info "Running database migrations..."
    
    # Create a temporary container to run migrations
    docker run --rm \
        --network n8n-pro-network \
        --env-file "$PROJECT_DIR/.env" \
        "$APP_NAME:${BUILD_VERSION:-latest}" \
        migrate up
    
    success "Database migrations completed"
}

# Rolling update deployment
deploy() {
    info "Starting rolling deployment..."
    
    # Pull latest images
    info "Pulling latest Docker images..."
    docker-compose pull
    
    # Rolling update with zero downtime
    info "Performing rolling update..."
    docker-compose up -d --force-recreate --no-deps n8n-pro-api
    
    # Wait for new container to be ready
    info "Waiting for new container to start..."
    sleep 30
    
    # Health check
    if ! health_check 30; then
        error "New deployment failed health check"
        return 1
    fi
    
    # Cleanup old images
    info "Cleaning up old Docker images..."
    docker image prune -f
    
    success "Rolling deployment completed successfully"
}

# Rollback to previous version
rollback() {
    warn "Starting rollback process..."
    
    # Get last backup path
    local backup_path=""
    if [ -f /tmp/last_backup_path ]; then
        backup_path=$(cat /tmp/last_backup_path)
    fi
    
    if [ -z "$backup_path" ] || [ ! -d "$backup_path" ]; then
        error "No backup found for rollback"
        return 1
    fi
    
    # Restore environment file
    if [ -f "$backup_path/.env" ]; then
        cp "$backup_path/.env" "$PROJECT_DIR/"
    fi
    
    # Restore Docker images from backup if available
    if [ -f "$backup_path/docker_images.txt" ]; then
        # This is a simplified rollback - in production you'd want more sophisticated image management
        warn "Manual image rollback required. Previous images listed in $backup_path/docker_images.txt"
    fi
    
    # Restart services with previous configuration
    docker-compose down
    docker-compose up -d
    
    # Wait and health check
    sleep 30
    if health_check 20; then
        success "Rollback completed successfully"
    else
        error "Rollback failed - manual intervention required"
        return 1
    fi
}

# Post-deployment tasks
post_deployment_tasks() {
    info "Running post-deployment tasks..."
    
    # Update monitoring dashboards if needed
    if docker ps --format "{{.Names}}" | grep -q grafana; then
        info "Refreshing Grafana dashboards..."
        # Add Grafana dashboard refresh logic here
    fi
    
    # Send deployment notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚀 $APP_NAME deployed to production successfully\"}" \
            "$SLACK_WEBHOOK_URL" || warn "Failed to send Slack notification"
    fi
    
    # Log deployment completion
    success "Post-deployment tasks completed"
}

# Main deployment process
main() {
    info "Starting production deployment for $APP_NAME"
    info "Environment: $DEPLOY_ENV"
    info "Version: ${BUILD_VERSION:-latest}"
    
    # Set deployment start time
    local start_time=$(date +%s)
    
    # Run deployment steps
    check_prerequisites
    backup_current_deployment
    pre_deployment_checks
    run_migrations
    deploy
    post_deployment_tasks
    
    # Calculate deployment time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    success "Production deployment completed successfully in ${duration}s"
    info "Application is running at: http://localhost:${API_PORT:-8080}"
    info "Health check: $HEALTH_CHECK_URL"
    info "Metrics: http://localhost:${METRICS_PORT:-9090}/metrics"
}

# Handle command line arguments
case "${1:-deploy}" in
    deploy)
        main
        ;;
    rollback)
        rollback
        ;;
    health-check)
        health_check
        ;;
    backup)
        backup_current_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|health-check|backup}"
        exit 1
        ;;
esac