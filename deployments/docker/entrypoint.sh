#!/bin/sh
# entrypoint.sh - Production-ready entrypoint for n8n Pro services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo "${GREEN}[SUCCESS]${NC} $1"
}

# Function to wait for service
wait_for_service() {
    local host=$1
    local port=$2
    local service=$3
    local timeout=${4:-60}
    local count=0
    
    log_info "Waiting for $service at $host:$port..."
    
    while ! nc -z "$host" "$port"; do
        count=$((count + 1))
        if [ $count -gt $timeout ]; then
            log_error "Timeout waiting for $service at $host:$port"
            exit 1
        fi
        sleep 1
    done
    
    log_success "$service is ready"
}

# Function to check if we have admin binary
check_admin_binary() {
    if [ ! -f "/app/bin/admin" ]; then
        log_warn "Admin binary not found, skipping migrations"
        return 1
    fi
    return 0
}

# Wait for required services
if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
    wait_for_service "$DB_HOST" "$DB_PORT" "PostgreSQL" 60
fi

if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
    wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis" 30
fi

if [ -n "$KAFKA_BROKERS" ]; then
    # Extract host and port from Kafka brokers
    KAFKA_HOST=$(echo "$KAFKA_BROKERS" | cut -d':' -f1)
    KAFKA_PORT=$(echo "$KAFKA_BROKERS" | cut -d':' -f2)
    wait_for_service "$KAFKA_HOST" "$KAFKA_PORT" "Kafka" 60
fi

# Run database migrations (only for API service or if explicitly requested)
if check_admin_binary && (echo "$@" | grep -q "api" || [ "$RUN_MIGRATIONS" = "true" ]); then
    log_info "Running database migrations..."
    
    # Check migration status
    if STATUS_OUTPUT=$(/app/bin/admin migrate status 2>&1); then
        log_info "Migration status: $STATUS_OUTPUT"
        
        # Check if database is in dirty state
        if echo "$STATUS_OUTPUT" | grep -q "Dirty: true"; then
            log_warn "Database is in dirty state, attempting to fix..."
            
            # Try to force version
            if ! /app/bin/admin migrate force $(echo "$STATUS_OUTPUT" | grep "Version" | awk '{print $2}') 2>/dev/null; then
                log_warn "Failed to force migration version, dropping and recreating..."
                /app/bin/admin migrate drop -f || log_warn "Failed to drop migrations"
            fi
        fi
    else
        log_info "Migration status check failed, will attempt to run migrations"
    fi
    
    # Run migrations
    if /app/bin/admin migrate up; then
        log_success "Database migrations completed successfully"
    else
        log_warn "Database migrations failed, continuing without migrations..."
        log_info "You may need to run migrations manually"
    fi
else
    log_info "Skipping database migrations (admin binary not available or not API service)"
fi

# Set up signal handling for graceful shutdown
trap 'log_info "Received shutdown signal, terminating..."; kill -TERM "$child" 2>/dev/null; wait "$child"' TERM INT

# Log startup information
log_info "Starting n8n Pro service with command: $*"
log_info "Environment: ${ENVIRONMENT:-development}"
log_info "Log Level: ${LOG_LEVEL:-info}"

# Execute the main command in background
"$@" &
child=$!

# Wait for the child process
wait "$child"
exit_code=$?

if [ $exit_code -eq 0 ]; then
    log_success "Service exited successfully"
else
    log_error "Service exited with code $exit_code"
fi

exit $exit_code
