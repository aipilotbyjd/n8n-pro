#!/bin/bash
# setup-production.sh - Production setup script for n8n Pro
set -e

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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to generate secure random password
generate_password() {
    openssl rand -hex 16
}

# Function to generate JWT secret
generate_jwt_secret() {
    openssl rand -hex 32
}

# Function to generate encryption key
generate_encryption_key() {
    openssl rand -hex 16
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command_exists docker; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    if ! command_exists openssl; then
        log_error "OpenSSL is not installed. Please install OpenSSL first."
        exit 1
    fi
    
    log_success "All prerequisites are installed"
}

# Create production environment file
create_production_env() {
    log_info "Creating production environment configuration..."
    
    # Generate secure passwords and secrets
    DB_PASSWORD=$(generate_password)
    REDIS_PASSWORD=$(generate_password)
    JWT_SECRET=$(generate_jwt_secret)
    ENCRYPTION_KEY=$(generate_encryption_key)
    
    cat > .env.production << EOF
# =============================================================================
# n8n Pro Production Environment Configuration
# =============================================================================

# Generated on $(date)

# -----------------------------------------------------------------------------
# General Application Settings
# -----------------------------------------------------------------------------
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=info

# -----------------------------------------------------------------------------
# Database Configuration (PostgreSQL)
# -----------------------------------------------------------------------------
DB_HOST=postgres
DB_PORT=5432
DB_NAME=n8n_clone
DB_USER=n8n_pro
DB_PASSWORD=${DB_PASSWORD}
DB_SSL_MODE=require
DB_MAX_OPEN_CONNECTIONS=50
DB_MAX_IDLE_CONNECTIONS=10
DB_CONNECTION_LIFETIME=30m
DB_CONNECTION_TIMEOUT=30s
DB_ENABLE_QUERY_LOGGING=false
DB_SLOW_QUERY_THRESHOLD=5s

# -----------------------------------------------------------------------------
# Redis Configuration
# -----------------------------------------------------------------------------
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}
REDIS_DATABASE=0
REDIS_MAX_RETRIES=3
REDIS_DIAL_TIMEOUT=10s
REDIS_READ_TIMEOUT=5s
REDIS_WRITE_TIMEOUT=5s
REDIS_POOL_SIZE=20
REDIS_MIN_IDLE_CONNECTIONS=5
REDIS_MAX_IDLE_CONNECTIONS=20
REDIS_CONN_MAX_LIFETIME=1h

# -----------------------------------------------------------------------------
# Kafka Configuration
# -----------------------------------------------------------------------------
KAFKA_BROKERS=kafka:9092
KAFKA_TOPIC=n8n-workflows-prod
KAFKA_GROUP_ID=n8n-workers-prod
KAFKA_CLIENT_ID=n8n-pro
KAFKA_VERSION=3.6.2
KAFKA_PRODUCER_RETRY_MAX=5
KAFKA_PRODUCER_RETURN_SUCCESSES=true
KAFKA_CONSUMER_RETRY_BACKOFF=5s

# -----------------------------------------------------------------------------
# API Configuration
# -----------------------------------------------------------------------------
API_HOST=0.0.0.0
API_PORT=8080
API_READ_TIMEOUT=30s
API_WRITE_TIMEOUT=30s
API_IDLE_TIMEOUT=120s
API_MAX_REQUEST_SIZE=50MB
API_ENABLE_CORS=true
API_CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
API_ENABLE_RATE_LIMIT=true
API_RATE_LIMIT_REQUESTS=1000
API_RATE_LIMIT_WINDOW=1h
API_ENABLE_GZIP=true
API_TLS_ENABLED=false

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION=24h
REFRESH_TOKEN_EXPIRATION=168h
ENCRYPTION_KEY=${ENCRYPTION_KEY}
HASH_COST=14
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_SYMBOLS=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
MAX_LOGIN_ATTEMPTS=5
LOGIN_ATTEMPT_WINDOW=30m

# Security Headers
SECURITY_ENABLE_CSRF=true
SECURITY_ENABLE_CONTENT_SECURITY=true
SECURITY_CONTENT_SECURITY_POLICY="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss: https:; font-src 'self' https:; object-src 'none'; media-src 'self'; frame-src 'none';"
SECURITY_ENABLE_HSTS=true
SECURITY_HSTS_MAX_AGE=31536000
SECURITY_ENABLE_X_FRAME_OPTIONS=true
SECURITY_X_FRAME_OPTIONS=DENY
SECURITY_ENABLE_X_CONTENT_TYPE=true
SECURITY_ENABLE_XSS_PROTECTION=true

# -----------------------------------------------------------------------------
# Webhook Configuration
# -----------------------------------------------------------------------------
WEBHOOK_HOST=0.0.0.0
WEBHOOK_PORT=8081
WEBHOOK_MAX_PAYLOAD_SIZE=50MB
WEBHOOK_TIMEOUT=30s
WEBHOOK_ENABLE_SIGNATURE_VERIFY=true
WEBHOOK_RETRY_ATTEMPTS=3
WEBHOOK_RETRY_DELAY=5s
WEBHOOK_ENABLE_RATE_LIMIT=true
WEBHOOK_RATE_LIMIT_REQUESTS=500
WEBHOOK_RATE_LIMIT_WINDOW=5m

# -----------------------------------------------------------------------------
# Worker Configuration
# -----------------------------------------------------------------------------
WORKER_ENABLED=true
WORKER_CONCURRENCY=20
WORKER_HEALTH_CHECK_PORT=8082
WORKER_JOB_TIMEOUT=30m
WORKER_RETRY_ATTEMPTS=3
WORKER_RETRY_DELAY=60s
WORKER_SHUTDOWN_TIMEOUT=60s

# -----------------------------------------------------------------------------
# Sandbox Configuration
# -----------------------------------------------------------------------------
SANDBOX_ENABLED=true
SANDBOX_MAX_CONCURRENT_JOBS=10
SANDBOX_JOB_TIMEOUT=10m
SANDBOX_MAX_MEMORY_MB=512
SANDBOX_MAX_CPU_PERCENT=80
SANDBOX_MAX_DISK_MB=100
SANDBOX_ENABLE_NODEJS=true
SANDBOX_ENABLE_PYTHON=true
SANDBOX_NETWORK_POLICY=restricted

# -----------------------------------------------------------------------------
# System Limits
# -----------------------------------------------------------------------------
LIMITS_MAX_WORKFLOWS_PER_TEAM=500
LIMITS_MAX_NODES_PER_WORKFLOW=100
LIMITS_MAX_EXECUTIONS_PER_MINUTE=1000
LIMITS_MAX_EXECUTION_TIME=30m
LIMITS_MAX_PAYLOAD_SIZE=100MB
LIMITS_MAX_CONCURRENT_EXECUTIONS=50
LIMITS_MAX_FILE_UPLOAD_SIZE=100MB
LIMITS_MAX_STORAGE_PER_TEAM=10GB

# -----------------------------------------------------------------------------
# Metrics and Monitoring
# -----------------------------------------------------------------------------
METRICS_ENABLED=true
METRICS_HOST=0.0.0.0
METRICS_PORT=9090
METRICS_NAMESPACE=n8n_pro
METRICS_SERVICE_NAME=production

# -----------------------------------------------------------------------------
# Feature Flags
# -----------------------------------------------------------------------------
FEATURE_WORKFLOW_VERSIONING=true
FEATURE_WORKFLOW_TEMPLATES=true
FEATURE_TEAM_COLLABORATION=true
FEATURE_ADVANCED_SCHEDULING=true
FEATURE_WEBHOOK_SIGNATURES=true
FEATURE_AUDIT_LOGGING=true
FEATURE_ADVANCED_METRICS=true
FEATURE_CUSTOM_NODES=true
FEATURE_WORKFLOW_SHARING=true
FEATURE_API_RATE_LIMITING=true

EOF

    log_success "Production environment configuration created at .env.production"
    
    # Display generated credentials
    echo ""
    log_info "Generated Credentials (SAVE THESE SECURELY!):"
    echo "Database Password: ${DB_PASSWORD}"
    echo "Redis Password: ${REDIS_PASSWORD}"
    echo "JWT Secret: ${JWT_SECRET}"
    echo "Encryption Key: ${ENCRYPTION_KEY}"
    echo ""
    log_warn "Please save these credentials in a secure location!"
}

# Create production docker-compose file
create_production_compose() {
    log_info "Creating production docker-compose configuration..."
    
    cat > docker-compose.production.yml << 'EOF'
version: '3.8'

networks:
  n8n-pro-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  # PostgreSQL Database with production settings
  postgres:
    image: postgres:15-alpine
    container_name: n8n-pro-postgres-prod
    restart: always
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --lc-collate=C --lc-ctype=C"
      PGDATA: /var/lib/postgresql/data/pgdata
    ports:
      - "127.0.0.1:5432:5432"  # Only bind to localhost in production
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./deployments/docker/postgres-init.sql:/docker-entrypoint-initdb.d/init.sql:ro
      - ./backups:/backups  # Backup directory
    networks:
      - n8n-pro-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d ${DB_NAME} -h localhost -p 5432"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
        reservations:
          memory: 1G
          cpus: '1.0'
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  # Redis Cache with production settings
  redis:
    image: redis:7-alpine
    container_name: n8n-pro-redis-prod
    restart: always
    command: redis-server --requirepass ${REDIS_PASSWORD} --maxmemory 1gb --maxmemory-policy allkeys-lru --appendonly yes --appendfsync everysec
    ports:
      - "127.0.0.1:6379:6379"  # Only bind to localhost in production
    volumes:
      - redis_data:/data
    networks:
      - n8n-pro-network
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  # Apache Kafka with production settings
  kafka:
    image: bitnami/kafka:3.6
    container_name: n8n-pro-kafka-prod
    restart: always
    ports:
      - "127.0.0.1:9092:9092"  # Only bind to localhost in production
    environment:
      # KRaft settings
      KAFKA_CFG_NODE_ID: 0
      KAFKA_CFG_PROCESS_ROLES: controller,broker
      KAFKA_CFG_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
      KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_CFG_CONTROLLER_QUORUM_VOTERS: 0@kafka:9093
      KAFKA_CFG_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CFG_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      # Performance settings for production
      KAFKA_CFG_NUM_NETWORK_THREADS: 16
      KAFKA_CFG_NUM_IO_THREADS: 16
      KAFKA_CFG_LOG_RETENTION_HOURS: 168
      KAFKA_CFG_LOG_RETENTION_BYTES: 10737418240  # 10GB
      KAFKA_CFG_LOG_SEGMENT_BYTES: 1073741824
      KAFKA_CFG_NUM_PARTITIONS: 12
      KAFKA_CFG_DEFAULT_REPLICATION_FACTOR: 1
      KAFKA_HEAP_OPTS: "-Xmx2g -Xms2g"
    volumes:
      - kafka_data:/bitnami/kafka
    networks:
      - n8n-pro-network
    healthcheck:
      test: ["CMD-SHELL", "/opt/bitnami/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list"]
      interval: 60s
      timeout: 20s
      retries: 5
      start_period: 120s
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
        reservations:
          memory: 2G
          cpus: '1.0'
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  # API Service
  api:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.api
    container_name: n8n-pro-api-prod
    restart: always
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics port
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    env_file:
      - .env.production
    volumes:
      - ./storage:/app/storage
      - ./logs:/app/logs
    networks:
      - n8n-pro-network
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"

  # Worker Service (multiple instances for scalability)
  worker-1:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.worker
    container_name: n8n-pro-worker-1-prod
    restart: always
    ports:
      - "8082:8082"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    env_file:
      - .env.production
    volumes:
      - ./storage:/app/storage
      - ./logs:/app/logs
    networks:
      - n8n-pro-network
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"

  worker-2:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.worker
    container_name: n8n-pro-worker-2-prod
    restart: always
    ports:
      - "8083:8082"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    env_file:
      - .env.production
    volumes:
      - ./storage:/app/storage
      - ./logs:/app/logs
    networks:
      - n8n-pro-network
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"

  # Scheduler Service
  scheduler:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.scheduler
    container_name: n8n-pro-scheduler-prod
    restart: always
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    env_file:
      - .env.production
    volumes:
      - ./logs:/app/logs
    networks:
      - n8n-pro-network
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"

  # Webhook Service
  webhook:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile.webhook
    container_name: n8n-pro-webhook-prod
    restart: always
    ports:
      - "8081:8081"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      kafka:
        condition: service_healthy
    env_file:
      - .env.production
    volumes:
      - ./storage:/app/storage
      - ./logs:/app/logs
    networks:
      - n8n-pro-network
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"

# Named volumes for data persistence
volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  kafka_data:
    driver: local

EOF

    log_success "Production docker-compose configuration created at docker-compose.production.yml"
}

# Create backup script
create_backup_script() {
    log_info "Creating backup script..."
    
    mkdir -p scripts backups
    
    cat > scripts/backup.sh << 'EOF'
#!/bin/bash
# backup.sh - Backup script for n8n Pro production

set -e

BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/n8n_pro_backup_${DATE}.sql"

echo "Starting backup at $(date)"

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

# Backup PostgreSQL database
echo "Backing up PostgreSQL database..."
docker-compose -f docker-compose.production.yml exec -T postgres pg_dump -U n8n_pro -d n8n_clone > "${BACKUP_FILE}"

# Compress the backup
echo "Compressing backup..."
gzip "${BACKUP_FILE}"

echo "Backup completed: ${BACKUP_FILE}.gz"

# Clean up old backups (keep last 30 days)
find "${BACKUP_DIR}" -name "*.sql.gz" -mtime +30 -delete

echo "Backup process finished at $(date)"
EOF

    chmod +x scripts/backup.sh
    log_success "Backup script created at scripts/backup.sh"
}

# Create monitoring script
create_monitoring_script() {
    log_info "Creating monitoring script..."
    
    cat > scripts/monitor.sh << 'EOF'
#!/bin/bash
# monitor.sh - System monitoring script for n8n Pro

check_service() {
    local service_name=$1
    local health_url=$2
    
    if curl -f -s "${health_url}" > /dev/null; then
        echo "✅ ${service_name} is healthy"
        return 0
    else
        echo "❌ ${service_name} is unhealthy"
        return 1
    fi
}

echo "🔍 n8n Pro System Health Check"
echo "================================="

# Check all services
check_service "API" "http://localhost:8080/health"
check_service "Webhook" "http://localhost:8081/health"
check_service "Worker-1" "http://localhost:8082/health"
check_service "Worker-2" "http://localhost:8083/health"

echo ""
echo "📊 Docker Container Status:"
docker-compose -f docker-compose.production.yml ps

echo ""
echo "💾 Disk Usage:"
df -h

echo ""
echo "🧠 Memory Usage:"
free -h

echo ""
echo "⚡ System Load:"
uptime
EOF

    chmod +x scripts/monitor.sh
    log_success "Monitoring script created at scripts/monitor.sh"
}

# Create log directories
create_log_directories() {
    log_info "Creating log directories..."
    mkdir -p logs storage backups
    
    # Create log rotation config
    cat > logs/logrotate.conf << 'EOF'
/app/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 0644 appuser appuser
}
EOF

    log_success "Log directories and rotation config created"
}

# Main setup function
main() {
    echo "🚀 n8n Pro Production Setup"
    echo "============================"
    echo ""
    
    check_prerequisites
    create_production_env
    create_production_compose
    create_backup_script
    create_monitoring_script
    create_log_directories
    
    echo ""
    log_success "Production setup completed!"
    echo ""
    echo "Next steps:"
    echo "1. Review and customize .env.production with your specific settings"
    echo "2. Update CORS origins in .env.production to match your domain"
    echo "3. Set up SSL/TLS certificates for production"
    echo "4. Start the production stack: docker-compose -f docker-compose.production.yml up -d"
    echo "5. Set up monitoring and log aggregation"
    echo "6. Schedule regular backups using scripts/backup.sh"
    echo ""
    echo "📋 Useful commands:"
    echo "  Start: docker-compose -f docker-compose.production.yml up -d"
    echo "  Stop:  docker-compose -f docker-compose.production.yml down"
    echo "  Logs:  docker-compose -f docker-compose.production.yml logs -f"
    echo "  Monitor: ./scripts/monitor.sh"
    echo "  Backup: ./scripts/backup.sh"
    echo ""
    log_warn "Remember to save the generated credentials securely!"
}

# Run main function
main "$@"