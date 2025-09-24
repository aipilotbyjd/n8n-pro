# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

**n8n Pro** is an enterprise-grade, cloud-native workflow automation platform built with Go. It provides a scalable, secure, and highly available solution for automating business processes, data integration, and API orchestration.

### Key Technologies
- **Language**: Go 1.23+
- **Database**: PostgreSQL 14+ (primary), Redis 6+ (caching/sessions)
- **Message Queue**: Apache Kafka 2.8+
- **Deployment**: Docker, Kubernetes, Helm
- **Architecture**: Microservices with distributed messaging

## Architecture Overview

The system follows a microservices architecture with these core services:

### Core Services
| Service | Description | Port | Entry Point |
|---------|-------------|------|-------------|
| **API** | REST API, GraphQL, authentication | 8080 | `cmd/api/main.go` |
| **Worker** | Workflow execution engine | 8082 | `cmd/worker/main.go` |
| **Scheduler** | CRON jobs and delayed tasks | N/A | `cmd/scheduler/main.go` |
| **Webhook** | Incoming webhook processing | 8081 | `cmd/webhook/main.go` |
| **Admin CLI** | Operations and maintenance | N/A | `cmd/admin/main.go` |

### Key Components

#### Configuration System (`internal/config/`)
- Comprehensive configuration management with environment variable support
- Type-safe configuration structs for all services
- Covers API, database, Redis, Kafka, auth, security, and more

#### Workflow Engine (`internal/workflows/`)
- **Models**: Rich domain models for workflows, executions, nodes, and connections
- **Service Layer**: Business logic for workflow management and execution
- **Repository Pattern**: Data access abstraction
- **Execution Engine**: Distributed workflow execution with retry logic
- **Template System**: Reusable workflow templates

#### Authentication & Authorization (`internal/auth/`)
- JWT-based authentication with refresh tokens
- Role-based access control (RBAC)
- OAuth2/OIDC integration support
- Multi-factor authentication (MFA)

#### Node System (`internal/nodes/`)
- Extensible node registry for workflow components
- Built-in integrations (Slack, Google Workspace, HTTP, Database, etc.)
- Code execution sandbox for JavaScript/Python
- Credential management with encryption

#### Multi-tenancy (`internal/teams/`)
- Team-based isolation
- Resource sharing and permissions
- Usage limits and billing integration

### Data Flow
1. **Trigger Events** → Webhook/Scheduler → Kafka → Worker
2. **Workflow Execution** → Worker pulls from Kafka → Executes nodes → Updates database
3. **API Operations** → Authentication → Business logic → Database/Redis

## Development Commands

### Environment Setup
```bash
# Install dependencies and tools
make deps
make tools-install

# Start development infrastructure (PostgreSQL, Redis, Kafka)
make dev

# Run database migrations
make db-migrate

# Seed with sample data (optional)  
make db-seed
```

### Building
```bash
# Build all services
make build-all

# Build individual services
make build/api          # API service
make build/worker       # Worker service  
make build/scheduler    # Scheduler service
make build/webhook      # Webhook service
make build/admin        # Admin CLI

# Cross-platform builds
make build-linux        # Linux binaries
make build-darwin       # macOS binaries
make build-windows      # Windows binaries
```

### Running Services Locally
```bash
# Run individual services (after build)
make run-api            # Start API on :8080
make run-worker         # Start worker service
make run-scheduler      # Start scheduler service
make run-webhook        # Start webhook service on :8081

# Watch mode for development
make watch              # Auto-rebuild on changes (requires air)
```

### Testing
```bash
# Run all tests
make test

# Test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests
make test-e2e          # End-to-end tests
make benchmark         # Performance benchmarks

# Generate coverage report
make test-coverage      # Creates coverage.html
```

### Code Quality
```bash
# Format and lint code
make fmt               # Format Go code
make lint              # Run golangci-lint
make vet               # Run go vet
make security-check    # Run gosec security analysis

# Run all quality checks
make check-all         # Format check, vet, lint, security, test
```

### Database Operations
```bash
# Database management
make db-up             # Start PostgreSQL and Redis
make db-down           # Stop database services
make db-migrate        # Run migrations up
make db-migrate-down   # Rollback migrations
make db-seed           # Populate with test data
make db-reset          # Reset database (down, up, seed)
make db-shell          # Connect to PostgreSQL shell
```

### Docker Operations
```bash
# Build Docker images
make docker-build      # Build all service images
make docker-build-api  # Build API image only

# Run with Docker Compose
make docker-run        # Start all services
make docker-stop       # Stop all services  
make docker-logs       # View service logs

# Registry operations
make docker-push       # Push images to registry
```

### Monitoring and Debugging
```bash
# View service logs
make logs              # All services
make logs-api          # API service only
make logs-worker       # Worker service only

# Health checks
make health-check      # Check service health endpoints

# Service metrics
make metrics           # Open metrics dashboard (localhost:9090)
```

## Testing Approach

### Running Specific Tests
```bash
# Run tests for specific package
go test ./internal/workflows/...

# Run specific test function
go test -run TestWorkflowExecution ./internal/workflows/

# Run tests with verbose output
go test -v ./...

# Run tests with race detection
go test -race ./...
```

### Test Structure
- **Unit Tests**: Located alongside source files (`*_test.go`)
- **Integration Tests**: In `test/integration/` with build tag `integration`
- **E2E Tests**: In `test/e2e/` with build tag `e2e`
- **Benchmarks**: In `test/benchmarks/` for performance testing

## Configuration

The application uses environment variables for configuration. Key files:
- `.env.example` - Complete configuration template
- `internal/config/config.go` - Configuration structs and loading logic

### Essential Environment Variables
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_clone
DB_USER=user
DB_PASSWORD=password

# Authentication  
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
ENCRYPTION_KEY=your-encryption-key-32-characters-long

# Services
API_PORT=8080
WEBHOOK_PORT=8081
WORKER_HEALTH_CHECK_PORT=8082

# Infrastructure
KAFKA_BROKERS=localhost:9092
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Key Development Patterns

### Repository Pattern
```go
// Repository interface defines data access contract
type WorkflowRepository interface {
    Create(ctx context.Context, workflow *Workflow) error
    GetByID(ctx context.Context, id string) (*Workflow, error)
    Update(ctx context.Context, workflow *Workflow) error
    Delete(ctx context.Context, id string) error
}
```

### Service Layer Pattern
Services orchestrate business logic and coordinate between repositories, external services, and validation:
```go
type Service struct {
    repo      WorkflowRepository
    validator Validator
    executor  Executor
    // ... other dependencies
}
```

### Domain Models
Rich domain models with business logic in `internal/workflows/models.go`:
- `Workflow` - Complete workflow definition with nodes, connections, variables
- `WorkflowExecution` - Runtime execution state and history
- `Node` - Individual workflow components with type-specific parameters
- `Connection` - Links between nodes with conditional logic

### Error Handling
Structured error handling with custom error types in `pkg/errors/`:
```go
return errors.ValidationError(errors.CodeInvalidInput, "workflow name required")
```

### Configuration Management
Type-safe configuration with validation and environment variable mapping.

## Deployment

### Docker Compose (Development)
```bash
make docker-run        # Starts all services with dependencies
```

### Kubernetes
```bash
make k8s-deploy        # Apply K8s manifests
make k8s-status        # Check deployment status
make k8s-delete        # Remove deployment
```

### Helm Charts
```bash
make helm-install      # Install with Helm
make helm-upgrade      # Upgrade deployment  
make helm-uninstall    # Remove Helm deployment
```

## Performance Considerations

### Service Scaling
- **API Service**: Scale based on HTTP request volume (stateless)
- **Worker Service**: Scale based on Kafka queue depth (horizontal scaling)
- **Database**: Use read replicas for heavy read workloads
- **Redis**: Cluster mode for high availability

### Resource Limits
- Default worker memory: 128MB per instance
- Sandbox execution limits: configurable CPU/memory constraints
- Workflow execution timeout: configurable (default 10 minutes)

## Security

### Credential Management
Encrypted credential storage with the credential manager in `internal/credentials/`:
- AES-256 encryption for sensitive data
- Vault integration support
- Secure credential sharing between team members

### Sandbox Execution
Safe code execution environment:
- Resource limits (memory, CPU, disk)
- Network policy restrictions
- Package allow/block lists
- Execution timeouts

### Authentication
- JWT tokens with configurable expiration
- Refresh token rotation
- OAuth2/OIDC provider integration
- Multi-factor authentication support

## Monitoring

### Health Endpoints
- API: `http://localhost:8080/health`
- Webhook: `http://localhost:8081/health` 
- Worker: `http://localhost:8082/health`

### Prometheus Metrics
- `n8n_pro_workflow_executions_total` - Total executions
- `n8n_pro_workflow_execution_duration_seconds` - Execution duration
- `n8n_pro_http_requests_total` - HTTP request count
- `n8n_pro_db_connections_open` - Database connection pool

### Logging
Structured JSON logging with configurable levels. Key fields:
- `service` - Service name (api, worker, scheduler, webhook)
- `workflow_id` - Workflow identifier for tracing
- `execution_id` - Execution identifier for debugging
- `user_id` - User context for audit trails