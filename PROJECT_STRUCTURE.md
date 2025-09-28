# n8n Pro - Project Structure Documentation

## 📁 Directory Structure Overview

```
n8n-pro/
├── build/                  # Compiled binaries (git-ignored)
│   ├── api
│   ├── worker
│   ├── scheduler
│   ├── webhook
│   ├── admin
│   └── migrate
│
├── cmd/                    # Application entry points
│   ├── api/               # Main API server
│   ├── worker/            # Workflow execution worker
│   ├── scheduler/         # Cron job scheduler
│   ├── webhook/           # Webhook handler service
│   ├── admin/             # Admin CLI tool
│   └── migrate/           # Database migration tool
│
├── configs/               # Configuration files
│   ├── development/       # Development environment configs
│   │   └── .env.development
│   ├── production/        # Production environment configs
│   │   └── .env.production
│   ├── test/              # Test environment configs
│   │   └── .env.test
│   └── .env.example       # Example configuration template
│
├── deployments/           # Deployment configurations
│   ├── docker/            # Docker configurations
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   ├── k8s/               # Kubernetes manifests
│   │   ├── api-deployment.yaml
│   │   ├── worker-deployment.yaml
│   │   ├── scheduler.yaml
│   │   └── ingress.yaml
│   └── helm/              # Helm charts
│
├── docs/                  # Documentation
│   ├── architecture/      # System design and architecture
│   ├── api/              # API documentation
│   ├── development/      # Developer guides
│   ├── operations/       # Operations and deployment guides
│   ├── security/         # Security documentation
│   └── tutorials/        # User tutorials and examples
│
├── examples/             # Example code and usage
│   ├── auth/            # Authentication examples
│   ├── workflows/       # Workflow examples
│   └── config/          # Configuration examples
│
├── internal/            # Private application code
│   ├── domain/          # Core business logic (DDD)
│   │   ├── workflow/    # Workflow domain
│   │   ├── execution/   # Execution domain
│   │   ├── user/        # User domain
│   │   ├── team/        # Team domain
│   │   ├── audit/       # Audit domain
│   │   ├── nodes/       # Node definitions
│   │   └── credentials/ # Credentials domain
│   │
│   ├── application/     # Application services layer
│   │   ├── workflow/    # Workflow service
│   │   ├── auth/        # Authentication service
│   │   ├── billing/     # Billing service
│   │   ├── execution/   # Execution service
│   │   ├── scheduler/   # Scheduling service
│   │   └── notifications/ # Notification service
│   │
│   ├── infrastructure/  # External concerns
│   │   ├── database/    # Database implementation
│   │   │   ├── postgres.go
│   │   │   └── migrations.go
│   │   ├── messaging/   # Message queue implementation
│   │   │   └── kafka/
│   │   ├── storage/     # File storage implementation
│   │   │   └── s3/
│   │   └── cache/       # Cache implementation
│   │       └── redis/
│   │
│   ├── presentation/    # API and presentation layer
│   │   ├── http/        # REST API
│   │   │   ├── handlers/
│   │   │   ├── middleware/
│   │   │   └── routes/
│   │   ├── grpc/        # gRPC services (future)
│   │   └── websocket/   # WebSocket handlers
│   │
│   ├── repository/      # Data access layer
│   │   ├── workflow_repository.go
│   │   ├── user_repository.go
│   │   └── execution_repository.go
│   │
│   ├── shared/          # Cross-cutting concerns
│   │   ├── errors/      # Custom error types
│   │   ├── utils/       # Utility functions
│   │   └── constants/   # Application constants
│   │
│   └── testutils/       # Internal test utilities
│       └── shared/      # Shared test helpers
│
├── migrations/          # Database migrations
│   ├── 001_initial_schema.up.sql
│   ├── 001_initial_schema.down.sql
│   └── ...
│
├── pkg/                 # Public packages (can be imported by external projects)
│   ├── config/         # Configuration utilities
│   ├── logger/         # Logging utilities
│   ├── metrics/        # Metrics collection
│   ├── tracing/        # Distributed tracing
│   ├── errors/         # Error handling
│   ├── validation/     # Input validation
│   ├── retry/          # Retry logic
│   ├── utils/          # General utilities
│   └── middleware/     # Generic middleware
│
├── scripts/            # Utility scripts
│   ├── test-api.sh     # API testing script
│   ├── test_registration.sh
│   ├── setup.sh        # Project setup script
│   └── deploy.sh       # Deployment script
│
├── storage/            # Local storage (git-ignored)
│   ├── uploads/        # File uploads
│   ├── temp/           # Temporary files
│   └── cache/          # Cache files
│
├── test/               # Test suites
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   ├── e2e/           # End-to-end tests
│   ├── benchmarks/     # Performance benchmarks
│   └── fixtures/       # Test data and mocks
│
├── .air.toml           # Air configuration (hot reload)
├── .gitignore          # Git ignore file
├── docker-compose.yml  # Docker compose for production
├── docker-compose.dev.yml # Docker compose for development
├── go.mod              # Go module definition
├── go.sum              # Go module checksums
├── Makefile            # Build automation
└── README.md           # Project documentation
```

## 🏗️ Architecture Layers

### Domain Layer (`/internal/domain/`)
- **Purpose**: Core business logic and entities
- **Dependencies**: None (pure business logic)
- **Contains**: Domain models, business rules, domain services
- **Example**: Workflow validation rules, execution logic

### Application Layer (`/internal/application/`)
- **Purpose**: Application-specific business logic
- **Dependencies**: Domain layer, Infrastructure interfaces
- **Contains**: Use cases, application services, DTOs
- **Example**: CreateWorkflow service, ExecuteWorkflow use case

### Infrastructure Layer (`/internal/infrastructure/`)
- **Purpose**: External service implementations
- **Dependencies**: Domain layer (for interfaces)
- **Contains**: Database, messaging, storage implementations
- **Example**: PostgreSQL repository, Kafka publisher, S3 storage

### Presentation Layer (`/internal/presentation/`)
- **Purpose**: Handle external requests and responses
- **Dependencies**: Application layer
- **Contains**: HTTP handlers, middleware, routing
- **Example**: REST API endpoints, WebSocket handlers

### Repository Layer (`/internal/repository/`)
- **Purpose**: Data access abstraction
- **Dependencies**: Domain models
- **Contains**: Repository interfaces and implementations
- **Example**: WorkflowRepository, UserRepository

## 📦 Package Dependencies

```
cmd/ → internal/application/, internal/presentation/
presentation/ → application/, domain/
application/ → domain/, infrastructure/
infrastructure/ → domain/
domain/ → (no internal dependencies)
repository/ → domain/
pkg/ → (standalone, no internal dependencies)
shared/ → domain/ (minimal dependencies)
```

## 🔧 Key Packages

### `/pkg` - Public Packages
Reusable packages that could potentially be extracted to separate modules:
- `config`: Configuration management
- `logger`: Structured logging with Zap
- `metrics`: Prometheus metrics collection
- `tracing`: OpenTelemetry tracing
- `validation`: Input validation utilities

### `/internal` - Private Packages
Application-specific code that should not be imported by external projects:
- `domain`: Core business entities and logic
- `application`: Business use cases and services
- `infrastructure`: External service integrations
- `presentation`: API and user interface layer

## 📝 Configuration Management

### Environment-based Configuration
```
configs/
├── development/.env.development  # Local development settings
├── production/.env.production    # Production settings
├── test/.env.test                # Test environment settings
└── .env.example                  # Template with all variables
```

### Configuration Loading Priority
1. Environment variables
2. Configuration files (`.env`)
3. Command-line flags
4. Default values

## 🧪 Testing Strategy

### Test Organization
```
test/
├── unit/          # Fast, isolated unit tests
├── integration/   # Tests with external dependencies
├── e2e/          # Full system tests
├── benchmarks/   # Performance tests
└── fixtures/     # Shared test data
```

### Test File Naming Convention
- Unit tests: `*_test.go` (alongside source files)
- Integration tests: `test/integration/*_test.go`
- E2E tests: `test/e2e/*_test.go`
- Benchmarks: `test/benchmarks/*_bench_test.go`

## 🚀 Build and Deployment

### Binary Output
All compiled binaries are placed in `/build/`:
```bash
make build  # Builds all services to /build/
```

### Docker Images
- Development: `docker-compose.dev.yml`
- Production: `docker-compose.yml`
- Kubernetes: `/deployments/k8s/`

## 📚 Documentation Structure

```
docs/
├── architecture/     # System design, diagrams
├── api/             # OpenAPI specs, endpoint docs
├── development/     # Setup, contribution guidelines
├── operations/      # Deployment, monitoring, maintenance
├── security/        # Security policies, threat model
└── tutorials/       # User guides, examples
```

## 🔄 Migration Path

### From Old Structure to New Structure
1. **Database packages**: Consolidated from `/internal/db` and `/internal/database` to `/internal/infrastructure/database`
2. **API layer**: Moved from `/internal/api` to `/internal/presentation/http`
3. **Services**: Reorganized from `/internal/services` to `/internal/application/*`
4. **Test utilities**: Consolidated to `/internal/testutils/shared`
5. **Configuration**: Centralized in `/configs` directory

## 🛡️ Security Considerations

- Environment files (`.env`) are git-ignored
- Secrets are never committed to version control
- TLS certificates stored separately
- Sensitive configuration uses environment variables

## 📈 Scalability Considerations

- Microservices can be deployed independently
- Each service has its own binary in `/cmd`
- Horizontal scaling supported via Kubernetes deployments
- Message-driven architecture for async processing

## 🔍 Code Navigation Tips

1. **Find business logic**: Look in `/internal/domain`
2. **Find API endpoints**: Check `/internal/presentation/http/handlers`
3. **Find database queries**: See `/internal/repository`
4. **Find configuration**: Check `/configs` and `/internal/config`
5. **Find utilities**: Look in `/pkg` for reusable, `/internal/shared` for internal

## 📖 Further Reading

- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Domain-Driven Design](https://martinfowler.com/tags/domain%20driven%20design.html)
- [Go Project Layout](https://github.com/golang-standards/project-layout)
- [Twelve-Factor App](https://12factor.net/)