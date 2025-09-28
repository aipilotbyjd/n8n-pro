# n8n Pro - Quick Reference Guide

## 🚀 Quick Start

### Development Setup
```bash
# 1. Clone and setup
git clone <repository>
cd n8n-pro

# 2. Install dependencies
go mod download

# 3. Setup configuration
cp configs/.env.example configs/development/.env.development
# Edit configs/development/.env.development with your settings

# 4. Run database migrations
make migrate-up

# 5. Build all services
make build-all

# 6. Run in development mode
make dev
```

## 📁 Where to Find Things

### Core Business Logic
- **Domain Models**: `internal/domain/*/models.go`
- **Business Rules**: `internal/domain/*/service.go`
- **Domain Events**: `internal/domain/*/events.go`

### API Endpoints
- **HTTP Handlers**: `internal/presentation/http/handlers/`
- **Routes**: `internal/presentation/http/routes/`
- **Middleware**: `internal/presentation/http/middleware/`
- **Validators**: `internal/presentation/http/validators/`

### Services & Use Cases
- **Auth Service**: `internal/application/auth/`
- **Workflow Service**: `internal/application/workflow/`
- **Execution Service**: `internal/application/execution/`
- **Billing Service**: `internal/application/billing/`

### Database & Persistence
- **Repositories**: `internal/repository/`
- **Migrations**: `migrations/`
- **Database Config**: `internal/infrastructure/database/`

### Configuration
- **Development**: `configs/development/.env.development`
- **Production**: `configs/production/.env.production`
- **Test**: `configs/test/.env.test`
- **Example**: `configs/.env.example`

### Tests
- **Unit Tests**: Next to source files (`*_test.go`)
- **Integration Tests**: `test/integration/`
- **E2E Tests**: `test/e2e/`
- **Benchmarks**: `test/benchmarks/`
- **Test Fixtures**: `test/fixtures/`

## 🔨 Common Commands

### Build Commands
```bash
# Build all services
make build-all

# Build specific service
make build-api
make build-worker
make build-scheduler

# Build with specific flags
go build -o build/api ./cmd/api
```

### Run Commands
```bash
# Run API server
./build/api

# Run with hot reload (development)
make dev

# Run specific service
make run-api
make run-worker
make run-scheduler

# Run with Docker
docker-compose up
docker-compose -f docker-compose.dev.yml up
```

### Test Commands
```bash
# Run all tests
make test

# Run unit tests
go test ./...

# Run integration tests
make test-integration

# Run with coverage
make test-coverage

# Run specific test
go test ./internal/domain/workflow/...

# Run benchmarks
go test -bench=. ./test/benchmarks/...
```

### Database Commands
```bash
# Run migrations up
make migrate-up

# Rollback migrations
make migrate-down

# Create new migration
make migration name=add_users_table

# Reset database
make db-reset
```

### Docker Commands
```bash
# Build Docker images
make docker-build

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down

# Clean up
docker-compose down -v
```

## 🏗️ Project Structure

```
n8n-pro/
├── cmd/                    # Service entry points
│   ├── api/               # REST API server
│   ├── worker/            # Background job worker
│   └── scheduler/         # Cron scheduler
│
├── internal/              # Private application code
│   ├── domain/           # Core business logic
│   ├── application/      # Use cases & services
│   ├── infrastructure/   # External integrations
│   ├── presentation/     # API layer
│   └── repository/       # Data access layer
│
├── pkg/                   # Public packages
├── configs/              # Configuration files
├── migrations/           # Database migrations
├── scripts/              # Utility scripts
├── test/                 # Test suites
└── docs/                 # Documentation
```

## 🔄 Import Paths After Migration

| Old Import | New Import |
|------------|------------|
| `internal/api/handlers` | `internal/presentation/http/handlers` |
| `internal/database` | `internal/infrastructure/database` |
| `internal/auth` | `internal/application/auth` |
| `internal/workflows` | `internal/domain/workflow` |
| `internal/common` | `internal/shared` |
| `internal/db` | `internal/infrastructure/database` |

## 🛠️ Development Workflow

### 1. Making Changes
```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes
vim internal/domain/workflow/service.go

# Run tests
go test ./internal/domain/workflow/...

# Format code
make fmt

# Lint code
make lint
```

### 2. Adding New Features

#### Add New Domain Entity
1. Create model in `internal/domain/<entity>/models.go`
2. Create repository interface in `internal/domain/<entity>/repository.go`
3. Implement repository in `internal/repository/<entity>_repository.go`
4. Create service in `internal/application/<entity>/service.go`
5. Add HTTP handler in `internal/presentation/http/handlers/<entity>.go`
6. Add routes in `internal/presentation/http/routes/routes.go`

#### Add New API Endpoint
1. Define handler in `internal/presentation/http/handlers/`
2. Add validation in `internal/presentation/http/validators/`
3. Register route in `internal/presentation/http/routes/`
4. Add tests in `*_test.go`

#### Add New Migration
```bash
# Create migration files
make migration name=add_feature_table

# Edit migration files in migrations/
vim migrations/xxx_add_feature_table.up.sql
vim migrations/xxx_add_feature_table.down.sql

# Apply migration
make migrate-up
```

## 📋 Environment Variables

### Essential Variables
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# API Server
API_PORT=8080
API_HOST=0.0.0.0

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRY=24h

# Environment
ENV=development  # development, staging, production
```

## 🐛 Debugging

### View Logs
```bash
# API logs
tail -f logs/api.log

# All logs
tail -f logs/*.log

# Docker logs
docker-compose logs -f
```

### Debug Mode
```bash
# Run with debug logging
DEBUG=true ./build/api

# Run with verbose output
VERBOSE=true make test
```

### Common Issues

#### Import Errors After Migration
```bash
# Update all imports automatically
go mod tidy
make fix-imports
```

#### Database Connection Issues
```bash
# Check database status
make db-status

# Reset database
make db-reset
```

#### Build Failures
```bash
# Clean and rebuild
make clean
make build-all
```

## 📚 Documentation

- **Architecture**: `docs/architecture/`
- **API Reference**: `docs/api/`
- **Development Guide**: `docs/development/`
- **Deployment**: `docs/operations/deployment/`
- **Security**: `docs/security/`
- **Migration Guide**: `docs/MIGRATION.md`

## 🔗 Useful Links

### Internal Documentation
- [Project Structure](PROJECT_STRUCTURE.md)
- [API Documentation](docs/api-reference.md)
- [Configuration Guide](docs/configuration.md)
- [Security Guide](docs/security.md)

### External Resources
- [Go Documentation](https://golang.org/doc/)
- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

## 💡 Tips & Tricks

### Fast Development
```bash
# Use air for hot reload
air -c .air.toml

# Run only changed tests
go test -run TestName ./...

# Quick build without optimization
go build -o build/api-dev ./cmd/api
```

### Performance
```bash
# Run benchmarks
go test -bench=. -benchmem ./...

# Generate CPU profile
go test -cpuprofile=cpu.prof -bench=.

# Analyze profile
go tool pprof cpu.prof
```

### Code Quality
```bash
# Format all code
gofmt -s -w .

# Run linter
golangci-lint run

# Check for vulnerabilities
go list -json -m all | nancy sleuth
```

## 🚨 Emergency Commands

```bash
# Stop all services
docker-compose down
pkill -f n8n-pro

# Emergency database backup
pg_dump -h localhost -U user n8n_pro > backup.sql

# Rollback last migration
make migrate-down

# Reset to clean state
make clean
make db-reset
git clean -fdx
```

## 📞 Getting Help

1. Check documentation in `docs/`
2. Look for examples in `examples/`
3. Search existing tests for usage patterns
4. Review `PROJECT_STRUCTURE.md` for detailed layout
5. Check `docs/MIGRATION.md` for recent changes

---

Last Updated: 2024
Version: 1.0.0