# Make Commands Reference

This document provides a comprehensive reference for all available Make commands in the n8n-pro project.

## 🚀 Quick Reference

```bash
make help                 # Show all available commands
make build               # Build all services
make dev                 # Start development environment
make test                # Run all tests
make db-migrate          # Run database migrations
make docker-run          # Run with Docker Compose
```

## 📦 Build Commands

### Core Build Targets

| Command | Description | Output Location |
|---------|-------------|-----------------|
| `make build` | Build all service binaries | `./build/` |
| `make build-all` | Alias for `build` | `./build/` |
| `make build-services` | Build all services | `./build/` |

### Individual Service Builds

| Command | Description | Output |
|---------|-------------|--------|
| `make build/api` | Build API service | `./build/api` |
| `make build/worker` | Build Worker service | `./build/worker` |
| `make build/scheduler` | Build Scheduler service | `./build/scheduler` |
| `make build/webhook` | Build Webhook service | `./build/webhook` |
| `make build/admin` | Build Admin CLI | `./build/admin` |
| `make build/migrate` | Build Migration CLI | `./build/migrate` |

### Cross-Platform Builds

| Command | Description | Output Location |
|---------|-------------|-----------------|
| `make build-linux` | Build for Linux AMD64 | `./build/linux/` |
| `make build-darwin` | Build for macOS AMD64 | `./build/darwin/` |
| `make build-windows` | Build for Windows AMD64 | `./build/windows/` |
| `make build-all-platforms` | Build for all platforms | `./build/{platform}/` |

## 🧪 Development Commands

### Environment Setup

| Command | Description | Notes |
|---------|-------------|-------|
| `make dev` | Start development environment | Starts PostgreSQL, Redis, Kafka |
| `make dev-down` | Stop development environment | |
| `make dev-setup` | Complete development setup | Build + migrate + ready to code |
| `make dev-reset` | Reset and setup development | Resets DB + fresh setup |

### Running Services

| Command | Description | Port | Dependencies |
|---------|-------------|------|--------------|
| `make run-api` | Run API service locally | 8080 | Database |
| `make run-worker` | Run Worker service locally | 8082 | Database, Kafka |
| `make run-scheduler` | Run Scheduler service locally | N/A | Database |
| `make run-webhook` | Run Webhook service locally | 8081 | Database |

### Development Tools

| Command | Description | Purpose |
|---------|-------------|---------|
| `make watch` | Watch for changes and rebuild | Development |
| `make deps` | Install Go dependencies | Setup |
| `make deps-update` | Update dependencies | Maintenance |
| `make deps-verify` | Verify dependencies | Validation |
| `make tools-install` | Install development tools | Setup |

## 🧪 Testing Commands

### Test Execution

| Command | Description | Scope | Coverage |
|---------|-------------|-------|----------|
| `make test` | Run all tests | Unit + Integration | Yes |
| `make test-unit` | Run unit tests only | Unit | Yes |
| `make test-integration` | Run integration tests | Integration | Yes |
| `make test-e2e` | Run end-to-end tests | E2E | No |
| `make benchmark` | Run performance benchmarks | Performance | No |

### Test Analysis

| Command | Description | Output |
|---------|-------------|--------|
| `make test-coverage` | Generate coverage report | `coverage.html` |
| `make test-race` | Run tests with race detection | Console |
| `make test-verbose` | Run tests with verbose output | Console |

## 🔍 Code Quality Commands

### Code Formatting

| Command | Description | Auto-fix |
|---------|-------------|----------|
| `make fmt` | Format Go code | Yes |
| `make fmt-check` | Check if code is formatted | No |

### Code Analysis

| Command | Description | Severity | Auto-fix |
|---------|-------------|----------|----------|
| `make lint` | Run linter | Warning/Error | Some |
| `make vet` | Run go vet | Error | No |
| `make security-check` | Run security scanner | Critical | No |
| `make check-all` | Run all quality checks | All | Some |

## 🗄️ Database Commands

### Migration Management

| Command | Description | Environment | Safety |
|---------|-------------|-------------|--------|
| `make db-migrate` | Run all pending migrations | All | Safe |
| `make db-migrate-status` | Show migration status | All | Safe |
| `make db-migrate-rollback` | Rollback last batch | All | Careful |
| `make db-migrate-health` | Check database health | All | Safe |
| `make db-reset` | Reset database (DEV ONLY) | Development | **Destructive** |

### Database Services

| Command | Description | Services |
|---------|-------------|----------|
| `make db-up` | Start database services | PostgreSQL, Redis |
| `make db-down` | Stop database services | PostgreSQL, Redis |
| `make db-shell` | Connect to database shell | PostgreSQL |

## 🐳 Docker Commands

### Image Management

| Command | Description | Tags |
|---------|-------------|------|
| `make docker-build` | Build all Docker images | `latest`, `{VERSION}` |
| `make docker-build-api` | Build API image | `api:latest` |
| `make docker-build-worker` | Build Worker image | `worker:latest` |
| `make docker-build-scheduler` | Build Scheduler image | `scheduler:latest` |
| `make docker-build-webhook` | Build Webhook image | `webhook:latest` |

### Container Operations

| Command | Description | Services |
|---------|-------------|----------|
| `make docker-run` | Run with Docker Compose | All services |
| `make docker-stop` | Stop Docker Compose | All services |
| `make docker-logs` | View service logs | All services |
| `make docker-push` | Push images to registry | All images |

### Cleanup

| Command | Description | Scope |
|---------|-------------|-------|
| `make clean-docker` | Clean Docker images | Local images |
| `make docker-prune` | Prune unused Docker resources | System-wide |

## ☸️ Kubernetes Commands

### Deployment

| Command | Description | Namespace |
|---------|-------------|-----------|
| `make k8s-deploy` | Deploy to Kubernetes | `default` |
| `make k8s-status` | Check deployment status | `default` |
| `make k8s-delete` | Delete from Kubernetes | `default` |

### Helm Operations

| Command | Description | Chart |
|---------|-------------|-------|
| `make helm-install` | Install with Helm | `n8n-pro` |
| `make helm-upgrade` | Upgrade with Helm | `n8n-pro` |
| `make helm-uninstall` | Uninstall with Helm | `n8n-pro` |

## 📊 Monitoring Commands

### Health Checks

| Command | Description | Services |
|---------|-------------|----------|
| `make health-check` | Check service health | API, Worker, Webhook |
| `make logs` | View application logs | All services |
| `make logs-api` | View API service logs | API only |
| `make logs-worker` | View Worker service logs | Worker only |
| `make logs-scheduler` | View Scheduler logs | Scheduler only |
| `make logs-webhook` | View Webhook logs | Webhook only |

### Metrics

| Command | Description | Port |
|---------|-------------|------|
| `make metrics` | Open metrics dashboard | 9090 |
| `make metrics-export` | Export metrics | File |

## 🏭 Release Commands

### Release Management

| Command | Description | Output |
|---------|-------------|--------|
| `make release` | Build release for all platforms | `./dist/` |
| `make changelog` | Generate changelog | `CHANGELOG.md` |

### Distribution

| Command | Description | Format |
|---------|-------------|--------|
| `make package-linux` | Package Linux release | `.tar.gz` |
| `make package-darwin` | Package macOS release | `.tar.gz` |
| `make package-windows` | Package Windows release | `.zip` |

## 🧹 Cleanup Commands

### Build Artifacts

| Command | Description | Scope |
|---------|-------------|-------|
| `make clean` | Clean build artifacts | `./build/`, `./dist/` |
| `make clean-all` | Clean everything | Build + Docker |

### Development Environment

| Command | Description | Scope |
|---------|-------------|-------|
| `make clean-dev` | Clean development data | Local data only |
| `make clean-cache` | Clean Go build cache | Go cache |

## ℹ️ Information Commands

### System Information

| Command | Description | Output |
|---------|-------------|--------|
| `make version` | Show version information | Version details |
| `make env` | Show environment information | Go environment |
| `make size` | Show binary sizes | File sizes |

### Configuration

| Command | Description | Output |
|---------|-------------|--------|
| `make config-check` | Validate configuration | Validation results |
| `make config-example` | Generate example config | `.env.example` |

## 🔧 Utility Commands

### File Operations

| Command | Description | Purpose |
|---------|-------------|---------|
| `make generate` | Generate code from templates | Code generation |
| `make proto` | Generate protobuf code | gRPC |
| `make swagger` | Generate API documentation | Swagger/OpenAPI |

### Dependency Management

| Command | Description | Scope |
|---------|-------------|-------|
| `make mod-tidy` | Clean up Go modules | Go modules |
| `make mod-download` | Download dependencies | Go dependencies |
| `make mod-verify` | Verify dependencies | Integrity check |

## 🎯 Workflow Examples

### Complete Development Setup

```bash
# 1. Get dependencies and tools
make deps tools-install

# 2. Start development environment
make dev

# 3. Run database migrations  
make db-migrate

# 4. Build all services
make build

# 5. Run tests
make test

# 6. Start API service
make run-api
```

### Production Build

```bash
# 1. Clean previous builds
make clean

# 2. Run all quality checks
make check-all

# 3. Run full test suite
make test

# 4. Build for all platforms
make build-all-platforms

# 5. Create release packages
make release
```

### Docker Deployment

```bash
# 1. Build Docker images
make docker-build

# 2. Run with Docker Compose
make docker-run

# 3. Check service health
make health-check

# 4. View logs
make docker-logs
```

### Database Operations

```bash
# 1. Start database
make db-up

# 2. Check migration status
make db-migrate-status

# 3. Run pending migrations
make db-migrate

# 4. Verify database health
make db-migrate-health
```

## 📝 Notes

### Environment Variables

Some commands respect these environment variables:

- `ENVIRONMENT` - Target environment (development, staging, production)
- `DB_HOST` - Database host for connections
- `DOCKER_REGISTRY` - Docker registry for image operations
- `KUBECONFIG` - Kubernetes configuration file

### Dependencies

Before running most commands, ensure you have:

- **Go 1.21+** installed
- **Docker** and **Docker Compose** installed  
- **PostgreSQL** client tools (for database commands)
- **kubectl** and **helm** (for Kubernetes commands)

### Troubleshooting

If commands fail:

1. Check that all dependencies are installed: `make deps-verify`
2. Verify environment setup: `make env`
3. Check service health: `make health-check` 
4. View logs: `make logs`

For more detailed troubleshooting, see the [Operations Guide](../operations/troubleshooting.md).

---

**Last Updated**: 2025-01-26 | **Make Version**: GNU Make 4.3+