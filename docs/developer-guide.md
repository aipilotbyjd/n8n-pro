# Developer Guide - n8n-pro

Welcome to the n8n-pro development team! This guide will help you get started with contributing to the project.

## 🚀 Quick Start

### Prerequisites

- **Go 1.21+** - [Download here](https://golang.org/dl/)
- **Docker & Docker Compose** - [Download here](https://docs.docker.com/get-docker/)
- **Git** - [Download here](https://git-scm.com/downloads)
- **Make** - Usually pre-installed on Unix systems

### One-Command Setup

```bash
make quick-start
```

This command will:
- Install dependencies
- Build the application
- Start the development environment
- Set up databases and services

### Manual Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/n8n-io/n8n-pro.git
   cd n8n-pro
   ```

2. **Install dependencies**
   ```bash
   make deps
   ```

3. **Install development tools**
   ```bash
   make install-tools
   ```

4. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Start development environment**
   ```bash
   make dev
   ```

## 🏗️ Development Environment

### Services

When you run `make dev`, the following services will be available:

| Service | URL | Purpose |
|---------|-----|---------|
| API | http://localhost:8080 | Main application API |
| Metrics | http://localhost:9090 | Prometheus metrics |
| PostgreSQL | localhost:5433 | Development database |
| Redis | localhost:6380 | Cache and sessions |
| MailHog | http://localhost:8025 | Email testing |

### Additional Development Tools

Start with additional tools:

```bash
# Database management tools
make dev-tools

# Monitoring stack
make dev-monitoring

# Full development stack
make dev-full
```

Additional services:

| Service | URL | Purpose |
|---------|-----|---------|
| pgAdmin | http://localhost:8081 | Database GUI |
| Redis Commander | http://localhost:8082 | Redis GUI |
| Prometheus | http://localhost:9091 | Metrics collection |
| Grafana | http://localhost:3001 | Dashboards |
| Jaeger | http://localhost:16686 | Distributed tracing |

### Default Credentials

Development environment default credentials:

| Service | Username | Password |
|---------|----------|----------|
| pgAdmin | dev@n8n-pro.com | devpassword |
| Grafana | admin | devpassword |
| PostgreSQL | n8n | devpassword |

## 🔧 Development Workflow

### Hot Reloading

The development environment includes automatic hot reloading using [Air](https://github.com/cosmtrek/air). Your changes will be automatically recompiled and restarted.

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run integration tests
make test-integration

# Run benchmarks
make bench
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run security checks
make security-scan

# Check for vulnerabilities
make deps-check
```

### Building

```bash
# Build for current platform
make build

# Build for Linux (for containers)
make build-linux

# Build Docker image
make docker-build
```

## 📁 Project Structure

```
n8n-pro/
├── cmd/                    # Application entrypoints
│   ├── api/               # Main API server
│   └── migrate/           # Database migrations
├── internal/              # Private application code
│   ├── api/              # HTTP handlers and routes
│   ├── auth/             # Authentication & authorization
│   ├── config/           # Configuration management
│   ├── database/         # Database layer
│   ├── execution/        # Workflow execution engine
│   ├── models/           # Data models
│   └── workflows/        # Workflow management
├── pkg/                  # Public library code
│   ├── config/          # Configuration utilities
│   ├── errors/          # Error definitions
│   ├── health/          # Health check system
│   ├── logger/          # Structured logging
│   ├── metrics/         # Metrics collection
│   ├── middleware/      # HTTP middleware
│   └── testutils/       # Testing utilities
├── test/                # Tests
│   ├── integration/     # Integration tests
│   ├── e2e/            # End-to-end tests
│   └── fixtures/       # Test fixtures
├── scripts/            # Build and deployment scripts
├── configs/            # Configuration files
├── docs/               # Documentation
└── .github/           # GitHub workflows
```

## 🧪 Testing Guidelines

### Unit Tests

- Place unit tests next to the code they test
- Use the `_test.go` suffix
- Follow the `TestFunctionName` pattern
- Use table-driven tests where appropriate

Example:
```go
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name    string
        input   *CreateUserRequest
        want    *User
        wantErr bool
    }{
        {
            name: "valid user creation",
            input: &CreateUserRequest{
                Email: "test@example.com",
                Name:  "Test User",
            },
            want: &User{
                Email: "test@example.com",
                Name:  "Test User",
            },
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Integration Tests

- Use the `integration` build tag
- Set up test databases and services
- Use the `testutils` package for common setup

Example:
```go
//go:build integration

func TestAuthAPI_Login(t *testing.T) {
    suite := testutils.NewTestSuite("auth-integration", nil)
    suite.SetupDatabase(t, &models.User{})
    suite.SetupHTTP(setupRouter())
    defer suite.Cleanup(t)
    
    // Test implementation
}
```

### Test Utilities

Use the `testutils` package for consistent testing:

```go
// Database testing
db, err := testutils.NewDatabaseTestHelper(nil)
require.NoError(t, err)

// HTTP testing
httpHelper := testutils.NewHTTPTestHelper(handler, nil)
resp, err := httpHelper.POST("/api/login", loginRequest)

// Assertions
testutils.AssertEqual(t, 200, resp.StatusCode)
testutils.AssertNoError(t, err)
```

## 🔍 Debugging

### Using Delve Debugger

The development container includes Delve for debugging:

```bash
# Start with debugger
docker-compose -f docker-compose.dev.yml exec n8n-pro-api dlv debug ./cmd/api

# Or attach to running process
docker-compose -f docker-compose.dev.yml exec n8n-pro-api dlv attach <pid>
```

Debugger will be available on port 2345.

### VS Code Integration

Add to `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Connect to server",
            "type": "go",
            "request": "attach",
            "mode": "remote",
            "remotePath": "/app",
            "port": 2345,
            "host": "127.0.0.1"
        }
    ]
}
```

### Logging

Use structured logging for debugging:

```go
logger.Debug("Processing request",
    "method", r.Method,
    "path", r.URL.Path,
    "user_id", userID,
)
```

## 📊 Performance Monitoring

### Metrics

Access metrics at http://localhost:9090/metrics

Key metrics to monitor:
- `n8n_pro_http_requests_total`
- `n8n_pro_workflow_executions_total`
- `n8n_pro_auth_login_attempts_total`
- `n8n_pro_db_query_duration_seconds`

### Profiling

Enable profiling in development:

```go
import _ "net/http/pprof"
```

Access profiling endpoints:
- http://localhost:8080/debug/pprof/
- http://localhost:8080/debug/pprof/heap
- http://localhost:8080/debug/pprof/profile

### Tracing

When Jaeger is enabled, traces are automatically collected and available at http://localhost:16686.

## 🚀 Deployment

### Local Deployment

```bash
# Build and deploy locally
make prod-build

# Deploy with monitoring
docker-compose --profile monitoring up -d
```

### Staging Deployment

```bash
make deploy-staging
```

### Production Deployment

```bash
# Tag release
git tag v1.0.0
git push origin v1.0.0

# Deploy (triggered automatically by CI/CD)
# Or manually:
make deploy-prod
```

## 🛠️ Common Development Tasks

### Adding a New API Endpoint

1. **Define the model** in `internal/models/`
2. **Create the handler** in `internal/api/handlers/`
3. **Add routes** in `internal/api/routes/`
4. **Add tests** for the handler
5. **Update API documentation**

### Adding Database Migrations

```bash
# Create new migration
./scripts/create-migration.sh add_user_table

# Run migrations
make db-migrate

# Rollback migrations
make db-rollback
```

### Adding New Configuration

1. **Update config struct** in `pkg/config/`
2. **Add environment variable** to `.env.example`
3. **Update documentation**
4. **Add validation** if needed

### Adding Metrics

```go
// Define metric
userCreations := prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "user_creations_total",
        Help: "Total number of user creations",
    },
    []string{"status"},
)

// Record metric
userCreations.WithLabelValues("success").Inc()
```

## 📝 Code Style Guidelines

### Go Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Follow Go naming conventions
- Write self-documenting code
- Add comments for public APIs

### Error Handling

Use the custom error types:

```go
import "n8n-pro/pkg/errors"

// Return typed errors
return errors.NewValidationError("invalid email format")

// Wrap errors with context
return errors.Wrap(err, "failed to create user")
```

### Logging

Use structured logging:

```go
logger.Info("User created",
    "user_id", user.ID,
    "email", user.Email,
    "organization_id", user.OrganizationID,
)
```

### Database Operations

Use the repository pattern:

```go
type UserRepository interface {
    Create(ctx context.Context, user *User) error
    FindByID(ctx context.Context, id string) (*User, error)
    Update(ctx context.Context, user *User) error
}
```

## 🤝 Contributing

### Before You Contribute

1. **Check existing issues** and PRs
2. **Create an issue** for new features
3. **Follow the coding standards**
4. **Write tests** for your changes
5. **Update documentation** as needed

### Pull Request Process

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/awesome-feature
   ```
3. **Make your changes**
4. **Run tests and linting**
   ```bash
   make test lint
   ```
5. **Commit with conventional commits**
   ```bash
   git commit -m "feat: add awesome feature"
   ```
6. **Push and create PR**

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `style:` formatting changes
- `refactor:` code refactoring
- `test:` adding tests
- `chore:` maintenance tasks

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Kill processes using the port
sudo lsof -ti:8080 | xargs kill -9
```

#### Database Connection Issues
```bash
# Check database status
make dev-logs

# Reset database
make db-reset
```

#### Docker Issues
```bash
# Clean Docker environment
make dev-clean

# Rebuild images
make docker-build-dev
```

#### Hot Reloading Not Working
```bash
# Check Air configuration
cat .air.toml

# Restart development environment
make dev-down && make dev
```

### Getting Help

1. **Check the logs**
   ```bash
   make dev-logs
   ```

2. **Search existing issues**
   - GitHub Issues
   - Stack Overflow

3. **Ask in Slack**
   - `#development` channel
   - `#support` channel

4. **Create an issue**
   - Provide reproduction steps
   - Include relevant logs
   - Mention your environment

## 📚 Additional Resources

### Documentation
- [API Documentation](./api-documentation.md)
- [Authentication System](./authentication-authorization.md)
- [Database Schema](./database-schema.md)
- [Deployment Guide](./deployment.md)

### External Resources
- [Go Documentation](https://golang.org/doc/)
- [Docker Documentation](https://docs.docker.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)

### Development Tools
- [Air (Hot Reloading)](https://github.com/cosmtrek/air)
- [Delve (Debugger)](https://github.com/go-delve/delve)
- [golangci-lint](https://golangci-lint.run/)
- [Gosec (Security)](https://github.com/securecodewarrior/sast-scan)

Happy coding! 🎉