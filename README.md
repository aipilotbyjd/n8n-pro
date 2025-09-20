# n8n Pro - Enterprise Workflow Automation Platform

[![Build Status](https://github.com/your-org/n8n-pro/workflows/CI/badge.svg)](https://github.com/your-org/n8n-pro/actions)
[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue?style=flat&logo=docker)](https://hub.docker.com/r/n8n-pro/api)
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-blue?style=flat&logo=kubernetes)](deployments/k8s/)

> **n8n Pro** is an enterprise-grade, cloud-native workflow automation platform built with Go. It provides a scalable, secure, and highly available solution for automating business processes, data integration, and API orchestration.

## 🚀 Features

### Core Features
- **Visual Workflow Editor**: Intuitive drag-and-drop interface for creating complex workflows
- **200+ Built-in Nodes**: Pre-built integrations with popular services (Slack, Google Workspace, AWS, etc.)
- **Code Execution**: Support for JavaScript and Python code nodes with secure sandboxing
- **Multiple Triggers**: Webhook, schedule, email, file watching, and database triggers
- **Real-time Execution**: Live workflow execution with detailed logging and monitoring

### Enterprise Features
- **Multi-tenancy**: Team-based isolation with role-based access control (RBAC)
- **High Availability**: Distributed architecture with load balancing and failover
- **Scalable Execution**: Horizontal scaling of workflow workers
- **Advanced Security**: Encryption at rest, OAuth2/OIDC integration, audit logging
- **Workflow Versioning**: Git-like versioning system for workflow management
- **Template Library**: Shareable workflow templates with marketplace
- **Advanced Monitoring**: Prometheus metrics, distributed tracing, comprehensive dashboards

### DevOps & Operations
- **Cloud Native**: Kubernetes-ready with Helm charts
- **Observability**: Structured logging, metrics, and distributed tracing
- **CI/CD Ready**: Docker images, automated testing, deployment pipelines
- **Database Migrations**: Automated schema management
- **Backup & Recovery**: Built-in backup and restore capabilities

## 🏗️ Architecture

n8n Pro follows a microservices architecture designed for scalability and reliability:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   API Gateway   │    │   Web Frontend  │
└─────────┬───────┘    └─────────┬───────┘    └─────────────────┘
          │                      │
          └──────────────────────┼──────────────────────────────┐
                                 │                              │
        ┌────────────────────────┼──────────────────────────────┴─┐
        │                       │                                │
   ┌────▼────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
   │   API   │  │   Webhook   │  │  Scheduler  │  │   Worker    │
   │ Service │  │   Service   │  │   Service   │  │   Service   │
   └────┬────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
        │              │                │                │
        └──────────────┼────────────────┼────────────────┘
                       │                │
        ┌──────────────▼────────────────▼──────────────────┐
        │              Message Queue (Kafka)               │
        └──────────────────────┬───────────────────────────┘
                               │
        ┌──────────────────────▼───────────────────────────┐
        │                 PostgreSQL                       │
        │            (Primary Database)                    │
        └──────────────────────┬───────────────────────────┘
                               │
        ┌──────────────────────▼───────────────────────────┐
        │                    Redis                         │
        │            (Caching & Sessions)                  │
        └──────────────────────────────────────────────────┘
```

### Services Overview

| Service | Description | Port | Scaling |
|---------|-------------|------|---------|
| **API** | REST API, GraphQL, authentication | 8080 | Horizontal |
| **Worker** | Workflow execution engine | 8082 | Horizontal |
| **Scheduler** | CRON jobs and delayed tasks | N/A | Active/Standby |
| **Webhook** | Incoming webhook processing | 8081 | Horizontal |
| **Admin CLI** | Operations and maintenance | N/A | On-demand |

## 🚦 Quick Start

### Prerequisites

- **Go 1.23+** - [Install Go](https://golang.org/doc/install)
- **PostgreSQL 14+** - [Install PostgreSQL](https://www.postgresql.org/download/)
- **Redis 6+** - [Install Redis](https://redis.io/download)
- **Apache Kafka 2.8+** - [Install Kafka](https://kafka.apache.org/downloads)
- **Docker & Docker Compose** - [Install Docker](https://docs.docker.com/get-docker/)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/n8n-pro.git
   cd n8n-pro
   ```

2. **Install dependencies**
   ```bash
   make deps
   make tools-install
   ```

3. **Start development environment**
   ```bash
   # Start infrastructure services (PostgreSQL, Redis, Kafka)
   make dev
   
   # Run database migrations
   make db-migrate
   
   # Seed with sample data (optional)
   make db-seed
   ```

4. **Build and run services**
   ```bash
   # Build all services
   make build
   
   # Run services (in separate terminals)
   make run-api      # API service on :8080
   make run-worker   # Worker service
   make run-scheduler # Scheduler service  
   make run-webhook  # Webhook service on :8081
   ```

5. **Access the application**
   - **API**: http://localhost:8080
   - **Health Check**: http://localhost:8080/health
   - **Metrics**: http://localhost:9090/metrics
   - **Webhooks**: http://localhost:8081

### Using Docker Compose

```bash
# Start all services
make docker-run

# View logs
make logs

# Stop services
make docker-stop
```

### Quick Test

Create a simple workflow:

```bash
curl -X POST http://localhost:8080/api/v1/workflows \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Hello World",
    "nodes": [
      {
        "id": "start",
        "type": "trigger",
        "name": "Manual Trigger"
      },
      {
        "id": "log",
        "type": "code",
        "name": "Log Message",
        "code": "console.log(\"Hello, World!\"); return { message: \"Hello, World!\" };"
      }
    ],
    "connections": [
      {
        "source_node": "start",
        "target_node": "log"
      }
    ]
  }'
```

## 📖 Documentation

### Configuration

n8n Pro uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
# Edit .env with your settings
```

Key configuration sections:

- **Database**: PostgreSQL connection settings
- **Redis**: Caching and session storage
- **Kafka**: Message queue configuration  
- **Authentication**: JWT secrets, OAuth providers
- **Security**: Encryption keys, CORS settings
- **Limits**: Resource and rate limits

See [Configuration Guide](docs/configuration.md) for detailed options.

### API Documentation

The API follows RESTful principles with comprehensive OpenAPI documentation:

- **API Base URL**: `http://localhost:8080/api/v1`
- **Authentication**: Bearer token (JWT)
- **Content Type**: `application/json`

#### Core Endpoints

```
# Workflows
GET    /api/v1/workflows              # List workflows
POST   /api/v1/workflows              # Create workflow
GET    /api/v1/workflows/{id}         # Get workflow
PUT    /api/v1/workflows/{id}         # Update workflow
DELETE /api/v1/workflows/{id}         # Delete workflow

# Executions
GET    /api/v1/executions             # List executions
POST   /api/v1/workflows/{id}/execute # Execute workflow
GET    /api/v1/executions/{id}        # Get execution
DELETE /api/v1/executions/{id}/cancel # Cancel execution

# Webhooks
POST   /webhook/{workflow_id}         # Trigger workflow via webhook
POST   /webhook/{workflow_id}/{node_id} # Trigger specific node
```

See [API Documentation](docs/api.md) for complete reference.

### Development

#### Project Structure

```
n8n-pro/
├── cmd/                    # Service entrypoints
│   ├── api/               # REST API server
│   ├── worker/            # Workflow execution worker
│   ├── scheduler/         # CRON scheduler service
│   ├── webhook/           # Webhook listener
│   └── admin/             # Admin CLI tool
├── internal/              # Private application code
│   ├── api/               # API handlers and middleware
│   ├── auth/              # Authentication system
│   ├── workflows/         # Workflow management
│   ├── execution/         # Execution engine
│   ├── nodes/             # Built-in node types
│   ├── storage/           # Database layer
│   └── config/            # Configuration management
├── pkg/                   # Public libraries
│   ├── logger/            # Structured logging
│   ├── metrics/           # Prometheus metrics
│   ├── errors/            # Error handling
│   ├── retry/             # Retry logic
│   ├── sandbox/           # Code execution sandbox
│   └── utils/             # Utility functions
├── deployments/           # Deployment configurations
│   ├── docker/            # Docker files
│   ├── k8s/               # Kubernetes manifests
│   └── helm/              # Helm charts
└── test/                  # Test files
    ├── e2e/               # End-to-end tests
    └── benchmarks/        # Performance tests
```

#### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests
make test-integration

# End-to-end tests
make test-e2e

# Benchmarks
make benchmark

# Coverage report
make test-coverage
```

#### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Security check
make security-check

# All checks
make check-all
```

## 🚀 Deployment

### Docker

Build and run with Docker:

```bash
# Build images
make docker-build

# Run with Docker Compose
make docker-run

# Push to registry
make docker-push
```

### Kubernetes

Deploy to Kubernetes:

```bash
# Apply manifests
make k8s-deploy

# Check status
make k8s-status

# Remove deployment
make k8s-delete
```

### Helm

Install with Helm:

```bash
# Install
make helm-install

# Upgrade
make helm-upgrade

# Uninstall
make helm-uninstall
```

### Production Checklist

- [ ] Configure external PostgreSQL database
- [ ] Set up Redis cluster for high availability
- [ ] Configure Kafka cluster
- [ ] Set up SSL/TLS certificates
- [ ] Configure authentication (OAuth2/OIDC)
- [ ] Set up monitoring (Prometheus + Grafana)
- [ ] Configure log aggregation (ELK/EFK stack)
- [ ] Set up backup and disaster recovery
- [ ] Configure resource limits and scaling policies
- [ ] Enable audit logging
- [ ] Set up alerting rules

## 🔧 Operations

### Admin CLI

The admin CLI provides operational commands:

```bash
# System health
./build/admin system health

# List workflows
./build/admin workflow list --team-id=uuid

# Database migrations
./build/admin migrate up

# User management
./build/admin user create --email=admin@example.com --name="Admin User"

# Cleanup old executions
./build/admin cleanup executions --before=2024-01-01
```

### Monitoring

Access monitoring dashboards:

- **Metrics**: http://localhost:9090/metrics (Prometheus format)
- **Health Checks**: http://localhost:8080/health
- **Worker Health**: http://localhost:8082/health

Key metrics to monitor:

- `n8n_pro_workflow_executions_total` - Total workflow executions
- `n8n_pro_workflow_execution_duration_seconds` - Execution duration
- `n8n_pro_http_requests_total` - HTTP request count
- `n8n_pro_db_connections_open` - Database connections
- `n8n_pro_queue_depth` - Message queue depth

### Logging

Structured JSON logging with configurable levels:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "service": "api",
  "message": "Workflow executed successfully",
  "workflow_id": "uuid",
  "execution_id": "uuid",
  "duration_ms": 1234
}
```

## 🧪 Testing

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test service interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Benchmark execution performance

### Sample Test Data

Use the admin CLI to populate test data:

```bash
# Create sample workflows
./build/admin seed --workflows=10 --executions=100

# Create sample users and teams  
./build/admin seed --users=5 --teams=2
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes and add tests
4. Run quality checks (`make check-all`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Standards

- Follow Go conventions and idioms
- Write comprehensive tests (aim for >80% coverage)
- Document public APIs with godoc comments
- Use structured logging throughout
- Handle errors explicitly
- Follow the project's architecture patterns

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database status
   make db-up
   
   # Test connection
   ./build/admin system health
   ```

2. **Kafka Connection Issues**
   ```bash
   # Restart Kafka
   docker-compose restart kafka
   
   # Check topics
   docker-compose exec kafka kafka-topics --list --bootstrap-server localhost:9092
   ```

3. **Memory Issues**
   ```bash
   # Increase worker memory limits in .env
   SANDBOX_MAX_MEMORY_MB=256
   LIMITS_MAX_EXECUTION_TIME=15m
   ```

4. **Permission Issues**
   ```bash
   # Check file permissions
   sudo chown -R $USER:$USER ./storage
   chmod -R 755 ./storage
   ```

### Debug Mode

Enable debug logging:

```bash
export DEBUG=true
export LOG_LEVEL=debug
./build/api
```

### Getting Help

- 📖 [Documentation](https://docs.n8n-pro.com)
- 💬 [Community Forum](https://community.n8n-pro.com)
- 🐛 [Issue Tracker](https://github.com/your-org/n8n-pro/issues)
- 📧 [Support Email](mailto:support@n8n-pro.com)

## 📊 Performance

### Benchmarks

| Metric | Value | Notes |
|--------|-------|--------|
| **Workflow Executions/sec** | 1,000+ | With horizontal scaling |
| **API Requests/sec** | 10,000+ | Cached responses |
| **Average Execution Time** | <200ms | Simple workflows |
| **Memory Usage** | 128MB | Per worker instance |
| **Startup Time** | <10s | Cold start |

### Scaling Guidelines

- **API Service**: Scale based on HTTP request volume
- **Worker Service**: Scale based on workflow execution queue depth
- **Database**: Use read replicas for heavy read workloads
- **Redis**: Use cluster mode for high availability
- **Kafka**: Scale partitions based on message throughput

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the original [n8n](https://n8n.io) project
- Built with amazing Go libraries and tools
- Special thanks to all contributors

---

**n8n Pro** - Empowering businesses with intelligent workflow automation.

For more information, visit [https://n8n-pro.com](https://n8n-pro.com)