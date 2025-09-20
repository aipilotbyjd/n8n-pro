# =============================================================================
# n8n Pro Makefile
# =============================================================================

# Project variables
PROJECT_NAME := n8n-pro
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')

# Build variables
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"
BUILD_DIR := ./build
DIST_DIR := ./dist
DOCKER_REGISTRY := your-registry.com
DOCKER_TAG := $(VERSION)

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Service binaries
SERVICES := api worker scheduler webhook admin
API_BINARY := $(BUILD_DIR)/api
WORKER_BINARY := $(BUILD_DIR)/worker
SCHEDULER_BINARY := $(BUILD_DIR)/scheduler
WEBHOOK_BINARY := $(BUILD_DIR)/webhook
ADMIN_BINARY := $(BUILD_DIR)/admin

# Docker compose files
COMPOSE_FILE := docker-compose.yml
COMPOSE_DEV_FILE := docker-compose.yml

# Database
DB_NAME := n8n_clone
DB_USER := user
DB_PASSWORD := password
DB_HOST := localhost
DB_PORT := 5432
MIGRATIONS_DIR := ./migrations

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
PURPLE := \033[35m
CYAN := \033[36m
WHITE := \033[37m
RESET := \033[0m

# Help target
.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)n8n Pro - Development Commands$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

# =============================================================================
# Build Targets
# =============================================================================

.PHONY: build
build: build-all ## Build all services

.PHONY: build-all
build-all: $(API_BINARY) $(WORKER_BINARY) $(SCHEDULER_BINARY) $(WEBHOOK_BINARY) $(ADMIN_BINARY) ## Build all service binaries

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(API_BINARY): $(BUILD_DIR) ## Build API service
	@echo "$(BLUE)Building API service...$(RESET)"
	$(GOBUILD) $(LDFLAGS) -o $(API_BINARY) ./cmd/api

$(WORKER_BINARY): $(BUILD_DIR) ## Build Worker service
	@echo "$(BLUE)Building Worker service...$(RESET)"
	$(GOBUILD) $(LDFLAGS) -o $(WORKER_BINARY) ./cmd/worker

$(SCHEDULER_BINARY): $(BUILD_DIR) ## Build Scheduler service
	@echo "$(BLUE)Building Scheduler service...$(RESET)"
	$(GOBUILD) $(LDFLAGS) -o $(SCHEDULER_BINARY) ./cmd/scheduler

$(WEBHOOK_BINARY): $(BUILD_DIR) ## Build Webhook service
	@echo "$(BLUE)Building Webhook service...$(RESET)"
	$(GOBUILD) $(LDFLAGS) -o $(WEBHOOK_BINARY) ./cmd/webhook

$(ADMIN_BINARY): $(BUILD_DIR) ## Build Admin CLI
	@echo "$(BLUE)Building Admin CLI...$(RESET)"
	$(GOBUILD) $(LDFLAGS) -o $(ADMIN_BINARY) ./cmd/admin

.PHONY: build-linux
build-linux: ## Build all binaries for Linux
	@echo "$(BLUE)Building for Linux...$(RESET)"
	@mkdir -p $(BUILD_DIR)/linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/api ./cmd/api
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/worker ./cmd/worker
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/scheduler ./cmd/scheduler
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/webhook ./cmd/webhook
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/admin ./cmd/admin

.PHONY: build-darwin
build-darwin: ## Build all binaries for macOS
	@echo "$(BLUE)Building for macOS...$(RESET)"
	@mkdir -p $(BUILD_DIR)/darwin
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/api ./cmd/api
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/worker ./cmd/worker
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/scheduler ./cmd/scheduler
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/webhook ./cmd/webhook
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/admin ./cmd/admin

.PHONY: build-windows
build-windows: ## Build all binaries for Windows
	@echo "$(BLUE)Building for Windows...$(RESET)"
	@mkdir -p $(BUILD_DIR)/windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/api.exe ./cmd/api
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/worker.exe ./cmd/worker
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/scheduler.exe ./cmd/scheduler
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/webhook.exe ./cmd/webhook
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/admin.exe ./cmd/admin

.PHONY: build-all-platforms
build-all-platforms: build-linux build-darwin build-windows ## Build for all platforms

# =============================================================================
# Development Targets
# =============================================================================

.PHONY: dev
dev: deps ## Start development environment
	@echo "$(GREEN)Starting development environment...$(RESET)"
	docker-compose -f $(COMPOSE_DEV_FILE) up -d
	@echo "$(GREEN)Services started. API available at http://localhost:8080$(RESET)"

.PHONY: dev-down
dev-down: ## Stop development environment
	@echo "$(YELLOW)Stopping development environment...$(RESET)"
	docker-compose -f $(COMPOSE_DEV_FILE) down

.PHONY: run-api
run-api: $(API_BINARY) ## Run API service locally
	@echo "$(GREEN)Starting API service...$(RESET)"
	./$(API_BINARY)

.PHONY: run-worker
run-worker: $(WORKER_BINARY) ## Run Worker service locally
	@echo "$(GREEN)Starting Worker service...$(RESET)"
	./$(WORKER_BINARY)

.PHONY: run-scheduler
run-scheduler: $(SCHEDULER_BINARY) ## Run Scheduler service locally
	@echo "$(GREEN)Starting Scheduler service...$(RESET)"
	./$(SCHEDULER_BINARY)

.PHONY: run-webhook
run-webhook: $(WEBHOOK_BINARY) ## Run Webhook service locally
	@echo "$(GREEN)Starting Webhook service...$(RESET)"
	./$(WEBHOOK_BINARY)

.PHONY: watch
watch: ## Watch for changes and rebuild
	@echo "$(GREEN)Watching for changes...$(RESET)"
	@which air > /dev/null || (echo "$(RED)Installing air...$(RESET)" && go install github.com/cosmtrek/air@latest)
	air

# =============================================================================
# Testing Targets
# =============================================================================

.PHONY: test
test: ## Run all tests
	@echo "$(GREEN)Running tests...$(RESET)"
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(RESET)"
	$(GOTEST) -v -race -short ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(RESET)"
	$(GOTEST) -v -race -tags=integration ./test/...

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "$(GREEN)Running e2e tests...$(RESET)"
	$(GOTEST) -v -race -tags=e2e ./test/e2e/...

.PHONY: test-coverage
test-coverage: test ## Generate and view test coverage report
	@echo "$(GREEN)Generating coverage report...$(RESET)"
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(RESET)"

.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "$(GREEN)Running benchmarks...$(RESET)"
	$(GOTEST) -bench=. -benchmem ./test/benchmarks/...

# =============================================================================
# Code Quality Targets
# =============================================================================

.PHONY: lint
lint: ## Run linter
	@echo "$(GREEN)Running linter...$(RESET)"
	@which golangci-lint > /dev/null || (echo "$(RED)Installing golangci-lint...$(RESET)" && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

.PHONY: fmt
fmt: ## Format Go code
	@echo "$(GREEN)Formatting code...$(RESET)"
	$(GOFMT) -s -w .

.PHONY: fmt-check
fmt-check: ## Check if code is formatted
	@echo "$(GREEN)Checking code formatting...$(RESET)"
	@test -z "$(shell $(GOFMT) -l .)" || (echo "$(RED)Code is not formatted. Run 'make fmt'$(RESET)" && exit 1)

.PHONY: vet
vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(RESET)"
	$(GOCMD) vet ./...

.PHONY: security-check
security-check: ## Run security checks
	@echo "$(GREEN)Running security checks...$(RESET)"
	@which gosec > /dev/null || (echo "$(RED)Installing gosec...$(RESET)" && go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)
	gosec ./...

.PHONY: check-all
check-all: fmt-check vet lint security-check test ## Run all code quality checks

# =============================================================================
# Database Targets
# =============================================================================

.PHONY: db-up
db-up: ## Start database
	@echo "$(GREEN)Starting database...$(RESET)"
	docker-compose up -d postgres redis

.PHONY: db-down
db-down: ## Stop database
	@echo "$(YELLOW)Stopping database...$(RESET)"
	docker-compose stop postgres redis

.PHONY: db-migrate
db-migrate: $(ADMIN_BINARY) ## Run database migrations
	@echo "$(GREEN)Running database migrations...$(RESET)"
	./$(ADMIN_BINARY) migrate up

.PHONY: db-migrate-down
db-migrate-down: $(ADMIN_BINARY) ## Rollback database migrations
	@echo "$(YELLOW)Rolling back database migrations...$(RESET)"
	./$(ADMIN_BINARY) migrate down

.PHONY: db-seed
db-seed: $(ADMIN_BINARY) ## Seed database with test data
	@echo "$(GREEN)Seeding database...$(RESET)"
	./$(ADMIN_BINARY) seed

.PHONY: db-reset
db-reset: db-migrate-down db-migrate db-seed ## Reset database (migrate down, up, and seed)

.PHONY: db-shell
db-shell: ## Connect to database shell
	@echo "$(GREEN)Connecting to database...$(RESET)"
	docker-compose exec postgres psql -U $(DB_USER) -d $(DB_NAME)

# =============================================================================
# Docker Targets
# =============================================================================

.PHONY: docker-build
docker-build: ## Build Docker images for all services
	@echo "$(GREEN)Building Docker images...$(RESET)"
	docker build -f deployments/docker/Dockerfile.api -t $(PROJECT_NAME)/api:$(DOCKER_TAG) .
	docker build -f deployments/docker/Dockerfile.worker -t $(PROJECT_NAME)/worker:$(DOCKER_TAG) .
	docker build -f deployments/docker/Dockerfile.scheduler -t $(PROJECT_NAME)/scheduler:$(DOCKER_TAG) .
	docker build -f deployments/docker/Dockerfile.webhook -t $(PROJECT_NAME)/webhook:$(DOCKER_TAG) .

.PHONY: docker-build-api
docker-build-api: ## Build Docker image for API service
	@echo "$(GREEN)Building API Docker image...$(RESET)"
	docker build -f deployments/docker/Dockerfile.api -t $(PROJECT_NAME)/api:$(DOCKER_TAG) .

.PHONY: docker-build-worker
docker-build-worker: ## Build Docker image for Worker service
	@echo "$(GREEN)Building Worker Docker image...$(RESET)"
	docker build -f deployments/docker/Dockerfile.worker -t $(PROJECT_NAME)/worker:$(DOCKER_TAG) .

.PHONY: docker-build-scheduler
docker-build-scheduler: ## Build Docker image for Scheduler service
	@echo "$(GREEN)Building Scheduler Docker image...$(RESET)"
	docker build -f deployments/docker/Dockerfile.scheduler -t $(PROJECT_NAME)/scheduler:$(DOCKER_TAG) .

.PHONY: docker-build-webhook
docker-build-webhook: ## Build Docker image for Webhook service
	@echo "$(GREEN)Building Webhook Docker image...$(RESET)"
	docker build -f deployments/docker/Dockerfile.webhook -t $(PROJECT_NAME)/webhook:$(DOCKER_TAG) .

.PHONY: docker-push
docker-push: docker-build ## Push Docker images to registry
	@echo "$(GREEN)Pushing Docker images...$(RESET)"
	docker tag $(PROJECT_NAME)/api:$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(PROJECT_NAME)/api:$(DOCKER_TAG)
	docker tag $(PROJECT_NAME)/worker:$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(PROJECT_NAME)/worker:$(DOCKER_TAG)
	docker tag $(PROJECT_NAME)/scheduler:$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(PROJECT_NAME)/scheduler:$(DOCKER_TAG)
	docker tag $(PROJECT_NAME)/webhook:$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(PROJECT_NAME)/webhook:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/api:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/worker:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/scheduler:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(PROJECT_NAME)/webhook:$(DOCKER_TAG)

.PHONY: docker-run
docker-run: ## Run services using Docker Compose
	@echo "$(GREEN)Starting services with Docker Compose...$(RESET)"
	docker-compose up -d

.PHONY: docker-stop
docker-stop: ## Stop Docker Compose services
	@echo "$(YELLOW)Stopping Docker Compose services...$(RESET)"
	docker-compose down

.PHONY: docker-logs
docker-logs: ## View Docker Compose logs
	docker-compose logs -f

# =============================================================================
# Dependencies and Tools
# =============================================================================

.PHONY: deps
deps: ## Install dependencies
	@echo "$(GREEN)Installing dependencies...$(RESET)"
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "$(GREEN)Updating dependencies...$(RESET)"
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

.PHONY: deps-verify
deps-verify: ## Verify dependencies
	@echo "$(GREEN)Verifying dependencies...$(RESET)"
	$(GOMOD) verify

.PHONY: tools-install
tools-install: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(RESET)"
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# =============================================================================
# Release and Distribution
# =============================================================================

.PHONY: release
release: clean build-all-platforms ## Build release for all platforms
	@echo "$(GREEN)Creating release packages...$(RESET)"
	@mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR)/linux .
	tar -czf $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR)/darwin .
	zip -r $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION)-windows-amd64.zip $(BUILD_DIR)/windows/
	@echo "$(GREEN)Release packages created in $(DIST_DIR)$(RESET)"

.PHONY: changelog
changelog: ## Generate changelog
	@echo "$(GREEN)Generating changelog...$(RESET)"
	@which git-chglog > /dev/null || (echo "$(RED)Installing git-chglog...$(RESET)" && go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest)
	git-chglog -o CHANGELOG.md

# =============================================================================
# Kubernetes Deployment
# =============================================================================

.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "$(GREEN)Deploying to Kubernetes...$(RESET)"
	kubectl apply -f deployments/k8s/

.PHONY: k8s-delete
k8s-delete: ## Delete from Kubernetes
	@echo "$(YELLOW)Deleting from Kubernetes...$(RESET)"
	kubectl delete -f deployments/k8s/

.PHONY: k8s-status
k8s-status: ## Check Kubernetes deployment status
	@echo "$(GREEN)Checking Kubernetes status...$(RESET)"
	kubectl get pods,services,deployments -l app=$(PROJECT_NAME)

.PHONY: helm-install
helm-install: ## Install using Helm
	@echo "$(GREEN)Installing with Helm...$(RESET)"
	helm install $(PROJECT_NAME) deployments/helm/$(PROJECT_NAME)

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade using Helm
	@echo "$(GREEN)Upgrading with Helm...$(RESET)"
	helm upgrade $(PROJECT_NAME) deployments/helm/$(PROJECT_NAME)

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall using Helm
	@echo "$(YELLOW)Uninstalling with Helm...$(RESET)"
	helm uninstall $(PROJECT_NAME)

# =============================================================================
# Monitoring and Debugging
# =============================================================================

.PHONY: logs
logs: ## View application logs
	@echo "$(GREEN)Viewing logs...$(RESET)"
	docker-compose logs -f api worker scheduler webhook

.PHONY: logs-api
logs-api: ## View API service logs
	docker-compose logs -f api

.PHONY: logs-worker
logs-worker: ## View Worker service logs
	docker-compose logs -f worker

.PHONY: logs-scheduler
logs-scheduler: ## View Scheduler service logs
	docker-compose logs -f scheduler

.PHONY: logs-webhook
logs-webhook: ## View Webhook service logs
	docker-compose logs -f webhook

.PHONY: metrics
metrics: ## Open metrics dashboard
	@echo "$(GREEN)Opening metrics dashboard...$(RESET)"
	@open http://localhost:9090 || xdg-open http://localhost:9090

.PHONY: health-check
health-check: ## Check service health
	@echo "$(GREEN)Checking service health...$(RESET)"
	@curl -s http://localhost:8080/health || echo "$(RED)API service not responding$(RESET)"
	@curl -s http://localhost:8081/health || echo "$(RED)Webhook service not responding$(RESET)"
	@curl -s http://localhost:8082/health || echo "$(RED)Worker service not responding$(RESET)"

# =============================================================================
# Cleanup Targets
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

.PHONY: clean-docker
clean-docker: ## Clean Docker images and containers
	@echo "$(YELLOW)Cleaning Docker images and containers...$(RESET)"
	docker system prune -f
	docker image prune -f

.PHONY: clean-all
clean-all: clean clean-docker ## Clean everything

# =============================================================================
# Utility Targets
# =============================================================================

.PHONY: version
version: ## Show version information
	@echo "$(CYAN)Version Information:$(RESET)"
	@echo "  Project: $(PROJECT_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Go Version: $(GO_VERSION)"

.PHONY: env
env: ## Show environment information
	@echo "$(CYAN)Environment Information:$(RESET)"
	@echo "  GOOS: $(shell go env GOOS)"
	@echo "  GOARCH: $(shell go env GOARCH)"
	@echo "  GOVERSION: $(shell go env GOVERSION)"
	@echo "  GOPATH: $(shell go env GOPATH)"
	@echo "  GOROOT: $(shell go env GOROOT)"

.PHONY: size
size: build-all ## Show binary sizes
	@echo "$(CYAN)Binary Sizes:$(RESET)"
	@ls -lh $(BUILD_DIR)/* | awk '{print "  " $$9 ": " $$5}'

# Default target
.DEFAULT_GOAL := help
