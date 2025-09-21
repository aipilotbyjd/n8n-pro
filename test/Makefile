# Test Management Makefile for n8n Pro

.PHONY: test test-unit test-integration test-e2e test-benchmarks test-coverage test-race test-short help clean

# Default target
help:
	@echo "Available test commands:"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests"
	@echo "  test-e2e          - Run end-to-end tests"
	@echo "  test-benchmarks   - Run performance benchmarks"
	@echo "  test-coverage     - Run tests with coverage report"
	@echo "  test-race         - Run tests with race detection"
	@echo "  test-short        - Run tests in short mode (skip slow tests)"
	@echo "  test-clean        - Clean test artifacts"

# Run all tests
test:
	@echo "🧪 Running all tests..."
	go test ./...

# Run unit tests only
test-unit:
	@echo "🔬 Running unit tests..."
	go test ./internal/... ./pkg/...

# Run integration tests
test-integration:
	@echo "🔗 Running integration tests..."
	go test ./test/integration/...

# Run end-to-end tests
test-e2e:
	@echo "🌐 Running end-to-end tests..."
	go test ./test/e2e/...

# Run performance benchmarks
test-benchmarks:
	@echo "🚀 Running performance benchmarks..."
	go test -bench=. -benchmem ./test/benchmarks/...

# Run tests with coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out
	@echo "📈 Coverage report generated: coverage.html"

# Run tests with race detection
test-race:
	@echo "🏃 Running tests with race detection..."
	go test -race ./...

# Run tests in short mode
test-short:
	@echo "⚡ Running tests in short mode..."
	go test -short ./...

# Clean test artifacts
test-clean:
	@echo "🧹 Cleaning test artifacts..."
	rm -f coverage.out coverage.html
	rm -f *.prof
	rm -f test/*.log

# Verbose test run
test-verbose:
	@echo "📝 Running tests with verbose output..."
	go test -v ./...

# Test with CPU profiling
test-profile:
	@echo "🔍 Running tests with CPU profiling..."
	go test -cpuprofile=cpu.prof ./...
	@echo "Profile saved to cpu.prof - analyze with: go tool pprof cpu.prof"

# Memory profiling
test-memprofile:
	@echo "💾 Running tests with memory profiling..."
	go test -memprofile=mem.prof ./...
	@echo "Memory profile saved to mem.prof - analyze with: go tool pprof mem.prof"

# Run specific test package
test-package:
	@if [ -z "$(PKG)" ]; then echo "Usage: make test-package PKG=package_path"; exit 1; fi
	@echo "🎯 Running tests for package: $(PKG)"
	go test ./$(PKG)/...

# Run specific test function
test-func:
	@if [ -z "$(FUNC)" ]; then echo "Usage: make test-func FUNC=TestFunctionName [PKG=package_path]"; exit 1; fi
	@echo "🎯 Running test function: $(FUNC)"
	@if [ -n "$(PKG)" ]; then \
		go test -run $(FUNC) ./$(PKG)/...; \
	else \
		go test -run $(FUNC) ./...; \
	fi

# Test with timeout
test-timeout:
	@echo "⏰ Running tests with 30s timeout..."
	go test -timeout 30s ./...

# Continuous testing (requires fswatch or inotify-tools)
test-watch:
	@echo "👀 Watching for changes and running tests..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make test-unit; \
	elif command -v inotifywait >/dev/null 2>&1; then \
		while inotifywait -r -e modify .; do make test-unit; done; \
	else \
		echo "Please install fswatch (macOS) or inotify-tools (Linux) for watch functionality"; \
	fi

# Lint and test
lint-and-test:
	@echo "🔍 Running linter and tests..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping linting"; \
	fi
	make test

# Test summary with coverage threshold
test-summary:
	@echo "📋 Running comprehensive test summary..."
	@go test -coverprofile=coverage.out ./... 2>&1 | tee test-results.log
	@echo "\n📊 Coverage Summary:"
	@go tool cover -func=coverage.out | grep total
	@coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ $$(echo "$$coverage < 80" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage below 80% threshold ($$coverage%)"; \
		exit 1; \
	else \
		echo "✅ Coverage above 80% threshold ($$coverage%)"; \
	fi

# Test specific workflow functionality
test-workflows:
	@echo "⚙️ Testing workflow functionality..."
	go test -v ./internal/workflows/...

# Test API handlers
test-handlers:
	@echo "🌐 Testing API handlers..."
	go test -v ./internal/api/handlers/...

# Test authentication
test-auth:
	@echo "🔐 Testing authentication..."
	go test -v ./internal/auth/...

# Test errors
test-errors:
	@echo "❌ Testing error handling..."
	go test -v ./pkg/errors/...

# Generate test report
test-report:
	@echo "📄 Generating comprehensive test report..."
	@go test -json ./... > test-report.json
	@echo "Test report saved to test-report.json"

# Docker-based testing (if using containers)
test-docker:
	@echo "🐳 Running tests in Docker container..."
	docker run --rm -v $(PWD):/app -w /app golang:1.23 make test

# Security testing
test-security:
	@echo "🔒 Running security tests..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Parallel testing
test-parallel:
	@echo "⚡ Running tests in parallel..."
	go test -parallel 4 ./...

# Test with build tags
test-integration-tags:
	@echo "🏷️ Running integration tests with build tags..."
	go test -tags=integration ./...

# Database tests (if applicable)
test-db:
	@echo "🗄️ Running database tests..."
	@echo "Note: Ensure test database is available"
	go test -tags=database ./test/...

# Full CI pipeline simulation
test-ci:
	@echo "🔄 Running full CI pipeline simulation..."
	make test-clean
	make lint-and-test
	make test-race
	make test-coverage
	make test-benchmarks
	@echo "✅ CI pipeline simulation completed successfully!"

# Performance regression testing
test-perf-regression:
	@echo "📈 Running performance regression tests..."
	@if [ -f "benchmarks-baseline.txt" ]; then \
		go test -bench=. -benchmem ./test/benchmarks/ > benchmarks-current.txt; \
		echo "Compare benchmarks-baseline.txt with benchmarks-current.txt"; \
	else \
		echo "Creating baseline benchmarks..."; \
		go test -bench=. -benchmem ./test/benchmarks/ > benchmarks-baseline.txt; \
		echo "Baseline created in benchmarks-baseline.txt"; \
	fi

# Load testing endpoints
test-load:
	@echo "🔥 Running load tests..."
	@echo "Note: This requires a running server instance"
	@if command -v hey >/dev/null 2>&1; then \
		hey -n 1000 -c 10 http://localhost:8080/health; \
	else \
		echo "hey load testing tool not found. Install with: go install github.com/rakyll/hey@latest"; \
	fi

# Memory leak detection
test-memory-leaks:
	@echo "🔍 Running memory leak detection..."
	go test -memprofile=mem.prof -memprofilerate=1 ./...
	@echo "Analyze with: go tool pprof mem.prof"

# Fuzz testing (Go 1.18+)
test-fuzz:
	@echo "🎲 Running fuzz tests..."
	go test -fuzz=. -fuzztime=30s ./...

# Test coverage by package
test-coverage-by-package:
	@echo "📦 Generating coverage by package..."
	@for pkg in $$(go list ./...); do \
		echo "Testing $$pkg..."; \
		go test -coverprofile=/tmp/coverage.out $$pkg; \
		if [ -f /tmp/coverage.out ]; then \
			go tool cover -func=/tmp/coverage.out | tail -1; \
		fi; \
	done

# Mutation testing (if using go-mutesting)
test-mutation:
	@echo "🧬 Running mutation tests..."
	@if command -v go-mutesting >/dev/null 2>&1; then \
		go-mutesting ./...; \
	else \
		echo "go-mutesting not found. Install with: go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest"; \
	fi