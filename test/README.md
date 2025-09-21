# Test Suite for n8n Pro

This directory contains comprehensive tests for the n8n Pro workflow automation system, designed to ensure reliability, performance, and maintainability of your n8n clone.

## Test Structure

### 📁 Test Organization

```
test/
├── api_test.go                          # Basic API integration tests
├── e2e/
│   └── e2e_test.go                      # End-to-end system tests
├── benchmarks/
│   └── workflow_benchmark_test.go       # Performance benchmarks
└── integration/
    └── integration_test.go              # Integration tests

internal/
├── testutils/
│   ├── testutils.go                    # Test utilities and helpers
│   └── mocks.go                        # Mock implementations
├── workflows/
│   ├── models_test.go                  # Unit tests for models
│   └── service_test.go                 # Unit tests for services
├── auth/
│   └── service_test.go                 # Authentication tests
├── api/handlers/
│   └── workflows_test.go               # API handler tests
├── execution/runner/
│   └── runner_test.go                  # Execution engine tests
└── pkg/errors/
    └── errors_test.go                  # Error handling tests
```

## Test Categories

### 🧪 Unit Tests
**Location**: `internal/*/` directories  
**Purpose**: Test individual components in isolation  
**Coverage**: Models, services, handlers, utilities  

Key test files:
- `internal/workflows/models_test.go` - Workflow model validation
- `internal/workflows/service_test.go` - Business logic testing
- `internal/auth/service_test.go` - Authentication logic
- `internal/api/handlers/workflows_test.go` - HTTP handlers
- `pkg/errors/errors_test.go` - Error handling system

### 🔗 Integration Tests
**Location**: `test/integration/`  
**Purpose**: Test component interactions  
**Coverage**: End-to-end workflows, database operations, API flows  

Features tested:
- Complete workflow lifecycle
- Node execution flows
- Error propagation
- Concurrent operations
- Database persistence patterns

### 🚀 Performance Tests
**Location**: `test/benchmarks/`  
**Purpose**: Measure and validate performance characteristics  
**Coverage**: Workflow operations, memory usage, concurrency  

Benchmarks include:
- Workflow creation and validation
- Node operations (add, retrieve, remove)
- JSON serialization/deserialization
- Concurrent operations
- Large workflow handling

### 🌐 End-to-End Tests
**Location**: `test/e2e/`  
**Purpose**: Full system integration testing  
**Coverage**: HTTP API, authentication, complete user flows  

## Running Tests

### Run All Tests
```bash
go test ./...
```

### Run Specific Test Categories

**Unit Tests Only**
```bash
go test ./internal/...
```

**Integration Tests**
```bash
go test ./test/integration/...
```

**Performance Benchmarks**
```bash
go test -bench=. ./test/benchmarks/...
```

**End-to-End Tests**
```bash
go test ./test/e2e/...
```

### Test with Coverage
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Run Tests in Short Mode (Skip slow tests)
```bash
go test -short ./...
```

## Test Utilities

### 🛠️ TestUtils Package
**Location**: `internal/testutils/`

Provides:
- **Test Data Creation**: `CreateTestUser()`, `CreateTestWorkflow()`, `CreateComplexTestWorkflow()`
- **Validation Helpers**: `ValidateWorkflowStructure()`, `AssertWorkflowEqual()`
- **HTTP Testing**: `CreateTestHTTPRequest()`
- **Error Testing**: `AssertError()`, `CreateTestError()`
- **Mock Time**: `MockTime` for time-dependent tests

### 🎭 Mocks Package
**Location**: `internal/testutils/mocks.go`

Mock implementations for:
- `MockWorkflowRepository` - Database operations
- `MockValidator` - Workflow validation
- `MockExecutor` - Workflow execution
- `MockAuthRepository` - User management
- `MockLogger` - Logging operations
- `TestWorkflowExecutor` - Configurable test executor

## Test Patterns

### 🏗️ Test Structure Pattern
```go
func TestFeatureName(t *testing.T) {
    t.Run("successful case", func(t *testing.T) {
        // Setup
        // Execute
        // Assert
    })
    
    t.Run("error case", func(t *testing.T) {
        // Setup with error conditions
        // Execute
        // Assert error handling
    })
}
```

### 🧪 Suite-Based Testing
```go
type FeatureTestSuite struct {
    suite.Suite
    // Test fixtures
}

func (suite *FeatureTestSuite) SetupTest() {
    // Setup before each test
}

func (suite *FeatureTestSuite) TestFeature() {
    // Test implementation
}

func TestFeatureSuite(t *testing.T) {
    suite.Run(t, new(FeatureTestSuite))
}
```

### 📊 Benchmark Pattern
```go
func BenchmarkOperation(b *testing.B) {
    // Setup
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        // Operation to benchmark
    }
}
```

## Test Coverage Goals

| Component | Target Coverage | Current Status |
|-----------|----------------|----------------|
| Models | 95%+ | ✅ Comprehensive |
| Services | 90%+ | ✅ Well covered |
| Handlers | 85%+ | ✅ Good coverage |
| Utilities | 90%+ | ✅ Well tested |
| Integration | 80%+ | ✅ Key flows covered |

## Testing Best Practices

### ✅ Do's
- **Use descriptive test names** that explain the scenario
- **Test both success and failure paths**
- **Use test utilities** for consistent test data
- **Mock external dependencies** for unit tests
- **Test edge cases** and boundary conditions
- **Use table-driven tests** for multiple input scenarios
- **Keep tests independent** and idempotent

### ❌ Don'ts
- **Don't test implementation details** - focus on behavior
- **Don't use production data** in tests
- **Don't skip cleanup** in test teardown
- **Don't make tests dependent** on external services
- **Don't ignore flaky tests** - fix them
- **Don't write overly complex tests** - keep them simple

## Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-go@v2
      with:
        go-version: 1.23
    - run: go test -race -coverprofile=coverage.out ./...
    - run: go tool cover -func=coverage.out
```

### Test Commands for CI
```bash
# Full test suite with race detection
go test -race ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...

# Check coverage threshold
go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 80) exit 1}'
```

## Performance Testing

### Benchmark Targets
- **Workflow Creation**: < 1ms per workflow
- **Workflow Validation**: < 100μs for complex workflows
- **Node Operations**: < 10μs per operation
- **JSON Serialization**: < 500μs for large workflows

### Memory Targets
- **Small Workflow** (< 10 nodes): < 50KB
- **Medium Workflow** (< 100 nodes): < 500KB
- **Large Workflow** (< 1000 nodes): < 5MB

## Troubleshooting Tests

### Common Issues

**Tests fail with "no such file or directory"**
```bash
# Ensure you're in the project root
cd /path/to/n8n-pro
go test ./...
```

**Mock assertions fail**
```bash
# Check mock setup and expectations
# Ensure all expected calls are made
# Verify mock cleanup in teardown
```

**Race conditions in tests**
```bash
# Run with race detection
go test -race ./...
```

**Slow tests**
```bash
# Use short mode to skip slow tests
go test -short ./...

# Profile tests to find bottlenecks
go test -cpuprofile=cpu.prof ./...
```

## Contributing to Tests

### Adding New Tests
1. **Identify the component** being tested
2. **Choose appropriate test type** (unit/integration/e2e)
3. **Use existing patterns** and utilities
4. **Add both positive and negative test cases**
5. **Update documentation** if needed

### Test Review Checklist
- [ ] Tests cover both success and failure scenarios
- [ ] Mock dependencies are properly configured
- [ ] Test data is realistic but not production data
- [ ] Tests are independent and can run in any order
- [ ] Performance impact is considered
- [ ] Documentation is updated if needed

## Monitoring and Reports

### Coverage Reports
Generate detailed coverage reports:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Performance Monitoring
Track benchmark results over time:
```bash
go test -bench=. -benchmem ./test/benchmarks/ > bench.txt
```

## Support

For questions about the test suite:
1. Check this documentation
2. Review existing test patterns
3. Look at similar components' tests
4. Consult the main project documentation

Remember: **Good tests are the foundation of reliable software!** 🧪✨