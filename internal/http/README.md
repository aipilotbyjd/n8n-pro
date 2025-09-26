# HTTP Server & API Layer

This directory contains the production-grade HTTP server implementation for the n8n-pro application.

## Architecture

The HTTP layer follows these design principles:

- **Layered Architecture**: Clear separation between HTTP concerns, business logic, and data access
- **Middleware Chain**: Composable middleware for cross-cutting concerns
- **Standardized Responses**: Consistent API response format across all endpoints
- **Error Handling**: Centralized error handling with proper HTTP status codes
- **Security**: Built-in security middleware and best practices
- **Observability**: Comprehensive logging, metrics, and health checks

## Structure

```
http/
├── server.go          # Main HTTP server implementation
├── response.go        # Response utilities and error handling
├── middleware/        # HTTP middleware collection
│   └── middleware.go  # Security, logging, metrics middleware
└── README.md         # This file
```

## Features

### 🔒 Security Middleware
- **Rate Limiting**: Token bucket algorithm with per-IP limiting
- **Security Headers**: HSTS, CSP, XSS protection, frame options
- **Request Size Limits**: Prevent large request attacks
- **CORS**: Configurable cross-origin resource sharing
- **Authentication**: JWT token validation (placeholder for implementation)

### 📊 Observability
- **Structured Logging**: Request/response logging with correlation IDs
- **Prometheus Metrics**: HTTP request metrics, duration, status codes
- **Health Checks**: Liveness, readiness, and general health endpoints
- **Request Tracing**: Request ID propagation for distributed tracing

### 🚀 Performance & Reliability
- **Graceful Shutdown**: Proper connection draining on shutdown
- **Timeouts**: Configurable request timeouts
- **Connection Limits**: HTTP server connection management
- **Panic Recovery**: Automatic panic recovery with logging

### 🔧 Development Features
- **Route Inspection**: Development endpoint to list all routes
- **Configuration Display**: Safe configuration viewing in development
- **Error Details**: Detailed error information in development mode

## API Response Format

All API responses follow a consistent format:

```json
{
  "success": true,
  "data": {
    "id": "12345",
    "name": "Example"
  },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  },
  "timestamp": "2023-12-01T12:00:00Z"
}
```

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "validation_errors": [
        {
          "field": "email",
          "message": "Invalid email format",
          "code": "INVALID_FORMAT"
        }
      ]
    }
  },
  "timestamp": "2023-12-01T12:00:00Z"
}
```

## Configuration

The HTTP server is configured through the main application configuration:

```yaml
api:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  max_request_size: 10485760  # 10MB
  enable_cors: true
  cors_allowed_origins:
    - "https://app.example.com"
  cors_allowed_methods:
    - "GET"
    - "POST"
    - "PUT" 
    - "DELETE"
  cors_allowed_headers:
    - "Authorization"
    - "Content-Type"
  enable_rate_limit: true
  rate_limit_requests: 1000
  rate_limit_window: 1h
  enable_gzip: true
  tls_enabled: false
```

## Middleware Chain

The middleware chain is applied in this order:

1. **Request ID** - Adds unique request identifier
2. **Real IP** - Extracts real client IP from proxy headers
3. **Logger** - Structured request/response logging
4. **Recoverer** - Panic recovery with logging
5. **Timeout** - Request timeout handling
6. **Security Headers** - Adds security headers
7. **CORS** - Cross-origin resource sharing
8. **Rate Limiting** - Request rate limiting
9. **Request Size Limit** - Body size validation
10. **Metrics** - Prometheus metrics collection
11. **Authentication** - JWT token validation (for API routes)

## Endpoints

### System Endpoints

- `GET /health` - General health check
- `GET /health/ready` - Readiness probe (dependencies check)
- `GET /health/live` - Liveness probe (basic availability)
- `GET /metrics` - Prometheus metrics (if enabled)

### Development Endpoints (development environment only)

- `GET /dev/routes` - Lists all registered routes
- `GET /dev/config` - Shows safe configuration (no secrets)

### API Endpoints

- `GET /api/v1/status` - API status check

## Usage Examples

### Basic Server Setup

```go
package main

import (
    "n8n-pro/internal/config"
    "n8n-pro/internal/http"
    "n8n-pro/pkg/logger"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        panic(err)
    }
    
    // Initialize logger
    log := logger.New("api")
    
    // Initialize services (empty for now)
    services := &http.Services{}
    
    // Create and start server
    server := http.NewServer(cfg, log, services)
    if err := server.Start(); err != nil {
        log.Fatal("Server failed to start", "error", err)
    }
}
```

### Custom Response Writing

```go
func handleExample(w http.ResponseWriter, r *http.Request) {
    // Success response
    http.WriteJSON(w, http.StatusOK, map[string]string{
        "message": "Hello, World!",
    })
    
    // Error response
    http.WriteError(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid request data")
    
    // Validation errors
    validationErrors := []http.ValidationError{
        http.CreateValidationError("email", "Invalid email format", "INVALID_FORMAT"),
    }
    http.WriteValidationErrors(w, validationErrors)
    
    // Paginated response
    data := []string{"item1", "item2", "item3"}
    meta := http.CreateMeta(1, 20, 100)
    http.WritePaginatedJSON(w, http.StatusOK, data, meta)
}
```

### Error Handling

```go
func handleWithErrorHandling(w http.ResponseWriter, r *http.Request) {
    errorHandler := http.NewErrorHandler(logger, cfg.Debug)
    
    // Your business logic here
    err := doSomething()
    if err != nil {
        errorHandler.HandleError(w, r, err)
        return
    }
    
    http.WriteJSON(w, http.StatusOK, result)
}
```

## Testing

The HTTP layer includes comprehensive testing utilities:

- Mock HTTP servers for testing
- Response validation helpers  
- Middleware testing utilities
- Error handling test cases

## Security Considerations

- All sensitive configuration is hidden from debug endpoints
- HTTPS is enforced in production environments
- Security headers are applied by default
- Rate limiting prevents abuse
- Request size limits prevent DoS attacks
- Panic recovery prevents crashes
- JWT tokens are validated for authenticated endpoints

## Performance

- Connection pooling for optimal resource usage
- Configurable timeouts prevent resource leaks
- Gzip compression reduces bandwidth
- Prometheus metrics for monitoring
- Graceful shutdown for zero-downtime deploys

## Integration

The HTTP layer integrates with:

- **Configuration System**: Environment-specific settings
- **Domain Layer**: Business logic and domain errors  
- **Logger**: Structured logging with correlation
- **Metrics**: Prometheus integration
- **Authentication**: JWT token validation
- **Authorization**: Role-based access control

This HTTP implementation provides a production-ready foundation for building scalable REST APIs with enterprise-grade features.