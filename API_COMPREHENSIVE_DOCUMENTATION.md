# N8N Clone API - Comprehensive API Documentation

## 🚀 Overview

This n8n clone provides a complete workflow automation platform with REST APIs that match and extend n8n's functionality. The system is built with Go, PostgreSQL, and includes enterprise-grade features.

## 🏗️ Architecture

- **Language**: Go 1.23
- **Database**: PostgreSQL with migrations
- **Authentication**: JWT-based with refresh tokens
- **Message Queue**: Kafka for async processing
- **Metrics**: Prometheus integration
- **Security**: AES-GCM credential encryption
- **Execution**: Sandboxed code execution environment

## 📋 API Endpoints

### 🔧 System Health & Information

#### Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "service": "api", 
  "timestamp": "2023-01-01T00:00:00Z"
}
```

#### Version Information
```http
GET /version
```
**Response:**
```json
{
  "version": "1.0.0",
  "build_time": "2023-01-01T00:00:00Z",
  "git_commit": "abc123",
  "go_version": "go1.23"
}
```

### 🔐 Authentication System

#### User Registration
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com", 
  "password": "SecurePassword123!"
}
```

#### User Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```
**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 3600,
    "user": {
      "id": "user-123",
      "name": "John Doe",
      "email": "john@example.com",
      "role": "user",
      "team_id": "team-456"
    }
  }
}
```

#### Token Refresh
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### Password Reset
```http
POST /api/v1/auth/forgot-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

```http
POST /api/v1/auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-here",
  "new_password": "NewSecurePassword123!"
}
```

#### Email Verification
```http
POST /api/v1/auth/verify-email
Content-Type: application/json

{
  "token": "verification-token-here"
}
```

### 👤 User Profile Management

#### Get Current User Profile
```http
GET /api/v1/profile
Authorization: Bearer <access_token>
```

#### Update Profile
```http
PUT /api/v1/profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "John Updated",
  "preferences": {
    "theme": "dark",
    "language": "en",
    "timezone": "UTC"
  }
}
```

#### Send Verification Email
```http
POST /api/v1/profile/send-verification
Authorization: Bearer <access_token>
```

### 🔄 Workflow Management (Core n8n Functionality)

#### Create Workflow
```http
POST /api/v1/workflows
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "My Automation Workflow",
  "description": "Processes GitHub webhook data",
  "nodes": [
    {
      "id": "webhook-1",
      "type": "n8n-nodes-base.webhook",
      "name": "Webhook",
      "parameters": {
        "path": "github-webhook"
      },
      "position": [250, 300]
    },
    {
      "id": "http-1", 
      "type": "n8n-nodes-base.httpRequest",
      "name": "Send to Slack",
      "parameters": {
        "url": "https://hooks.slack.com/services/...",
        "method": "POST",
        "body": {
          "text": "New commit: {{$json[\"commits\"][0][\"message\"]}}"
        }
      },
      "position": [450, 300]
    }
  ],
  "connections": {
    "Webhook": {
      "main": [[{
        "node": "Send to Slack",
        "type": "main", 
        "index": 0
      }]]
    }
  },
  "tags": ["github", "slack", "automation"],
  "active": true,
  "config": {
    "timezone": "UTC",
    "save_execution_progress": true
  }
}
```

#### List Workflows
```http
GET /api/v1/workflows?limit=50&offset=0&active=true&tags=automation
Authorization: Bearer <access_token>
```

#### Get Workflow
```http
GET /api/v1/workflows/{id}
Authorization: Bearer <access_token>
```

#### Update Workflow  
```http
PUT /api/v1/workflows/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Updated Workflow Name",
  "active": false,
  "description": "Updated description"
}
```

#### Delete Workflow
```http
DELETE /api/v1/workflows/{id}
Authorization: Bearer <access_token>
```

#### Execute Workflow
```http
POST /api/v1/workflows/{id}/execute
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "input_data": {
    "test": true,
    "user_id": "123"
  },
  "mode": "manual"
}
```

### ⚡ Execution Management

#### List Executions
```http
GET /api/v1/executions?workflow_id={id}&status=success&limit=20
Authorization: Bearer <access_token>
```

#### Get Execution Details
```http
GET /api/v1/executions/{id}
Authorization: Bearer <access_token>
```

#### Cancel Execution
```http
DELETE /api/v1/executions/{id}/cancel  
Authorization: Bearer <access_token>
```

#### Retry Failed Execution
```http
POST /api/v1/executions/{id}/retry
Authorization: Bearer <access_token>
```

### 🔑 Credential Management

#### Create Credential
```http
POST /api/v1/credentials
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "GitHub API Token",
  "type": "githubApi",
  "data": {
    "accessToken": "ghp_xxxxxxxxxxxxxxxxxxxx"
  },
  "description": "GitHub API access for repository webhooks",
  "shared": false
}
```

#### List Credentials
```http
GET /api/v1/credentials?type=githubApi&shared=false
Authorization: Bearer <access_token>
```

#### Get Credential
```http
GET /api/v1/credentials/{id}
Authorization: Bearer <access_token>
```

#### Update Credential
```http
PUT /api/v1/credentials/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Updated GitHub Token",
  "description": "Updated description"
}
```

#### Test Credential
```http
POST /api/v1/credentials/{id}/test
Authorization: Bearer <access_token>
```

#### Get Decrypted Credential Data
```http
GET /api/v1/credentials/{id}/data
Authorization: Bearer <access_token>
```

#### Get Credential Types
```http
GET /api/v1/credentials/types
Authorization: Bearer <access_token>
```

#### Get Credential Statistics
```http
GET /api/v1/credentials/stats
Authorization: Bearer <access_token>
```

### 📊 Metrics & Monitoring

#### System Metrics
```http
GET /api/v1/metrics/system
Authorization: Bearer <access_token>
```
**Response:**
```json
{
  "success": true,
  "data": {
    "uptime": 3600,
    "memory_usage": 128000000,
    "cpu_usage": 15.5,
    "active_executions": 5,
    "total_workflows": 25,
    "database_connections": 10
  }
}
```

#### Workflow Metrics
```http
GET /api/v1/metrics/workflows/{workflowId}
Authorization: Bearer <access_token>
```

#### Team Metrics
```http
GET /api/v1/metrics/team
Authorization: Bearer <access_token>
```

#### Health Metrics
```http
GET /api/v1/metrics/health
Authorization: Bearer <access_token>
```

#### Prometheus Metrics
```http
GET /metrics
```
Returns Prometheus-formatted metrics for monitoring integration.

### 👥 Legacy User Endpoints

#### Get Current User (Legacy)
```http
GET /api/v1/users/me
Authorization: Bearer <access_token>
```

#### Update Current User (Legacy)
```http
PUT /api/v1/users/me
Authorization: Bearer <access_token>
```

#### Change Password
```http
POST /api/v1/users/me/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword123!"
}
```

#### Delete Account
```http
DELETE /api/v1/users/me
Authorization: Bearer <access_token>
```

## 🔧 Advanced Features

### Workflow Node Types Supported

1. **HTTP Request Node** (`n8n-nodes-base.httpRequest`)
   - GET, POST, PUT, DELETE, PATCH requests
   - Authentication support (Basic, Bearer, OAuth)
   - Custom headers and query parameters
   - JSON/XML/Form data support

2. **Slack Node** (`n8n-nodes-base.slack`)
   - Send messages to channels
   - Direct messages
   - File uploads
   - Interactive messages

3. **Google Sheets Node** (`n8n-nodes-base.googleSheets`)
   - Read/write spreadsheet data
   - Create sheets and workbooks
   - Batch operations

4. **Database Node** (`n8n-nodes-base.database`)
   - PostgreSQL, MySQL, SQLite support
   - Raw SQL queries
   - CRUD operations
   - Connection pooling

### Credential Types Supported

- `httpBasicAuth` - HTTP Basic Authentication
- `httpBearerAuth` - HTTP Bearer Token
- `oAuth2Api` - OAuth 2.0
- `githubApi` - GitHub API Token
- `slackApi` - Slack Bot Token
- `googleSheetsOAuth2Api` - Google Sheets OAuth
- `postgresDb` - PostgreSQL Database
- `mysqlDb` - MySQL Database

### Execution Modes

- **Manual**: Triggered by user action
- **Webhook**: Triggered by HTTP webhook
- **Schedule**: Triggered by cron schedule
- **API**: Triggered via API call

### Security Features

- **JWT Authentication**: Secure token-based auth
- **Credential Encryption**: AES-GCM encryption for sensitive data
- **Team Isolation**: Multi-tenant data separation
- **Rate Limiting**: API request throttling
- **CORS Support**: Cross-origin resource sharing
- **Input Validation**: Comprehensive request validation

### Performance Features

- **Connection Pooling**: Database connection management
- **Async Execution**: Background workflow processing
- **Metrics Collection**: Performance monitoring
- **Caching**: Redis-based response caching
- **Compression**: Gzip response compression

## 🚀 Getting Started

### Prerequisites
- Go 1.23+
- PostgreSQL 13+
- Docker (optional)

### Running the API

#### With Docker
```bash
docker-compose up -d
```

#### Manual Setup
```bash
# Set environment variables
export DB_HOST=localhost
export DB_PORT=5432  
export DB_NAME=n8n_clone
export DB_USER=user
export DB_PASSWORD=password
export JWT_SECRET=your-super-secret-jwt-key-32-chars-long

# Run the API server
go run cmd/api/main.go
```

### Testing the API

Run the comprehensive test script:
```bash
./test_api.sh
```

Or test individual endpoints:
```bash
# Health check
curl http://localhost:8080/health

# Register user
curl -X POST http://localhost:8080/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Test User","email":"test@example.com","password":"TestPass123!"}'
```

## 📈 Monitoring & Observability

- **Prometheus Metrics**: Available at `/metrics`
- **Health Checks**: Available at `/health`
- **Structured Logging**: JSON-formatted logs
- **Performance Metrics**: Request duration, error rates
- **Business Metrics**: Workflow executions, user activity

## 🔄 Migration & Deployment

The system includes comprehensive database migrations:
- User and team management
- Workflow definitions and executions
- Credential storage with encryption
- Webhook configurations
- Audit logging
- Performance indexes

## 🎯 Production Readiness

This n8n clone includes enterprise features:
- **High Availability**: Stateless design for horizontal scaling
- **Security**: Enterprise-grade encryption and authentication
- **Monitoring**: Full observability stack
- **Performance**: Optimized database queries and caching
- **Reliability**: Comprehensive error handling and retries

The API is fully compatible with n8n's workflow definitions and can serve as a drop-in replacement with additional enterprise features.