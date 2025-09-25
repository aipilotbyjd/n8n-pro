# n8n-Pro API Documentation

## Overview

n8n-Pro is a workflow automation platform with a comprehensive REST API. This documentation covers all available endpoints, request/response formats, and authentication requirements.

## Base URLs

- **Main API Server**: `http://localhost:8080/api/v1`
- **Webhook Server**: `http://localhost:8081`

## Authentication

Most endpoints require authentication using Bearer tokens. Include the token in the Authorization header:

```
Authorization: Bearer <access_token>
```

Access tokens are obtained through the login endpoint and expire after 1 hour. Use the refresh token to obtain new access tokens.

## Response Format

All API responses follow a standardized format:

### Success Response
```json
{
  "success": true,
  "data": { ... },
  "message": "Success message"
}
```

### Error Response
```json
{
  "success": false,
  "error": "error_type",
  "message": "Error description",
  "details": "Additional error details"
}
```

## HTTP Status Codes

- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `204 No Content` - Successful request with no response body
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required or invalid
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation errors
- `500 Internal Server Error` - Server error

---

## Authentication APIs

### Login

**POST** `/api/v1/auth/login`

Authenticate user and receive access tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user_123",
      "name": "John Doe",
      "email": "user@example.com",
      "role": "admin",
      "team_id": "team_456",
      "is_active": true
    }
  }
}
```

**Validation Rules:**
- `email`: Required, valid email format
- `password`: Required, minimum 6 characters

---

### Register

**POST** `/api/v1/auth/register`

Create a new user account.

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "user@example.com",
  "password": "securepassword123",
  "team_name": "My Team"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": "user_123",
    "email": "user@example.com",
    "name": "John Doe",
    "team_id": "team_456",
    "message": "User registered successfully"
  }
}
```

**Validation Rules:**
- `name`: Required, 2-100 characters
- `email`: Required, valid email format, must be unique
- `password`: Required, minimum 8 characters
- `team_name`: Optional

---

### Refresh Token

**POST** `/api/v1/auth/refresh`

Get new access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user_123",
      "name": "John Doe",
      "email": "user@example.com",
      "role": "admin",
      "team_id": "team_456",
      "is_active": true
    }
  }
}
```

---

### Logout

**POST** `/api/v1/auth/logout`

🔒 **Authentication Required**

Logout current user session.

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Logged out successfully"
  }
}
```

---

## Workflow APIs

### List Workflows

**GET** `/api/v1/workflows`

🔒 **Authentication Required**

Retrieve list of workflows with filtering and pagination.

**Query Parameters:**
- `status` (optional): Filter by workflow status (`draft`, `active`, `inactive`)
- `search` (optional): Search workflows by name or description
- `owner_id` (optional): Filter by workflow owner
- `is_template` (optional): Filter templates (`true`, `false`)
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 50, max: 1000)

**Example Request:**
```
GET /api/v1/workflows?status=active&page=1&page_size=20
```

**Response:**
```json
{
  "success": true,
  "data": {
    "workflows": [
      {
        "id": "workflow_123",
        "name": "Customer Onboarding",
        "description": "Automated customer onboarding process",
        "status": "active",
        "team_id": "team_456",
        "owner_id": "user_123",
        "version": 1,
        "is_template": false,
        "created_at": "2023-01-01T12:00:00Z",
        "updated_at": "2023-01-01T12:00:00Z",
        "nodes": [...],
        "connections": [...],
        "tags": [...],
        "config": {...}
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 20,
      "total": 150,
      "total_pages": 8
    }
  }
}
```

---

### Create Workflow

**POST** `/api/v1/workflows`

🔒 **Authentication Required**

Create a new workflow.

**Request Body:**
```json
{
  "name": "Customer Onboarding",
  "description": "Automated customer onboarding process",
  "nodes": [
    {
      "id": "node_1",
      "type": "webhook",
      "position": {"x": 100, "y": 100},
      "parameters": {...}
    }
  ],
  "connections": [
    {
      "from_node": "node_1",
      "from_output": "main",
      "to_node": "node_2",
      "to_input": "main"
    }
  ],
  "tags": [
    {"name": "onboarding", "color": "#ff0000"}
  ],
  "config": {
    "timeout": 300,
    "retry_attempts": 3
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "workflow_123",
    "name": "Customer Onboarding",
    "status": "draft",
    "team_id": "team_456",
    "owner_id": "user_123",
    "version": 1,
    "created_at": "2023-01-01T12:00:00Z",
    "updated_at": "2023-01-01T12:00:00Z"
  }
}
```

**Validation Rules:**
- `name`: Required, 1-255 characters
- `description`: Optional
- `nodes`: Array of workflow nodes
- `connections`: Array of node connections
- `tags`: Optional array of tags
- `config`: Optional workflow configuration

---

### Get Workflow

**GET** `/api/v1/workflows/{id}`

🔒 **Authentication Required**

Retrieve workflow details by ID.

**Path Parameters:**
- `id`: Workflow ID

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "workflow_123",
    "name": "Customer Onboarding",
    "description": "Automated customer onboarding process",
    "status": "active",
    "team_id": "team_456",
    "owner_id": "user_123",
    "version": 1,
    "is_template": false,
    "created_at": "2023-01-01T12:00:00Z",
    "updated_at": "2023-01-01T12:00:00Z",
    "nodes": [...],
    "connections": [...],
    "tags": [...],
    "config": {...}
  }
}
```

---

### Update Workflow

**PUT** `/api/v1/workflows/{id}`

🔒 **Authentication Required**

Update existing workflow.

**Path Parameters:**
- `id`: Workflow ID

**Request Body:**
```json
{
  "name": "Updated Customer Onboarding",
  "description": "Updated automated customer onboarding process",
  "nodes": [...],
  "connections": [...],
  "tags": [...],
  "config": {...},
  "status": "active"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "workflow_123",
    "name": "Updated Customer Onboarding",
    "status": "active",
    "version": 2,
    "updated_at": "2023-01-01T13:00:00Z"
  }
}
```

---

### Delete Workflow

**DELETE** `/api/v1/workflows/{id}`

🔒 **Authentication Required**

Delete workflow by ID.

**Path Parameters:**
- `id`: Workflow ID

**Response:**
- Status: `204 No Content`

---

### Execute Workflow

**POST** `/api/v1/workflows/{id}/execute`

🔒 **Authentication Required**

Manually execute a workflow.

**Path Parameters:**
- `id`: Workflow ID

**Request Body:**
```json
{
  "input_data": {
    "customer_email": "new.customer@example.com",
    "customer_name": "Jane Smith"
  },
  "mode": "manual"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "execution_id": "exec_123",
    "workflow_id": "workflow_123",
    "status": "running",
    "mode": "manual",
    "started_at": "2023-01-01T12:00:00Z",
    "message": "Workflow execution started successfully"
  }
}
```

---

## Execution APIs

### List Executions

**GET** `/api/v1/executions`

🔒 **Authentication Required**

Retrieve list of workflow executions.

**Query Parameters:**
- `workflow_id` (optional): Filter by workflow ID
- `status` (optional): Filter by status (`running`, `completed`, `failed`, `cancelled`)
- `mode` (optional): Filter by execution mode (`manual`, `webhook`, `schedule`)
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 50, max: 1000)

**Response:**
```json
{
  "success": true,
  "data": {
    "executions": [
      {
        "id": "exec_123",
        "workflow_id": "workflow_123",
        "status": "completed",
        "mode": "manual",
        "started_at": "2023-01-01T12:00:00Z",
        "finished_at": "2023-01-01T12:05:00Z",
        "duration": 300000,
        "input_data": {...},
        "output_data": {...}
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 50,
      "total": 100,
      "total_pages": 2
    }
  }
}
```

---

### Get Execution

**GET** `/api/v1/executions/{id}`

🔒 **Authentication Required**

Retrieve execution details by ID.

**Path Parameters:**
- `id`: Execution ID

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "exec_123",
    "workflow_id": "workflow_123",
    "status": "completed",
    "mode": "manual",
    "started_at": "2023-01-01T12:00:00Z",
    "finished_at": "2023-01-01T12:05:00Z",
    "duration": 300000,
    "input_data": {
      "customer_email": "new.customer@example.com"
    },
    "output_data": {
      "user_id": "user_456",
      "welcome_email_sent": true
    }
  }
}
```

---

### Cancel Execution

**DELETE** `/api/v1/executions/{id}/cancel`

🔒 **Authentication Required**

Cancel a running execution.

**Path Parameters:**
- `id`: Execution ID

**Response:**
```json
{
  "success": true,
  "data": {
    "execution_id": "exec_123",
    "status": "cancelled",
    "message": "Execution cancelled successfully"
  }
}
```

---

### Retry Execution

**POST** `/api/v1/executions/{id}/retry`

🔒 **Authentication Required**

Retry a failed execution.

**Path Parameters:**
- `id`: Execution ID

**Response:**
```json
{
  "success": true,
  "data": {
    "new_execution_id": "exec_456",
    "original_execution_id": "exec_123",
    "status": "running",
    "message": "Execution retry started successfully"
  }
}
```

---

## User Management APIs

### Get Current User

**GET** `/api/v1/users/me`

🔒 **Authentication Required**

Get current user profile information.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "name": "John Doe",
    "email": "user@example.com",
    "role": "admin",
    "team_id": "team_456",
    "is_active": true
  }
}
```

---

### Update Current User

**PUT** `/api/v1/users/me`

🔒 **Authentication Required**

Update current user profile.

**Request Body:**
```json
{
  "name": "John Smith",
  "email": "john.smith@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "name": "John Smith",
    "email": "john.smith@example.com",
    "role": "admin",
    "team_id": "team_456",
    "is_active": true
  }
}
```

**Validation Rules:**
- `name`: Optional, if provided must be non-empty
- `email`: Optional, if provided must be valid email format and unique

---

### Change Password

**POST** `/api/v1/users/me/change-password`

🔒 **Authentication Required**

Change user password.

**Request Body:**
```json
{
  "current_password": "oldpassword123",
  "new_password": "newpassword456"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Password changed successfully"
  }
}
```

**Validation Rules:**
- `current_password`: Required, must match existing password
- `new_password`: Required, minimum 8 characters

---

### Delete Account

**DELETE** `/api/v1/users/me`

🔒 **Authentication Required**

Deactivate user account.

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Account deactivated successfully"
  }
}
```

---

## Metrics APIs

### Get Workflow Metrics

**GET** `/api/v1/metrics/workflows/{workflowId}`

🔒 **Authentication Required**

Get metrics for a specific workflow.

**Path Parameters:**
- `workflowId`: Workflow ID

**Query Parameters:**
- `period` (optional): Time period (`1d`, `7d`, `30d`, `90d`, `1y`, `all`) (default: `30d`)

**Response:**
```json
{
  "success": true,
  "data": {
    "workflow_id": "workflow_123",
    "workflow_name": "Customer Onboarding",
    "total_executions": 1250,
    "successful_runs": 1187,
    "failed_runs": 63,
    "success_rate": 94.96,
    "average_runtime": 245000,
    "period": "30d"
  }
}
```

---

### Get Team Metrics

**GET** `/api/v1/metrics/team`

🔒 **Authentication Required**

Get metrics for the user's team.

**Query Parameters:**
- `period` (optional): Time period (`1d`, `7d`, `30d`, `90d`, `1y`, `all`) (default: `30d`)

**Response:**
```json
{
  "success": true,
  "data": {
    "team_id": "team_456",
    "total_workflows": 25,
    "active_workflows": 18,
    "total_executions": 5432,
    "successful_runs": 4987,
    "failed_runs": 445,
    "success_rate": 91.8,
    "average_runtime": 180.5,
    "executions_today": 127,
    "executions_this_week": 892,
    "executions_this_month": 3456,
    "top_workflows": [
      {
        "workflow_id": "workflow_123",
        "workflow_name": "Customer Onboarding",
        "executions": 1250,
        "success_rate": 94.96
      }
    ],
    "period": "30d"
  }
}
```

---

### Get System Metrics

**GET** `/api/v1/metrics/system`

🔒 **Authentication Required** (Admin Only)

Get system-wide metrics.

**Query Parameters:**
- `period` (optional): Time period (default: `1h`)
- `type` (optional): Metric type (default: `summary`)

**Response:**
```json
{
  "success": true,
  "data": {
    "system": {
      "status": "healthy",
      "uptime": "24h:30m:15s",
      "version": "1.0.0"
    },
    "performance": {
      "cpu_usage": "45%",
      "memory_usage": "68%",
      "disk_usage": "32%"
    },
    "api": {
      "requests_per_minute": 125,
      "avg_response_time": "245ms",
      "error_rate": "0.2%"
    },
    "workflows": {
      "active_executions": 23,
      "queued_executions": 5,
      "total_workflows": 156
    },
    "period": "1h",
    "type": "summary"
  }
}
```

---

### Get Health Metrics

**GET** `/api/v1/metrics/health`

🔒 **Authentication Optional** (Detailed metrics require admin)

Get system health information.

**Query Parameters:**
- `detailed` (optional): Get detailed metrics (`true`, `false`) - requires admin role

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2023-01-01T12:00:00Z",
    "version": "1.0.0",
    "checks": {
      "database": "healthy",
      "cache": "healthy",
      "queue": "healthy",
      "storage": "healthy"
    },
    "metrics": {
      "uptime": "24h:30m:15s",
      "requests_processed": 125430,
      "active_connections": 45,
      "memory_usage": "512MB"
    }
  }
}
```

---

## Webhook APIs

### Workflow Webhook

**POST** `/webhook/{workflowId}`

Trigger workflow execution via webhook.

**Path Parameters:**
- `workflowId`: Workflow ID

**Request Body:**
Any JSON payload that will be passed as input data to the workflow.

**Response:**
```json
{
  "success": true,
  "data": {
    "execution_id": "exec_789",
    "workflow_id": "workflow_123",
    "status": "running",
    "message": "Workflow execution started via webhook"
  }
}
```

---

### Node Webhook

**POST** `/webhook/{workflowId}/{nodeId}`

Trigger specific node in workflow via webhook.

**Path Parameters:**
- `workflowId`: Workflow ID
- `nodeId`: Node ID

**Request Body:**
Any JSON payload.

---

### Workflow Webhook (GET)

**GET** `/webhook/{workflowId}`

Handle GET requests to workflow webhook.

**Path Parameters:**
- `workflowId`: Workflow ID

**Query Parameters:**
Any query parameters will be passed to the workflow.

---

### Generic Webhook

**POST** `/hooks/{hookId}`

Generic webhook endpoint for custom integrations.

**Path Parameters:**
- `hookId`: Custom hook identifier

**Request Body:**
Any JSON payload.

---

### Generic Webhook (GET)

**GET** `/hooks/{hookId}`

Handle GET requests to generic webhook.

**Path Parameters:**
- `hookId`: Custom hook identifier

---

## System APIs

### Health Check

**GET** `/health`

Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "api",
  "timestamp": "2023-01-01T12:00:00Z"
}
```

---

### Version Information

**GET** `/version`

Get API version information.

**Response:**
```json
{
  "version": "1.0.0",
  "build_time": "2023-01-01T10:00:00Z",
  "git_commit": "abc123def456",
  "go_version": "go1.23"
}
```

---

### Prometheus Metrics

**GET** `/metrics`

🔒 **Authentication Required** (Admin Only)

Prometheus metrics endpoint for monitoring.

**Response:**
Prometheus format metrics data.

---

## Error Codes

### Authentication Errors
- `AUTH_REQUIRED` - Authentication token is required
- `AUTH_INVALID` - Invalid or expired token
- `AUTH_FORBIDDEN` - Insufficient permissions

### Validation Errors
- `VALIDATION_ERROR` - Request validation failed
- `INVALID_INPUT` - Invalid input parameters
- `MISSING_REQUIRED_FIELD` - Required field is missing

### Resource Errors
- `RESOURCE_NOT_FOUND` - Requested resource does not exist
- `RESOURCE_CONFLICT` - Resource already exists or conflict
- `RESOURCE_LOCKED` - Resource is locked or in use

### System Errors
- `INTERNAL_ERROR` - Internal server error
- `SERVICE_UNAVAILABLE` - Service temporarily unavailable
- `RATE_LIMIT_EXCEEDED` - Rate limit exceeded

---

## Rate Limiting

API endpoints are rate limited to prevent abuse:
- **Default limit**: 100 requests per minute per user
- **Webhook endpoints**: 1000 requests per minute per workflow
- **System endpoints**: 10 requests per minute per IP

When rate limit is exceeded, the API returns HTTP 429 with:
```json
{
  "success": false,
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded. Try again later.",
  "details": "Limit: 100 requests per minute"
}
```

---

## Pagination

List endpoints support pagination with the following parameters:
- `page`: Page number (starts from 1)
- `page_size`: Items per page (default: 50, max: 1000)

Pagination response format:
```json
{
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total": 150,
    "total_pages": 3
  }
}
```

---

## Security

### HTTPS
- Production deployments should use HTTPS
- TLS 1.2 or higher is required

### CORS
- CORS is configurable per deployment
- Default allowed origins: `["http://localhost:3000"]`

### Request Size Limits
- Maximum request body size: 10MB
- Maximum file upload size: 50MB

### Security Headers
All responses include standard security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

---

## SDK and Examples

### cURL Examples

**Login:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

**Create Workflow:**
```bash
curl -X POST http://localhost:8080/api/v1/workflows \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"name":"Test Workflow","description":"A test workflow"}'
```

**Execute Workflow:**
```bash
curl -X POST http://localhost:8080/api/v1/workflows/workflow_123/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"input_data":{"test":"data"},"mode":"manual"}'
```

---

## Support

For API support and questions:
- Documentation: This file
- Issues: Create GitHub issues for bugs or feature requests
- API Version: Check `/version` endpoint for current version

---

*Last updated: 2023-01-01*