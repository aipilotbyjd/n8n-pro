# n8n Pro API Documentation

This document provides comprehensive documentation for the n8n Pro REST API. The API follows REST principles and returns JSON responses.

## Base URL

```
https://api.n8n-pro.com/api/v1
```

For local development:
```
http://localhost:8080/api/v1
```

## Authentication

n8n Pro uses JWT (JSON Web Tokens) for authentication. Include the token in the `Authorization` header:

```bash
Authorization: Bearer <your-jwt-token>
```

### Getting an Access Token

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-password"
  }'
```

Response:
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "user",
      "team_id": "team-uuid"
    }
  }
}
```

## API Reference

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | User login |
| POST | `/auth/register` | User registration |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout user |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password |
| POST | `/auth/verify-email` | Verify email address |

### Workflow Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/workflows` | List workflows |
| POST | `/workflows` | Create workflow |
| GET | `/workflows/{id}` | Get workflow by ID |
| PUT | `/workflows/{id}` | Update workflow |
| DELETE | `/workflows/{id}` | Delete workflow |
| POST | `/workflows/{id}/execute` | Execute workflow |

### Execution Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/executions` | List executions |
| GET | `/executions/{id}` | Get execution by ID |
| DELETE | `/executions/{id}/cancel` | Cancel execution |
| POST | `/executions/{id}/retry` | Retry failed execution |

### User Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users/me` | Get current user |
| PUT | `/users/me` | Update current user |
| POST | `/users/me/change-password` | Change password |
| DELETE | `/users/me` | Delete account |

### Team Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/teams` | List user's teams |
| POST | `/teams` | Create team |
| GET | `/teams/{id}` | Get team by ID |
| PUT | `/teams/{id}` | Update team |
| DELETE | `/teams/{id}` | Delete team |
| POST | `/teams/{id}/members` | Add team member |
| GET | `/teams/{id}/members` | List team members |
| DELETE | `/teams/{id}/members/{user_id}` | Remove team member |

### Credential Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/credentials` | List credentials |
| POST | `/credentials` | Create credential |
| GET | `/credentials/types` | Get credential types |
| GET | `/credentials/{id}` | Get credential by ID |
| PUT | `/credentials/{id}` | Update credential |
| DELETE | `/credentials/{id}` | Delete credential |
| POST | `/credentials/{id}/test` | Test credential |

### Webhook Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/webhooks` | List webhooks |
| POST | `/webhooks` | Create webhook |
| GET | `/webhooks/{id}` | Get webhook by ID |
| PUT | `/webhooks/{id}` | Update webhook |
| DELETE | `/webhooks/{id}` | Delete webhook |
| POST | `/webhooks/{id}/test` | Test webhook |

### Node Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/nodes` | List available nodes |
| GET | `/nodes/categories` | List node categories |
| GET | `/nodes/{type}` | Get node definition |
| POST | `/nodes/{type}/test` | Test node |

### Template Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/templates` | List templates |
| POST | `/templates` | Create template |
| GET | `/templates/{id}` | Get template by ID |
| PUT | `/templates/{id}` | Update template |
| DELETE | `/templates/{id}` | Delete template |
| POST | `/templates/{id}/use` | Use template |

### Settings Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/settings/user` | Get user settings |
| PUT | `/settings/user` | Update user settings |
| GET | `/settings/system` | Get system settings |
| PUT | `/settings/system` | Update system settings |

### Metrics Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/metrics/workflows/{id}` | Get workflow metrics |
| GET | `/metrics/team` | Get team metrics |
| GET | `/metrics/system` | Get system metrics |
| GET | `/metrics/health` | Get health metrics |

## Standard Response Format

All API responses follow a consistent format:

### Success Response
```json
{
  "status": "success",
  "data": {
    // Response data here
  },
  "meta": {
    "timestamp": "2024-01-15T10:00:00Z",
    "request_id": "req-uuid"
  }
}
```

### Error Response
```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input provided",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  },
  "meta": {
    "timestamp": "2024-01-15T10:00:00Z",
    "request_id": "req-uuid"
  }
}
```

## Pagination

List endpoints support pagination using query parameters:

- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `sort`: Sort field and direction (e.g., `created_at:desc`)

Example:
```bash
GET /api/v1/workflows?page=2&limit=50&sort=name:asc
```

Response includes pagination metadata:
```json
{
  "status": "success",
  "data": {
    "workflows": [...],
    "pagination": {
      "page": 2,
      "limit": 50,
      "total": 250,
      "pages": 5,
      "has_next": true,
      "has_prev": true
    }
  }
}
```

## Filtering and Search

Many endpoints support filtering and search:

- `q`: Search query
- `filter[field]`: Filter by field value
- `created_after`: Filter by creation date
- `status`: Filter by status

Example:
```bash
GET /api/v1/workflows?q=automation&filter[status]=active&created_after=2024-01-01
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Default Limit**: 1000 requests per hour per user
- **Burst Limit**: 100 requests per minute
- **Headers**: Check `X-RateLimit-*` headers in responses

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
```

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | VALIDATION_ERROR | Invalid request data |
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 409 | CONFLICT | Resource conflict |
| 422 | UNPROCESSABLE_ENTITY | Business logic error |
| 429 | RATE_LIMITED | Rate limit exceeded |
| 500 | INTERNAL_ERROR | Server error |
| 503 | SERVICE_UNAVAILABLE | Service temporarily unavailable |

## Webhooks

n8n Pro can send webhooks for various events. Configure webhook URLs in your settings.

### Available Events

- `workflow.created`
- `workflow.updated`
- `workflow.deleted`
- `workflow.executed`
- `execution.started`
- `execution.completed`
- `execution.failed`
- `user.registered`
- `team.created`

### Webhook Payload

```json
{
  "event": "workflow.executed",
  "data": {
    "workflow_id": "workflow-uuid",
    "execution_id": "execution-uuid",
    "status": "completed",
    "started_at": "2024-01-15T10:00:00Z",
    "completed_at": "2024-01-15T10:01:30Z"
  },
  "meta": {
    "timestamp": "2024-01-15T10:01:31Z",
    "delivery_id": "delivery-uuid"
  }
}
```

### Webhook Security

Webhooks are signed with HMAC-SHA256. Verify the signature using the `X-Signature` header.

## SDKs and Libraries

Official SDKs are available for:

- **JavaScript/TypeScript**: `npm install @n8n-pro/sdk`
- **Python**: `pip install n8n-pro`
- **Go**: `go get github.com/n8n-pro/go-sdk`

## API Versioning

The API uses URL-based versioning. The current version is `v1`. Breaking changes will result in a new version.

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- JSON: `/api/v1/openapi.json`
- YAML: `/api/v1/openapi.yaml`
- Interactive docs: `/api/v1/docs`

## Support

For API support:
- **Documentation**: [docs.n8n-pro.com](https://docs.n8n-pro.com)
- **GitHub Issues**: [github.com/n8n-pro/n8n-pro/issues](https://github.com/n8n-pro/n8n-pro/issues)
- **Email**: api-support@n8n-pro.com