# Workflows API

The Workflows API allows you to manage workflow definitions, including creating, updating, deleting, and executing workflows.

## Endpoints

### List Workflows

```http
GET /api/v1/workflows
```

Get a paginated list of workflows for the current user/team.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `limit` | integer | 20 | Items per page (max: 100) |
| `sort` | string | `created_at:desc` | Sort field and direction |
| `q` | string | - | Search query |
| `status` | string | - | Filter by status (`draft`, `active`, `inactive`) |
| `tag` | string | - | Filter by tag |
| `created_after` | string | - | Filter by creation date (ISO 8601) |

#### Example Request

```bash
curl -X GET "http://localhost:8080/api/v1/workflows?page=1&limit=10&status=active" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Example Response

```json
{
  "status": "success",
  "data": {
    "workflows": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Daily Report Automation",
        "description": "Generates and sends daily reports to stakeholders",
        "status": "active",
        "tags": ["reporting", "automation"],
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T12:00:00Z",
        "last_executed": "2024-01-16T09:00:00Z",
        "execution_count": 25,
        "success_rate": 96.0,
        "node_count": 8
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 45,
      "pages": 5,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

### Create Workflow

```http
POST /api/v1/workflows
```

Create a new workflow.

#### Request Body

```json
{
  "name": "My New Workflow",
  "description": "Description of the workflow",
  "nodes": [
    {
      "id": "start-node",
      "type": "n8n-nodes-base.start",
      "name": "Start",
      "parameters": {},
      "position": [100, 100]
    },
    {
      "id": "http-node",
      "type": "n8n-nodes-base.httpRequest",
      "name": "HTTP Request",
      "parameters": {
        "url": "https://api.example.com/data",
        "method": "GET",
        "headers": {
          "Content-Type": "application/json"
        }
      },
      "position": [300, 100]
    }
  ],
  "connections": [
    {
      "source_node": "start-node",
      "source_output": "main",
      "target_node": "http-node",
      "target_input": "main"
    }
  ],
  "tags": ["api", "automation"],
  "settings": {
    "timeout": 300,
    "max_execution_time": 3600,
    "error_workflow": null,
    "enable_logging": true
  }
}
```

#### Example Request

```bash
curl -X POST "http://localhost:8080/api/v1/workflows" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Data Fetcher",
    "description": "Fetches data from external API",
    "nodes": [
      {
        "id": "start",
        "type": "n8n-nodes-base.start",
        "name": "Start",
        "parameters": {},
        "position": [100, 100]
      }
    ],
    "connections": [],
    "tags": ["api"]
  }'
```

#### Example Response

```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "name": "API Data Fetcher",
    "description": "Fetches data from external API",
    "status": "draft",
    "nodes": [
      {
        "id": "start",
        "type": "n8n-nodes-base.start",
        "name": "Start",
        "parameters": {},
        "position": [100, 100]
      }
    ],
    "connections": [],
    "tags": ["api"],
    "created_at": "2024-01-16T10:00:00Z",
    "updated_at": "2024-01-16T10:00:00Z",
    "created_by": "user-uuid",
    "team_id": "team-uuid"
  }
}
```

### Get Workflow

```http
GET /api/v1/workflows/{id}
```

Get a specific workflow by ID.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Workflow UUID |

#### Example Request

```bash
curl -X GET "http://localhost:8080/api/v1/workflows/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Example Response

```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Daily Report Automation",
    "description": "Generates and sends daily reports to stakeholders",
    "status": "active",
    "nodes": [
      {
        "id": "start-node",
        "type": "n8n-nodes-base.start",
        "name": "Start",
        "parameters": {},
        "position": [100, 100]
      },
      {
        "id": "database-node",
        "type": "n8n-nodes-base.postgres",
        "name": "Fetch Data",
        "parameters": {
          "query": "SELECT * FROM sales WHERE date = CURRENT_DATE",
          "credential": "postgres-cred-id"
        },
        "position": [300, 100]
      },
      {
        "id": "email-node",
        "type": "n8n-nodes-base.emailSend",
        "name": "Send Report",
        "parameters": {
          "to": "team@company.com",
          "subject": "Daily Sales Report",
          "credential": "email-cred-id"
        },
        "position": [500, 100]
      }
    ],
    "connections": [
      {
        "source_node": "start-node",
        "source_output": "main",
        "target_node": "database-node",
        "target_input": "main"
      },
      {
        "source_node": "database-node",
        "source_output": "main",
        "target_node": "email-node",
        "target_input": "main"
      }
    ],
    "tags": ["reporting", "automation"],
    "settings": {
      "timeout": 300,
      "max_execution_time": 3600,
      "error_workflow": null,
      "enable_logging": true
    },
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-01-15T12:00:00Z",
    "created_by": "user-uuid",
    "team_id": "team-uuid",
    "statistics": {
      "execution_count": 25,
      "success_rate": 96.0,
      "average_duration": 45.2,
      "last_executed": "2024-01-16T09:00:00Z"
    }
  }
}
```

### Update Workflow

```http
PUT /api/v1/workflows/{id}
```

Update an existing workflow.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Workflow UUID |

#### Request Body

Same structure as Create Workflow, but all fields are optional.

#### Example Request

```bash
curl -X PUT "http://localhost:8080/api/v1/workflows/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Workflow Name",
    "description": "Updated description",
    "status": "active"
  }'
```

#### Example Response

```json
{
  "status": "success",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Updated Workflow Name",
    "description": "Updated description",
    "status": "active",
    "updated_at": "2024-01-16T11:00:00Z"
  }
}
```

### Delete Workflow

```http
DELETE /api/v1/workflows/{id}
```

Delete a workflow. This action is irreversible.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Workflow UUID |

#### Example Request

```bash
curl -X DELETE "http://localhost:8080/api/v1/workflows/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Example Response

```json
{
  "status": "success",
  "data": {
    "message": "Workflow deleted successfully",
    "deleted_at": "2024-01-16T12:00:00Z"
  }
}
```

### Execute Workflow

```http
POST /api/v1/workflows/{id}/execute
```

Execute a workflow immediately.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Workflow UUID |

#### Request Body

```json
{
  "mode": "sync",
  "input_data": {
    "customVariable": "value",
    "anotherVariable": 42
  },
  "wait_for_webhook": false,
  "timeout": 300
}
```

#### Request Body Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `async` | Execution mode (`sync` or `async`) |
| `input_data` | object | `{}` | Custom input data for the workflow |
| `wait_for_webhook` | boolean | `false` | Wait for webhook responses |
| `timeout` | integer | `300` | Execution timeout in seconds |

#### Example Request

```bash
curl -X POST "http://localhost:8080/api/v1/workflows/550e8400-e29b-41d4-a716-446655440000/execute" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "sync",
    "input_data": {
      "reportDate": "2024-01-16"
    }
  }'
```

#### Example Response (Async Mode)

```json
{
  "status": "success",
  "data": {
    "execution_id": "exec-550e8400-e29b-41d4-a716-446655440002",
    "workflow_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "running",
    "started_at": "2024-01-16T13:00:00Z",
    "mode": "async"
  }
}
```

#### Example Response (Sync Mode)

```json
{
  "status": "success",
  "data": {
    "execution_id": "exec-550e8400-e29b-41d4-a716-446655440002",
    "workflow_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "started_at": "2024-01-16T13:00:00Z",
    "finished_at": "2024-01-16T13:01:30Z",
    "execution_time": 90.5,
    "mode": "sync",
    "output_data": {
      "reportGenerated": true,
      "recordsProcessed": 1542,
      "emailSent": true
    }
  }
}
```

## Workflow Node Types

### Built-in Node Types

Common node types available in workflows:

| Type | Description | Category |
|------|-------------|----------|
| `n8n-nodes-base.start` | Manual trigger | Triggers |
| `n8n-nodes-base.webhook` | Webhook trigger | Triggers |
| `n8n-nodes-base.cron` | Schedule trigger | Triggers |
| `n8n-nodes-base.httpRequest` | HTTP request | Actions |
| `n8n-nodes-base.code` | JavaScript/Python code | Actions |
| `n8n-nodes-base.if` | Conditional logic | Logic |
| `n8n-nodes-base.switch` | Multi-way branching | Logic |
| `n8n-nodes-base.merge` | Merge data streams | Logic |
| `n8n-nodes-base.emailSend` | Send email | Communication |
| `n8n-nodes-base.slack` | Slack integration | Communication |
| `n8n-nodes-base.postgres` | PostgreSQL database | Databases |
| `n8n-nodes-base.mysql` | MySQL database | Databases |
| `n8n-nodes-base.mongodb` | MongoDB database | Databases |

### Node Parameters

Each node type has specific parameters. Common parameter patterns:

#### HTTP Request Node
```json
{
  "url": "https://api.example.com/endpoint",
  "method": "GET|POST|PUT|DELETE",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token"
  },
  "body": "JSON string or object",
  "timeout": 30000,
  "credential": "credential-id"
}
```

#### Code Node
```json
{
  "language": "javascript|python",
  "code": "// JavaScript code here\nreturn items;",
  "libraries": ["lodash", "moment"],
  "timeout": 60
}
```

#### Database Node
```json
{
  "operation": "select|insert|update|delete",
  "query": "SELECT * FROM users WHERE active = true",
  "parameters": ["value1", "value2"],
  "credential": "database-credential-id"
}
```

## Error Responses

### Common Errors

#### Workflow Not Found
```json
{
  "status": "error",
  "error": {
    "code": "WORKFLOW_NOT_FOUND",
    "message": "Workflow with ID '550e8400-e29b-41d4-a716-446655440000' not found",
    "details": {
      "workflow_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

#### Validation Error
```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Workflow validation failed",
    "details": {
      "field": "nodes",
      "reason": "Workflow must contain at least one node"
    }
  }
}
```

#### Execution Error
```json
{
  "status": "error",
  "error": {
    "code": "EXECUTION_ERROR",
    "message": "Workflow execution failed",
    "details": {
      "node_id": "http-node",
      "reason": "Connection timeout after 30 seconds"
    }
  }
}
```

## Workflow Best Practices

1. **Naming**: Use descriptive names for workflows and nodes
2. **Error Handling**: Include error workflows for critical processes
3. **Timeouts**: Set appropriate timeouts for long-running operations
4. **Credentials**: Use secure credential storage for sensitive data
5. **Testing**: Test workflows in draft mode before activation
6. **Monitoring**: Enable logging for troubleshooting
7. **Documentation**: Use descriptions to document complex logic