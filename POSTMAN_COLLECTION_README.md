# n8n Pro API - Postman Collection

This directory contains a comprehensive Postman collection for testing all n8n Pro APIs.

## Files

- `n8n-pro-api.postman_collection.json` - Main Postman collection with all API endpoints
- `n8n-pro.postman_environment.json` - Environment variables for the collection
- `API_DOCUMENTATION.md` - Complete API documentation

## Quick Setup

### 1. Import Collection & Environment

1. Open Postman
2. Click **Import** button
3. Import both files:
   - `n8n-pro-api.postman_collection.json`
   - `n8n-pro.postman_environment.json`

### 2. Configure Environment

1. Select the **n8n Pro Environment** from the environment dropdown
2. Update these variables if needed:
   - `base_url` - API server URL (default: `http://localhost:8080/api/v1`)
   - `webhook_base_url` - Webhook server URL (default: `http://localhost:8081`)
   - `user_email` - Your login email
   - `user_password` - Your login password

### 3. Start Testing

1. **First, run "Login"** from the Authentication folder
   - This will automatically save your access token
   - All other requests will use this token automatically

2. **Test any endpoint** - they're organized by functionality:
   - 🔐 **Authentication** - Login, register, refresh tokens
   - 📋 **Workflows** - CRUD operations, execution
   - ⚡ **Executions** - View, cancel, retry executions
   - 👤 **User Management** - Profile management
   - 📊 **Metrics** - Performance and analytics
   - 🪝 **Webhooks** - Trigger workflows externally
   - 🔧 **System** - Health checks and version info

## Collection Features

### 🔄 **Automatic Token Management**
- Login automatically saves access and refresh tokens
- All authenticated requests use saved tokens
- Refresh token endpoint updates tokens automatically

### 📝 **Smart Test Scripts**
- Automatic response validation
- Status code checks
- Response time monitoring
- Error logging with detailed messages

### 🔗 **Variable Chaining**
- Created resources (workflows, executions) automatically save IDs
- Use saved IDs in subsequent requests
- No manual copy-pasting required

### 📊 **Response Validation**
- Validates response structure
- Checks for required fields
- Monitors API performance

## Usage Examples

### Basic Workflow Testing

1. **Login** (Authentication → Login)
2. **Create Workflow** (Workflows → Create Workflow)
3. **Execute Workflow** (Workflows → Execute Workflow)
4. **Check Execution** (Executions → Get Execution)

### Advanced Testing Sequence

1. **Login** to get authenticated
2. **List Workflows** to see existing workflows
3. **Create new workflow** with custom nodes
4. **Execute the workflow** with test data
5. **Monitor execution** status and results
6. **Get workflow metrics** to see performance
7. **Get team metrics** for overview

## Environment Variables

### Server Configuration
```
base_url = http://localhost:8080/api/v1
webhook_base_url = http://localhost:8081
```

### Authentication
```
user_email = admin@example.com
user_password = admin123
access_token = (auto-populated after login)
refresh_token = (auto-populated after login)
```

### Dynamic IDs (auto-populated)
```
user_id = (from login response)
team_id = (from login response)
workflow_id = (from first workflow in list)
created_workflow_id = (from create workflow response)
execution_id = (from execute workflow response)
```

## API Endpoint Coverage

### ✅ Authentication APIs
- `POST /auth/login` - User authentication
- `POST /auth/register` - User registration  
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - User logout

### ✅ Workflow APIs
- `GET /workflows` - List workflows with filters
- `POST /workflows` - Create new workflow
- `GET /workflows/{id}` - Get workflow details
- `PUT /workflows/{id}` - Update workflow
- `DELETE /workflows/{id}` - Delete workflow
- `POST /workflows/{id}/execute` - Execute workflow

### ✅ Execution APIs
- `GET /executions` - List executions
- `GET /executions/{id}` - Get execution details
- `DELETE /executions/{id}/cancel` - Cancel execution
- `POST /executions/{id}/retry` - Retry failed execution

### ✅ User Management APIs
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update user profile
- `POST /users/me/change-password` - Change password
- `DELETE /users/me` - Delete account

### ✅ Metrics APIs
- `GET /metrics/workflows/{id}` - Workflow metrics
- `GET /metrics/team` - Team metrics
- `GET /metrics/system` - System metrics (admin)
- `GET /metrics/health` - Health metrics

### ✅ Webhook APIs
- `POST /webhook/{workflowId}` - Trigger workflow webhook
- `POST /webhook/{workflowId}/{nodeId}` - Trigger node webhook
- `GET /webhook/{workflowId}` - GET webhook handler
- `POST /hooks/{hookId}` - Generic webhook

### ✅ System APIs
- `GET /health` - Basic health check
- `GET /version` - Version information
- `GET /metrics` - Prometheus metrics (admin)

## Testing Tips

### 🔥 **Quick Start Sequence**
1. Run **Authentication → Login** first
2. Run **Workflows → List Workflows** to populate workflow_id
3. Now you can test any workflow-specific endpoints

### 🛠️ **Debugging**
- Check the **Console** tab in Postman for detailed logs
- Failed requests show error details automatically
- Response times are monitored for performance

### 🔄 **Automated Testing**
- Use **Collection Runner** to run entire folders
- Set up **Monitors** for continuous API testing
- Export **Newman** scripts for CI/CD integration

### 📈 **Performance Testing**
- All requests include response time validation
- Use **Performance** tab to monitor API speed
- Collection includes load testing capabilities

## Sample Requests

### Create a Complete Workflow
```json
{
  "name": "Customer Onboarding",
  "description": "Automated customer onboarding process",
  "nodes": [
    {
      "id": "webhook_trigger",
      "type": "webhook",
      "position": {"x": 100, "y": 100},
      "parameters": {
        "method": "POST",
        "path": "/customer-signup"
      }
    },
    {
      "id": "send_welcome_email",
      "type": "email",
      "position": {"x": 300, "y": 100},
      "parameters": {
        "template": "welcome_email",
        "to": "{{customer.email}}"
      }
    }
  ],
  "connections": [
    {
      "from_node": "webhook_trigger",
      "from_output": "main",
      "to_node": "send_welcome_email",
      "to_input": "main"
    }
  ],
  "config": {
    "timeout": 300,
    "retry_attempts": 3
  }
}
```

### Execute Workflow with Data
```json
{
  "input_data": {
    "customer": {
      "name": "John Doe",
      "email": "john.doe@example.com",
      "plan": "premium"
    },
    "source": "website_signup"
  },
  "mode": "manual"
}
```

## Troubleshooting

### Common Issues

**❌ "Unauthorized" errors**
- Make sure you've run the Login request first
- Check that access_token is saved in environment variables
- Try refreshing your token with the Refresh Token endpoint

**❌ "Workflow ID is required" errors**
- Run "List Workflows" first to populate the workflow_id variable
- Or manually set workflow_id in environment variables

**❌ Connection refused errors**
- Verify your n8n Pro servers are running
- Check base_url and webhook_base_url in environment
- Ensure ports 8080 (API) and 8081 (Webhook) are accessible

### Debug Steps

1. **Check Environment Variables**
   - Go to Environment settings
   - Verify all URLs and credentials are correct

2. **Review Console Logs**
   - Open Postman Console
   - Check for detailed error messages and debug info

3. **Validate Server Status**
   - Run "System → Health Check" to verify server is running
   - Run "System → Version Info" to check API version

## Advanced Usage

### Collection Runner
- Select any folder (e.g., "Workflows")
- Click **Run** to execute all requests in sequence
- Perfect for regression testing

### Newman CLI
```bash
# Export and run with Newman
newman run n8n-pro-api.postman_collection.json \
  -e n8n-pro.postman_environment.json \
  --reporters cli,json
```

### Continuous Integration
```yaml
# Example GitHub Actions workflow
- name: API Tests
  run: |
    newman run n8n-pro-api.postman_collection.json \
      -e n8n-pro.postman_environment.json \
      --reporters junit
```

---

## 🚀 Ready to Test!

Your n8n Pro API collection is now ready for comprehensive testing. Start with the Authentication folder and explore all the powerful features of your workflow automation platform!

**Need help?** Check the [API Documentation](./API_DOCUMENTATION.md) for detailed endpoint specifications.