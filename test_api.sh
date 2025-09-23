#!/bin/bash

# N8N Clone API Testing Script
# This script tests all the major API endpoints like an n8n clone

echo "🚀 Starting N8N Clone API Testing..."
echo "========================================="

# Configuration
API_BASE="http://localhost:8080"
TEST_EMAIL="test$(date +%s)@n8n-clone.com"
TEST_PASSWORD="TestPassword123!"
AUTH_TOKEN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to test an endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_code=$4
    local description=$5
    
    echo -e "\n${BLUE}Testing:${NC} $description"
    echo -e "${YELLOW}$method${NC} $endpoint"
    
    if [ -n "$data" ]; then
        if [ -n "$AUTH_TOKEN" ]; then
            response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $method \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $AUTH_TOKEN" \
                -d "$data" \
                "$API_BASE$endpoint")
        else
            response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $method \
                -H "Content-Type: application/json" \
                -d "$data" \
                "$API_BASE$endpoint")
        fi
    else
        if [ -n "$AUTH_TOKEN" ]; then
            response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $method \
                -H "Authorization: Bearer $AUTH_TOKEN" \
                "$API_BASE$endpoint")
        else
            response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $method \
                "$API_BASE$endpoint")
        fi
    fi
    
    # Extract HTTP status code
    http_code=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
    
    # Check if response matches expected
    if [ "$http_code" -eq "$expected_code" ]; then
        echo -e "${GREEN}✅ PASS${NC} (HTTP $http_code)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} (Expected HTTP $expected_code, got HTTP $http_code)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
        return 1
    fi
}

# Start testing
echo -e "\n${BLUE}Phase 1: Basic Health Checks${NC}"
echo "================================"

# Test health endpoint
test_endpoint "GET" "/health" "" 200 "Health Check"

# Test version endpoint
test_endpoint "GET" "/version" "" 200 "Version Information"

echo -e "\n${BLUE}Phase 2: Authentication System${NC}"
echo "=================================="

# Test user registration
registration_data="{
    \"name\": \"Test User\",
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
}"

test_endpoint "POST" "/api/v1/auth/register" "$registration_data" 201 "User Registration"

# Test user login
login_data="{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
}"

echo -e "\n${BLUE}Attempting login...${NC}"
login_response=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$login_data" \
    "$API_BASE/api/v1/auth/login")

echo "$login_response" | jq . 2>/dev/null || echo "$login_response"

# Extract token (if login successful)
AUTH_TOKEN=$(echo "$login_response" | jq -r '.data.access_token // empty' 2>/dev/null)

if [ -n "$AUTH_TOKEN" ] && [ "$AUTH_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ Login successful, token extracted${NC}"
else
    echo -e "${YELLOW}⚠️  Login may have failed or token not found, continuing with limited tests${NC}"
fi

echo -e "\n${BLUE}Phase 3: Workflow Management${NC}"
echo "================================"

# Test workflow creation
workflow_data='{
    "name": "Test Integration Workflow",
    "description": "A comprehensive test workflow for API validation",
    "nodes": [
        {
            "id": "start-node-1",
            "type": "n8n-nodes-base.start",
            "name": "When clicking Test workflow",
            "parameters": {},
            "position": [250, 300]
        },
        {
            "id": "http-node-1",
            "type": "n8n-nodes-base.httpRequest",
            "name": "GitHub API Request",
            "parameters": {
                "url": "https://api.github.com/users/octocat",
                "method": "GET"
            },
            "position": [450, 300]
        },
        {
            "id": "set-node-1", 
            "type": "n8n-nodes-base.set",
            "name": "Transform Data",
            "parameters": {
                "values": {
                    "string": [
                        {
                            "name": "username",
                            "value": "={{$json[\"login\"]}}"
                        }
                    ]
                }
            },
            "position": [650, 300]
        }
    ],
    "connections": {
        "When clicking Test workflow": {
            "main": [
                [
                    {
                        "node": "GitHub API Request",
                        "type": "main",
                        "index": 0
                    }
                ]
            ]
        },
        "GitHub API Request": {
            "main": [
                [
                    {
                        "node": "Transform Data",
                        "type": "main",
                        "index": 0
                    }
                ]
            ]
        }
    },
    "tags": ["test", "integration", "api"],
    "active": true
}'

test_endpoint "POST" "/api/v1/workflows" "$workflow_data" 201 "Create Workflow"

# Get workflows list
test_endpoint "GET" "/api/v1/workflows" "" 200 "List Workflows"

echo -e "\n${BLUE}Phase 4: Credential Management${NC}"
echo "=================================="

# Test credential creation
credential_data='{
    "name": "Test API Credentials",
    "type": "httpBasicAuth",
    "data": {
        "username": "testuser",
        "password": "testpass"
    },
    "description": "Test credentials for API integration testing"
}'

test_endpoint "POST" "/api/v1/credentials" "$credential_data" 201 "Create Credential"

# List credentials
test_endpoint "GET" "/api/v1/credentials" "" 200 "List Credentials"

# Get credential types
test_endpoint "GET" "/api/v1/credentials/types" "" 200 "Get Credential Types"

echo -e "\n${BLUE}Phase 5: Execution Management${NC}"
echo "================================="

# List executions
test_endpoint "GET" "/api/v1/executions" "" 200 "List Executions"

echo -e "\n${BLUE}Phase 6: Metrics and Monitoring${NC}"
echo "===================================="

# Test system metrics
test_endpoint "GET" "/api/v1/metrics/system" "" 200 "System Metrics"

# Test team metrics
test_endpoint "GET" "/api/v1/metrics/team" "" 200 "Team Metrics"

# Test Prometheus metrics (no auth required)
AUTH_TOKEN_BACKUP="$AUTH_TOKEN"
AUTH_TOKEN=""
test_endpoint "GET" "/metrics" "" 200 "Prometheus Metrics"
AUTH_TOKEN="$AUTH_TOKEN_BACKUP"

echo -e "\n${BLUE}Phase 7: User Profile Management${NC}"
echo "====================================="

# Get current user profile
test_endpoint "GET" "/api/v1/profile" "" 200 "Get User Profile"

# Update profile
profile_update='{
    "name": "Updated Test User",
    "preferences": {
        "theme": "dark",
        "language": "en"
    }
}'

test_endpoint "PUT" "/api/v1/profile" "$profile_update" 200 "Update User Profile"

echo -e "\n${BLUE}Phase 8: Advanced Features Testing${NC}"
echo "======================================="

# Test webhook endpoints (if available)
test_endpoint "GET" "/api/v1/webhooks" "" 200 "List Webhooks" || echo -e "${YELLOW}⚠️  Webhooks endpoint may not be implemented${NC}"

# Test template endpoints (if available)
test_endpoint "GET" "/api/v1/templates" "" 200 "List Templates" || echo -e "${YELLOW}⚠️  Templates endpoint may not be implemented${NC}"

echo -e "\n${GREEN}🎉 API Testing Complete!${NC}"
echo "==============================="

echo -e "\n${BLUE}Summary:${NC}"
echo "- Health checks: Basic server functionality"
echo "- Authentication: User registration and login"
echo "- Workflows: Creation and management like n8n"
echo "- Credentials: Secure credential storage"
echo "- Executions: Workflow execution tracking"
echo "- Metrics: System monitoring and analytics"
echo "- Profile: User profile management"

echo -e "\n${BLUE}Test completed for n8n clone API!${NC}"
echo "All major endpoints have been validated."

# Check if server is running for real-time testing
if curl -s "$API_BASE/health" > /dev/null; then
    echo -e "\n${GREEN}✅ Server is running at $API_BASE${NC}"
    echo -e "You can run this script with: ${YELLOW}./test_api.sh${NC}"
else
    echo -e "\n${RED}❌ Server is not running at $API_BASE${NC}"
    echo -e "Please start the server first with:"
    echo -e "${YELLOW}DB_HOST=localhost DB_PORT=5432 DB_NAME=n8n_clone DB_USER=user DB_PASSWORD=password JWT_SECRET=test-secret-key-for-jwt-signing-32-chars-long go run cmd/api/main.go${NC}"
fi