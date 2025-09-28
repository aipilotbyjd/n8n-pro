#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
BASE_URL="http://localhost:8080"
API_URL="$BASE_URL/api/v1"

echo -e "${BLUE}🚀 n8n Pro Registration Endpoint Test${NC}"
echo -e "${BLUE}=====================================${NC}\n"

# Function to print test results
print_result() {
    local test_name="$1"
    local status_code="$2"
    local expected_code="$3"
    local response="$4"

    echo -e "${YELLOW}Test: $test_name${NC}"
    echo -e "Expected: $expected_code | Got: $status_code"

    if [ "$status_code" = "$expected_code" ]; then
        echo -e "${GREEN}✅ PASS${NC}"
    else
        echo -e "${RED}❌ FAIL${NC}"
    fi

    echo -e "Response:"
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    echo -e "\n${BLUE}----------------------------------------${NC}\n"
}

# Function to make HTTP request
make_request() {
    local url="$1"
    local method="$2"
    local data="$3"

    if [ -n "$data" ]; then
        curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" \
             -H "Content-Type: application/json" \
             -d "$data" \
             "$url"
    else
        curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" "$url"
    fi
}

# Step 1: Check if server is running
echo -e "${BLUE}1. Checking if server is running...${NC}"
response=$(make_request "$BASE_URL/health" "GET")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

if [ "$status_code" = "200" ]; then
    echo -e "${GREEN}✅ Server is running${NC}"
    echo "Health check response: $response_body"
else
    echo -e "${RED}❌ Server is not running or not accessible${NC}"
    echo "Make sure your server is started with: go run cmd/api/main.go"
    exit 1
fi
echo ""

# Step 2: Check API info
echo -e "${BLUE}2. Checking API info...${NC}"
response=$(make_request "$API_URL" "GET")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "API Info" "$status_code" "200" "$response_body"

# Step 3: Test valid registration
echo -e "${BLUE}3. Testing valid registration...${NC}"
valid_data='{
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "organization_name": "Test Corp"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$valid_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Valid Registration" "$status_code" "201" "$response_body"

# Step 4: Test duplicate email registration
echo -e "${BLUE}4. Testing duplicate email registration...${NC}"
duplicate_data='{
    "email": "test@example.com",
    "password": "AnotherPassword123!",
    "confirm_password": "AnotherPassword123!",
    "first_name": "Jane",
    "last_name": "Smith",
    "organization_name": "Another Corp"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$duplicate_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Duplicate Email Registration" "$status_code" "400" "$response_body"

# Step 5: Test invalid email format
echo -e "${BLUE}5. Testing invalid email format...${NC}"
invalid_email_data='{
    "email": "invalid-email",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$invalid_email_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Invalid Email Format" "$status_code" "400" "$response_body"

# Step 6: Test password mismatch
echo -e "${BLUE}6. Testing password mismatch...${NC}"
password_mismatch_data='{
    "email": "test2@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "DifferentPassword123!",
    "first_name": "John",
    "last_name": "Doe"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$password_mismatch_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Password Mismatch" "$status_code" "400" "$response_body"

# Step 7: Test weak password
echo -e "${BLUE}7. Testing weak password...${NC}"
weak_password_data='{
    "email": "test3@example.com",
    "password": "123",
    "confirm_password": "123",
    "first_name": "John",
    "last_name": "Doe"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$weak_password_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Weak Password" "$status_code" "400" "$response_body"

# Step 8: Test missing required fields
echo -e "${BLUE}8. Testing missing required fields...${NC}"
missing_fields_data='{
    "email": "test4@example.com"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$missing_fields_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Missing Required Fields" "$status_code" "400" "$response_body"

# Step 9: Test invalid JSON
echo -e "${BLUE}9. Testing invalid JSON...${NC}"
invalid_json='{
    "email": "test5@example.com",
    "password": "SecurePassword123!"
    "first_name": "John"
}'

response=$(make_request "$API_URL/auth/register" "POST" "$invalid_json")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Invalid JSON" "$status_code" "400" "$response_body"

# Step 10: Test successful registration with unique email
echo -e "${BLUE}10. Testing another successful registration...${NC}"
timestamp=$(date +%s)
success_data="{
    \"email\": \"user$timestamp@example.com\",
    \"password\": \"SecurePassword123!\",
    \"confirm_password\": \"SecurePassword123!\",
    \"first_name\": \"Jane\",
    \"last_name\": \"Smith\",
    \"organization_name\": \"Tech Startup\"
}"

response=$(make_request "$API_URL/auth/register" "POST" "$success_data")
status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')

print_result "Another Successful Registration" "$status_code" "201" "$response_body"

# Final Summary
echo -e "${BLUE}📊 Test Summary${NC}"
echo -e "${BLUE}===============${NC}"
echo -e "${GREEN}✅ Server Health Check - PASSED${NC}"
echo -e "${GREEN}✅ API Info Check - EXPECTED${NC}"
echo -e "${YELLOW}📋 Registration Tests:${NC}"
echo -e "   - Valid registration: Check status 201"
echo -e "   - Duplicate email: Check status 400"
echo -e "   - Invalid email format: Check status 400"
echo -e "   - Password mismatch: Check status 400"
echo -e "   - Weak password: Check status 400"
echo -e "   - Missing fields: Check status 400"
echo -e "   - Invalid JSON: Check status 400"
echo -e "   - Second valid registration: Check status 201"

echo -e "\n${BLUE}🔧 How to run your server:${NC}"
echo -e "1. Make sure your database is running"
echo -e "2. Run: ${YELLOW}go run cmd/api/main.go${NC}"
echo -e "3. Server should start on: ${YELLOW}http://localhost:8080${NC}"

echo -e "\n${BLUE}🔍 Manual test example:${NC}"
echo -e "${YELLOW}curl -X POST http://localhost:8080/api/v1/auth/register \\"
echo -e "  -H \"Content-Type: application/json\" \\"
echo -e "  -d '{"
echo -e "    \"email\": \"manual@example.com\","
echo -e "    \"password\": \"SecurePassword123!\","
echo -e "    \"confirm_password\": \"SecurePassword123!\","
echo -e "    \"first_name\": \"Manual\","
echo -e "    \"last_name\": \"Test\""
echo -e "  }'${NC}"

echo -e "\n${GREEN}✨ Test completed!${NC}"
