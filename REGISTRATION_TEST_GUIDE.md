# 🧪 Registration Testing Guide

This guide will help you test your n8n Pro registration system using cURL commands. Follow these steps to verify that your authentication system is working correctly.

## 📋 Prerequisites

Before testing, make sure you have:

- ✅ **Go 1.23+** installed
- ✅ **PostgreSQL** running (default port 5432)
- ✅ **Redis** running (default port 6379)
- ✅ **Database migrated** and ready
- ✅ **cURL** installed (for testing)
- ✅ **jq** installed (optional, for pretty JSON output)

## 🚀 Step 1: Start Your Server

### Option A: Using Go Run (Development)
```bash
cd n8n-pro
go run cmd/api/main.go
```

### Option B: Using Built Binary
```bash
cd n8n-pro
go build -o bin/api cmd/api/main.go
./bin/api
```

### Expected Server Output
```
INFO Starting n8n Pro API Server version=dev build_time=unknown git_commit=unknown
INFO Starting API server addr=localhost:8080
INFO API server started successfully port=8080 tls_enabled=false
```

## 🔍 Step 2: Health Check

First, verify your server is running:

```bash
# Basic health check
curl http://localhost:8080/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "service": "api",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## 🧪 Step 3: API Information

Check if the API endpoints are available:

```bash
# Get API info
curl http://localhost:8080/api/v1
```

**Expected Response:**
```json
{
  "name": "n8n-pro API",
  "version": "v1",
  "description": "Enterprise Workflow Automation Platform API",
  "endpoints": {
    "authentication": {
      "login": "POST /api/v1/auth/login",
      "register": "POST /api/v1/auth/register",
      "refresh": "POST /api/v1/auth/refresh",
      "logout": "POST /api/v1/users/logout"
    }
  }
}
```

## ✅ Step 4: Valid Registration Tests

### Test 1: Basic Valid Registration

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "organization_name": "My Company"
  }'
```

**Expected Response (HTTP 201):**
```json
{
  "user": {
    "id": "uuid-here",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "status": "pending",
    "role": "member",
    "email_verified": false,
    "created_at": "2024-01-15T10:30:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900,
  "token_type": "Bearer",
  "session_id": "session-uuid-here"
}
```

### Test 2: Minimal Valid Registration

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "jane.smith@example.com",
    "password": "AnotherSecure123!",
    "confirm_password": "AnotherSecure123!",
    "first_name": "Jane",
    "last_name": "Smith"
  }'
```

### Test 3: Registration with All Fields

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@techcorp.com",
    "password": "SuperSecure456!",
    "confirm_password": "SuperSecure456!",
    "first_name": "Alice",
    "last_name": "Johnson",
    "organization_name": "Tech Corp Inc",
    "accept_terms": true
  }'
```

## ❌ Step 5: Invalid Registration Tests

### Test 4: Duplicate Email

```bash
# First registration
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "duplicate@example.com",
    "password": "Password123!",
    "confirm_password": "Password123!",
    "first_name": "First",
    "last_name": "User"
  }'

# Second registration with same email (should fail)
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "duplicate@example.com",
    "password": "Different123!",
    "confirm_password": "Different123!",
    "first_name": "Second",
    "last_name": "User"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Email already exists",
  "status": 400
}
```

### Test 5: Invalid Email Format

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid-email-format",
    "password": "Password123!",
    "confirm_password": "Password123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Invalid email format",
  "status": 400
}
```

### Test 6: Password Mismatch

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "mismatch@example.com",
    "password": "Password123!",
    "confirm_password": "Different123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Passwords do not match",
  "status": 400
}
```

### Test 7: Weak Password

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "weak@example.com",
    "password": "123",
    "confirm_password": "123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Password must be at least 8 characters long",
  "status": 400
}
```

### Test 8: Missing Required Fields

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "missing@example.com"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Missing required fields",
  "status": 400
}
```

### Test 9: Invalid JSON

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid@example.com",
    "password": "Password123!"
    "first_name": "John"
  }'
```

**Expected Response (HTTP 400):**
```json
{
  "error": "Invalid request body",
  "status": 400
}
```

## 🛠️ Step 6: Advanced Testing

### Test with Pretty Output (using jq)

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "pretty@example.com",
    "password": "PrettyPassword123!",
    "confirm_password": "PrettyPassword123!",
    "first_name": "Pretty",
    "last_name": "Output"
  }' | jq '.'
```

### Test with Verbose Output

```bash
curl -v -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "verbose@example.com",
    "password": "VerboseTest123!",
    "confirm_password": "VerboseTest123!",
    "first_name": "Verbose",
    "last_name": "Test"
  }'
```

### Test Response Time

```bash
curl -w "@curl-format.txt" -o /dev/null -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "timing@example.com",
    "password": "TimingTest123!",
    "confirm_password": "TimingTest123!",
    "first_name": "Timing",
    "last_name": "Test"
  }'
```

Create `curl-format.txt` with:
```
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
```

## 🔄 Step 7: Automated Test Script

Run the provided test script for comprehensive testing:

```bash
# Make script executable
chmod +x test_registration.sh

# Run all tests
./test_registration.sh

# Or specify custom URL
BASE_URL="http://localhost:8080" ./test_registration.sh
```

## 🐛 Step 8: Troubleshooting

### Server Not Starting

**Error:** Connection refused
```bash
curl: (7) Failed to connect to localhost port 8080: Connection refused
```

**Solutions:**
1. Check if server is running: `ps aux | grep api`
2. Check server logs for errors
3. Verify database connection
4. Check if port 8080 is available: `lsof -i :8080`

### Database Connection Issues

**Error in server logs:**
```
FATAL Failed to connect to database error="connection refused"
```

**Solutions:**
1. Start PostgreSQL: `brew services start postgresql` (macOS) or `sudo systemctl start postgresql` (Linux)
2. Check connection: `psql -h localhost -p 5432 -U postgres`
3. Verify database exists: `SELECT datname FROM pg_database;`

### Auth Service Not Available

**Response:**
```json
{"error":"Auth service not available"}
```

**Solutions:**
1. Check server logs for auth service initialization errors
2. Verify database schema is migrated
3. Check if required tables exist

### Invalid Responses

**Issue:** Getting HTML instead of JSON
```html
<html><body><h1>404 Not Found</h1></body></html>
```

**Solutions:**
1. Check URL path (use `/api/v1/auth/register` not `/auth/register`)
2. Verify server is running on correct port
3. Check if Content-Type header is set

## 📊 Step 9: Expected Test Results

### ✅ Successful Tests
- **Valid Registration**: HTTP 201, returns user data and tokens
- **Health Check**: HTTP 200, returns status "healthy"
- **API Info**: HTTP 200, returns endpoint information

### ❌ Expected Failures
- **Duplicate Email**: HTTP 400, validation error
- **Invalid Email**: HTTP 400, format error
- **Password Mismatch**: HTTP 400, validation error
- **Weak Password**: HTTP 400, password policy error
- **Missing Fields**: HTTP 400, required field error
- **Invalid JSON**: HTTP 400, parsing error

## 🎯 Step 10: Production Testing Checklist

Before deploying to production, verify:

- [ ] All registration validations work correctly
- [ ] Email uniqueness is enforced
- [ ] Password hashing is working (passwords not stored in plain text)
- [ ] JWT tokens are generated correctly
- [ ] Session management works
- [ ] Rate limiting prevents abuse
- [ ] Error messages don't reveal sensitive information
- [ ] Database transactions are atomic
- [ ] Logging captures security events
- [ ] HTTPS is enforced (in production)

## 🔐 Security Notes

1. **Never log passwords** in production
2. **Use HTTPS** in production
3. **Implement rate limiting** to prevent brute force attacks
4. **Validate all inputs** on server side
5. **Use secure JWT secrets** (32+ characters)
6. **Monitor failed registration attempts**

## 📝 Example Test Session

```bash
# 1. Start server
go run cmd/api/main.go &

# 2. Wait for server to start
sleep 2

# 3. Test health
curl http://localhost:8080/health

# 4. Test valid registration
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "confirm_password": "TestPassword123!",
    "first_name": "Test",
    "last_name": "User"
  }' | jq '.'

# 5. Test duplicate (should fail)
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "AnotherPassword123!",
    "confirm_password": "AnotherPassword123!",
    "first_name": "Another",
    "last_name": "User"
  }' | jq '.'

# 6. Stop server
killall api
```

## 🎉 Success Criteria

Your registration system is working correctly if:

✅ Valid registrations return HTTP 201 with user data and JWT tokens  
✅ Invalid registrations return appropriate HTTP 4xx errors  
✅ Email uniqueness is enforced  
✅ Password validation works  
✅ JWT tokens are properly formatted  
✅ Database records are created correctly  

Happy testing! 🚀