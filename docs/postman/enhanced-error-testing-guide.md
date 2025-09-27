# Enhanced Error Handling - Postman Testing Guide

This guide provides comprehensive instructions for testing the enhanced error handling system using Postman.

## Overview

The n8n-pro API now includes detailed error handling that provides:
- ✅ **Specific error codes** for different scenarios
- ✅ **User-friendly messages** in plain language  
- ✅ **Actionable guidance** on how to resolve issues
- ✅ **Detailed context** for debugging
- ✅ **Security-conscious** error responses

## Postman Collection Structure

### 🔐 Authentication Tests

#### ✅ Successful Tests
1. **Valid Login** - Tests successful authentication
2. **Valid Registration** - Tests successful user registration

#### ❌ Error Tests

##### Login Errors
- **Invalid Email Format** - Tests email validation
- **Missing Password** - Tests required field validation  
- **Invalid Credentials** - Tests authentication failure
- **Invalid JSON Body** - Tests request format validation

##### Registration Errors  
- **Email Already Exists** - Tests duplicate email handling
- **Password Too Short** - Tests minimum length validation
- **Weak Password** - Tests password complexity requirements
- **Common Password** - Tests forbidden password detection
- **Invalid Email Format** - Tests email format validation
- **Missing Name** - Tests required field validation

## Test Execution Guide

### Step 1: Environment Setup

1. **Import Environment**: Import `n8n-pro.postman_environment.json`
2. **Configure Base URL**: Set `base_url` to your API endpoint (default: `http://localhost:8080/api/v1`)
3. **Set Test Credentials**: Update `user_email` and `user_password` with valid credentials

### Step 2: Running Error Tests

#### 🎯 **Recommended Test Order**

1. **Start with Registration Tests** (to create test data)
2. **Run Login Tests** (to validate authentication)
3. **Execute Error Scenarios** (to validate error handling)

#### 🔄 **Test Execution Patterns**

##### Pattern 1: Full Suite Testing
```
1. Run "✅ Valid Registration" 
2. Run "✅ Valid Login" (save tokens)
3. Run all "❌ Error Tests" sequentially
```

##### Pattern 2: Individual Error Testing
```
1. Select specific error test
2. Review expected error structure
3. Execute and validate response
```

### Step 3: Understanding Error Responses

#### Standard Error Response Structure
```json
{
  "success": false,
  "error": {
    "code": "specific_error_code",
    "message": "User-friendly error message", 
    "details": "Additional helpful information",
    "context": {
      "field_name": "context_value",
      "missing_requirements": ["requirement1", "requirement2"]
    }
  },
  "timestamp": "2023-01-01T12:00:00.000Z"
}
```

#### Error Code Categories

| Category | Codes | Purpose |
|----------|-------|---------|
| **Validation** | `invalid_email`, `password_too_short`, `password_too_weak` | Input validation errors |
| **Authentication** | `invalid_credentials`, `account_locked`, `account_disabled` | Authentication failures |
| **Conflict** | `email_exists` | Resource conflicts |
| **Format** | Request format issues | JSON parsing errors |

## Detailed Test Scenarios

### 🔍 **Email Validation Tests**

#### Test Case: Invalid Email Format
```javascript
// Request Body
{
  "email": "invalid-email",
  "password": "testpassword123"
}

// Expected Response
{
  "success": false,
  "error": {
    "code": "invalid_email",
    "message": "Please enter a valid email address",
    "details": "Email should be in format: user@example.com",
    "context": {
      "email": "invalid-email"
    }
  }
}
```

**Validation Points:**
- ✅ Status code: `400 Bad Request`
- ✅ Error code matches expected value
- ✅ Message is user-friendly
- ✅ Details provide guidance
- ✅ Context includes invalid input

### 🔒 **Password Validation Tests**

#### Test Case: Weak Password
```javascript
// Request Body  
{
  "name": "Test User",
  "email": "test@example.com", 
  "password": "lowercase",
  "team_name": "Test Team"
}

// Expected Response
{
  "success": false,
  "error": {
    "code": "password_too_weak",
    "message": "Password does not meet security requirements",
    "details": "Password must contain: at least one uppercase letter (A-Z), at least one number (0-9)",
    "context": {
      "missing_requirements": [
        "at least one uppercase letter (A-Z)",
        "at least one number (0-9)"
      ]
    }
  }
}
```

**Validation Points:**
- ✅ Status code: `400 Bad Request`
- ✅ Specific password requirements listed
- ✅ Context includes missing requirements array
- ✅ Details explain what to do

### 🔐 **Authentication Tests**

#### Test Case: Invalid Credentials
```javascript
// Request Body
{
  "email": "nonexistent@example.com",
  "password": "wrongpassword"
}

// Expected Response  
{
  "success": false,
  "error": {
    "code": "invalid_credentials", 
    "message": "Invalid email address or password",
    "details": "Please check your credentials and try again"
  }
}
```

**Security Notes:**
- ✅ Generic message prevents user enumeration
- ✅ No indication whether email exists
- ✅ Consistent response time
- ✅ Status code: `401 Unauthorized`

## Advanced Testing Features

### 🎲 **Dynamic Test Data**

The collection uses Postman's dynamic variables:
- `{{$randomInt}}` - Generates unique numbers for emails
- `{{$timestamp}}` - Creates unique timestamps
- `{{$guid}}` - Generates UUIDs

**Example Dynamic Email:**
```json
{
  "email": "testuser{{$randomInt}}@example.com"
}
```

### 📊 **Automated Test Assertions**

Each test includes comprehensive assertions:

```javascript
// Status Code Validation
pm.test('❌ Invalid Email - Status code is 400', () => {
    pm.response.to.have.status(400);
});

// Response Structure Validation  
pm.test('❌ Invalid Email - Error structure', () => {
    const response = pm.response.json();
    pm.expect(response.success).to.be.false;
    pm.expect(response.error).to.exist;
    pm.expect(response.error.code).to.eql('invalid_email');
    pm.expect(response.error.message).to.eql('Please enter a valid email address');
    pm.expect(response.error.details).to.contain('Email should be in format');
});
```

### 🔄 **Test Chain Execution**

Tests are designed to run in sequence:

1. **Setup Phase**: Create test data
2. **Success Phase**: Verify normal operation  
3. **Error Phase**: Validate error scenarios
4. **Cleanup Phase**: Clear test data

## Troubleshooting

### Common Issues

#### 🚫 **Server Not Running**
```json
{
  "error": {
    "name": "NetworkError",
    "message": "getaddrinfo ENOTFOUND localhost"
  }
}
```
**Solution**: Ensure API server is running on configured port

#### 🚫 **Wrong Base URL**  
```json
{
  "error": {
    "name": "StatusCodeError", 
    "statusCode": 404
  }
}
```
**Solution**: Verify `base_url` in environment settings

#### 🚫 **Invalid Environment**
```
ReferenceError: user_email is not defined
```
**Solution**: Import and select proper environment

### Debug Mode

Enable detailed logging in tests:
```javascript
console.log('Request:', pm.request);
console.log('Response:', pm.response.json());
console.log('Environment:', pm.environment.toObject());
```

## Performance Testing

### Response Time Validation
```javascript
pm.test('Response time is acceptable', () => {
    pm.expect(pm.response.responseTime).to.be.below(2000);
});
```

### Memory Usage Monitoring
- Monitor response sizes
- Check for memory leaks in error handling
- Validate consistent performance across error types

## Security Testing

### Error Information Disclosure
- ✅ No sensitive data in error messages
- ✅ No stack traces in production errors
- ✅ Generic messages for authentication failures
- ✅ No database schema information exposed

### Rate Limiting Tests
- Test multiple failed login attempts
- Verify account lockout mechanisms  
- Check rate limiting error messages

## Continuous Integration

### Newman CLI Integration
```bash
# Install Newman
npm install -g newman

# Run full test suite
newman run n8n-pro-api.postman_collection.json \
  -e n8n-pro.postman_environment.json \
  --reporters cli,json \
  --reporter-json-export results.json

# Run only authentication tests
newman run n8n-pro-api.postman_collection.json \
  -e n8n-pro.postman_environment.json \
  --folder "Authentication"
```

### GitHub Actions Example
```yaml
name: API Error Handling Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run API Tests
        run: |
          newman run postman/n8n-pro-api.postman_collection.json \
            -e postman/n8n-pro.postman_environment.json \
            --reporters cli,junit \
            --reporter-junit-export results.xml
```

## Best Practices

### ✅ **Test Design**
- Always test both success and failure scenarios
- Use descriptive test names with emojis for clarity
- Include comprehensive assertions
- Test edge cases and boundary conditions

### ✅ **Error Message Quality**
- Verify messages are user-friendly
- Check that guidance is actionable  
- Ensure context is helpful but not verbose
- Validate security considerations

### ✅ **Maintenance**
- Keep test data synchronized with API changes
- Update assertions when error messages change
- Review error scenarios regularly
- Document any custom test setups

## Conclusion

The enhanced error handling system provides a much better developer and user experience. This testing guide ensures you can thoroughly validate all error scenarios and maintain high quality error handling as your API evolves.

For questions or issues, refer to the main API documentation or contact the development team.