#!/bin/bash

# Setup script for n8n-pro Postman testing
# This script helps set up the environment for comprehensive API error testing

set -e

echo "🚀 Setting up n8n-pro Postman Testing Environment"
echo "================================================="

# Check if Newman is installed
if ! command -v newman &> /dev/null; then
    echo "📦 Newman not found. Installing Newman CLI..."
    npm install -g newman
    echo "✅ Newman installed successfully"
else
    echo "✅ Newman is already installed"
fi

# Check if the API server is running
echo "🔍 Checking if API server is running..."
API_URL="http://localhost:8080/api/v1/health"

if curl -s "$API_URL" > /dev/null 2>&1; then
    echo "✅ API server is running at http://localhost:8080"
else
    echo "⚠️  API server is not running at http://localhost:8080"
    echo "   Please start your API server before running tests"
    echo "   Typically: 'go run cmd/api/main.go' or './api'"
fi

# Check if Postman collection exists
COLLECTION_FILE="postman/n8n-pro-api.postman_collection.json"
ENVIRONMENT_FILE="postman/n8n-pro.postman_environment.json"

if [[ -f "$COLLECTION_FILE" ]]; then
    echo "✅ Postman collection found: $COLLECTION_FILE"
else
    echo "❌ Postman collection not found: $COLLECTION_FILE"
    exit 1
fi

if [[ -f "$ENVIRONMENT_FILE" ]]; then
    echo "✅ Postman environment found: $ENVIRONMENT_FILE"
else
    echo "❌ Postman environment not found: $ENVIRONMENT_FILE"
    exit 1
fi

echo ""
echo "🎯 Available Test Commands:"
echo "=========================="

echo ""
echo "1️⃣  Run Full Test Suite:"
echo "   newman run $COLLECTION_FILE -e $ENVIRONMENT_FILE"

echo ""
echo "2️⃣  Run Only Authentication Tests:"
echo "   newman run $COLLECTION_FILE -e $ENVIRONMENT_FILE --folder 'Authentication'"

echo ""
echo "3️⃣  Run Tests with Detailed Output:"
echo "   newman run $COLLECTION_FILE -e $ENVIRONMENT_FILE --reporters cli,json --reporter-json-export results.json"

echo ""
echo "4️⃣  Run Tests and Generate HTML Report:"
echo "   newman run $COLLECTION_FILE -e $ENVIRONMENT_FILE --reporters cli,htmlextra --reporter-htmlextra-export report.html"

echo ""
echo "5️⃣  Run Specific Error Tests:"
echo "   newman run $COLLECTION_FILE -e $ENVIRONMENT_FILE --folder 'Authentication' --bail"

echo ""
echo "📊 Test Categories Available:"
echo "============================"
echo "   ✅ Valid Login & Registration"
echo "   ❌ Email Validation Errors"
echo "   ❌ Password Validation Errors"
echo "   ❌ Authentication Errors"
echo "   ❌ JSON Format Errors"
echo "   🔄 Token Refresh Tests"

echo ""
echo "🔧 Environment Variables:"
echo "========================"
echo "   base_url: http://localhost:8080/api/v1"
echo "   webhook_base_url: http://localhost:8081"
echo "   user_email: admin@example.com"
echo "   user_password: [SECRET]"

echo ""
echo "📚 Documentation:"
echo "================="
echo "   📖 Testing Guide: docs/postman/enhanced-error-testing-guide.md"
echo "   📋 Error Examples: examples/error_handling_demo.md"
echo "   🔗 Collection: $COLLECTION_FILE"
echo "   ⚙️  Environment: $ENVIRONMENT_FILE"

# Function to run a specific test category
run_authentication_tests() {
    echo ""
    echo "🔐 Running Authentication Error Tests..."
    echo "======================================="
    
    newman run "$COLLECTION_FILE" \
        -e "$ENVIRONMENT_FILE" \
        --folder "Authentication" \
        --reporters cli,json \
        --reporter-json-export "auth-test-results.json" \
        --bail
        
    if [[ $? -eq 0 ]]; then
        echo "✅ All authentication tests passed!"
    else
        echo "❌ Some authentication tests failed. Check the output above."
    fi
}

# Function to validate error responses
validate_error_responses() {
    echo ""
    echo "🔍 Validating Enhanced Error Response Structure..."
    echo "================================================"
    
    echo "Testing invalid email format..."
    RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"invalid-email","password":"test123"}' \
        2>/dev/null || echo '{"error":"connection_failed"}')
    
    if echo "$RESPONSE" | jq -e '.error.code == "invalid_email"' > /dev/null 2>&1; then
        echo "✅ Enhanced error structure is working correctly"
        echo "   Error Code: $(echo "$RESPONSE" | jq -r '.error.code')"
        echo "   Message: $(echo "$RESPONSE" | jq -r '.error.message')"
        echo "   Details: $(echo "$RESPONSE" | jq -r '.error.details')"
    else
        echo "⚠️  Enhanced error structure may not be working as expected"
        echo "   Response: $RESPONSE"
    fi
}

# Check if user wants to run tests immediately
echo ""
read -p "🚀 Would you like to run authentication tests now? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🎬 Starting Test Execution..."
    
    # First validate the enhanced error responses
    validate_error_responses
    
    echo ""
    read -p "🔐 Run full authentication test suite? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_authentication_tests
    fi
fi

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "You can now:"
echo "1. Open Postman and import the collection & environment"
echo "2. Use Newman CLI with the commands shown above"
echo "3. Review the testing guide in docs/postman/"
echo "4. Check error examples in examples/"
echo ""
echo "Happy Testing! 🧪✨"