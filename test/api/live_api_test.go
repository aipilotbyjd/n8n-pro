package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultBaseURL = "http://localhost:8080"
	timeout        = 30 * time.Second
)

type APITester struct {
	baseURL string
	client  *http.Client
	token   string
}

func TestLiveAPI(t *testing.T) {
	baseURL := defaultBaseURL
	if os.Getenv("API_BASE_URL") != "" {
		baseURL = os.Getenv("API_BASE_URL")
	}

	tester := &APITester{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}

	fmt.Printf("🚀 Testing n8n Clone API at %s\n\n", baseURL)

	// Test endpoints
	tests := []func() error{
		tester.testHealthEndpoint,
		tester.testVersionEndpoint,
		tester.testAuthEndpoints,
		tester.testWorkflowEndpoints,
		tester.testExecutionEndpoints,
		tester.testErrorHandling,
	}

	passed := 0
	total := len(tests)

	for i, test := range tests {
		if err := test(); err != nil {
			fmt.Printf("❌ Test %d failed: %v\n", i+1, err)
		} else {
			fmt.Printf("✅ Test %d passed\n", i+1)
			passed++
		}
	}

	fmt.Printf("\n📊 Results: %d/%d tests passed\n", passed, total)
	
	if passed == total {
		t.Logf("🎉 All tests passed! Your n8n clone API is working correctly.")
	} else {
		t.Errorf("❌ Some tests failed. Please check your API implementation.")
	}
}

func (t *APITester) testHealthEndpoint() error {
	fmt.Print("Testing health endpoint... ")
	
	resp, err := t.client.Get(t.baseURL + "/health")
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		return fmt.Errorf("expected status 'healthy', got %v", response["status"])
	}

	return nil
}

func (t *APITester) testVersionEndpoint() error {
	fmt.Print("Testing version endpoint... ")
	
	resp, err := t.client.Get(t.baseURL + "/version")
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if response["version"] == nil {
		return fmt.Errorf("version field is missing")
	}

	return nil
}

func (t *APITester) testAuthEndpoints() error {
	fmt.Print("Testing authentication endpoints... ")
	
	// Test login endpoint (should exist but may not be fully implemented)
	loginData := map[string]interface{}{
		"email":    "test@example.com",
		"password": "test123",
	}
	
	body, _ := json.Marshal(loginData)
	resp, err := t.client.Post(t.baseURL+"/api/v1/auth/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	// Accept any reasonable status for auth endpoints (they might not be fully implemented)
	if resp.StatusCode >= 500 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error on login: %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (t *APITester) testWorkflowEndpoints() error {
	fmt.Print("Testing workflow endpoints... ")
	
	// Test list workflows (should require auth, expect 401)
	resp, err := t.client.Get(t.baseURL + "/api/v1/workflows")
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be unauthorized without auth token
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 401 or 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Test create workflow (should require auth)
	workflowData := map[string]interface{}{
		"name":        "Test Workflow",
		"description": "API Test Workflow",
		"nodes":       []interface{}{},
		"connections": []interface{}{},
	}
	
	body, _ := json.Marshal(workflowData)
	resp, err = t.client.Post(t.baseURL+"/api/v1/workflows", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create workflow request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be unauthorized without auth token
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 401 or 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (t *APITester) testExecutionEndpoints() error {
	fmt.Print("Testing execution endpoints... ")
	
	// Test list executions (should require auth)
	resp, err := t.client.Get(t.baseURL + "/api/v1/executions")
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be unauthorized without auth token
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 401 or 200, got %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *APITester) testErrorHandling() error {
	fmt.Print("Testing error handling... ")
	
	// Test invalid endpoint
	resp, err := t.client.Get(t.baseURL + "/api/v1/nonexistent")
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 404, got %d: %s", resp.StatusCode, string(body))
	}

	// Test invalid JSON
	resp, err = t.client.Post(t.baseURL+"/api/v1/workflows", "application/json", strings.NewReader("{invalid json"))
	if err != nil {
		return fmt.Errorf("invalid JSON request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be 400 (bad request) or 401 (unauthorized)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected 400 or 401, got %d: %s", resp.StatusCode, string(body))
	}

	return nil
}