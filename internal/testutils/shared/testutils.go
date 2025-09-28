package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"n8n-pro/pkg/logger"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestConfig holds test configuration
type TestConfig struct {
	DatabaseURL    string
	RedisURL       string
	LogLevel       string
	EnableLogs     bool
	TestDataDir    string
	TempDir        string
	EnableMetrics  bool
	TimeoutSeconds int
}

// DefaultTestConfig returns default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		DatabaseURL:    ":memory:",
		RedisURL:       "redis://localhost:6379/15", // Use test database
		LogLevel:       "debug",
		EnableLogs:     false, // Disable logs by default in tests
		TestDataDir:    "./testdata",
		TempDir:        os.TempDir(),
		EnableMetrics:  false,
		TimeoutSeconds: 30,
	}
}

// TestContext provides a test context with timeout
type TestContext struct {
	Ctx    context.Context
	Cancel context.CancelFunc
	T      *testing.T
}

// NewTestContext creates a new test context
func NewTestContext(t *testing.T, timeout ...time.Duration) *TestContext {
	duration := 30 * time.Second
	if len(timeout) > 0 {
		duration = timeout[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	
	// Add test-specific context values
	ctx = context.WithValue(ctx, "test_name", t.Name())
	ctx = context.WithValue(ctx, "request_id", fmt.Sprintf("test-%d", time.Now().UnixNano()))

	return &TestContext{
		Ctx:    ctx,
		Cancel: cancel,
		T:      t,
	}
}

// Cleanup cancels the context (should be deferred)
func (tc *TestContext) Cleanup() {
	tc.Cancel()
}

// DatabaseTestHelper provides database testing utilities
type DatabaseTestHelper struct {
	DB     *gorm.DB
	config *TestConfig
}

// NewDatabaseTestHelper creates a new database test helper
func NewDatabaseTestHelper(config *TestConfig) (*DatabaseTestHelper, error) {
	if config == nil {
		config = DefaultTestConfig()
	}

	var db *gorm.DB
	var err error

	if config.DatabaseURL == ":memory:" {
		// Use in-memory SQLite for tests
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
			Logger: logger.NewGormLogger(logger.New("test-db")),
		})
	} else {
		// Use provided database URL
		db, err = gorm.Open(sqlite.Open(config.DatabaseURL), &gorm.Config{
			Logger: logger.NewGormLogger(logger.New("test-db")),
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to test database: %w", err)
	}

	return &DatabaseTestHelper{
		DB:     db,
		config: config,
	}, nil
}

// Setup initializes the test database with schema
func (dth *DatabaseTestHelper) Setup(t *testing.T, models ...interface{}) error {
	if err := dth.DB.AutoMigrate(models...); err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
		return err
	}
	return nil
}

// Cleanup cleans up the test database
func (dth *DatabaseTestHelper) Cleanup(t *testing.T) error {
	// Get the underlying SQL DB
	sqlDB, err := dth.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Truncate truncates all specified tables
func (dth *DatabaseTestHelper) Truncate(t *testing.T, tables ...string) {
	for _, table := range tables {
		if err := dth.DB.Exec(fmt.Sprintf("DELETE FROM %s", table)).Error; err != nil {
			t.Errorf("Failed to truncate table %s: %v", table, err)
		}
	}
}

// Seed seeds the database with test data
func (dth *DatabaseTestHelper) Seed(t *testing.T, data map[string][]interface{}) {
	for table, records := range data {
		for _, record := range records {
			if err := dth.DB.Table(table).Create(record).Error; err != nil {
				t.Errorf("Failed to seed table %s: %v", table, err)
			}
		}
	}
}

// HTTPTestHelper provides HTTP testing utilities
type HTTPTestHelper struct {
	Server *httptest.Server
	Client *http.Client
	config *TestConfig
}

// NewHTTPTestHelper creates a new HTTP test helper
func NewHTTPTestHelper(handler http.Handler, config *TestConfig) *HTTPTestHelper {
	if config == nil {
		config = DefaultTestConfig()
	}

	server := httptest.NewServer(handler)
	client := &http.Client{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}

	return &HTTPTestHelper{
		Server: server,
		Client: client,
		config: config,
	}
}

// Cleanup closes the test server
func (hth *HTTPTestHelper) Cleanup() {
	hth.Server.Close()
}

// Request makes an HTTP request to the test server
func (hth *HTTPTestHelper) Request(method, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	var bodyReader io.Reader
	
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	url := hth.Server.URL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set default headers
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return hth.Client.Do(req)
}

// GET makes a GET request
func (hth *HTTPTestHelper) GET(path string, headers ...map[string]string) (*http.Response, error) {
	h := make(map[string]string)
	if len(headers) > 0 {
		h = headers[0]
	}
	return hth.Request("GET", path, nil, h)
}

// POST makes a POST request
func (hth *HTTPTestHelper) POST(path string, body interface{}, headers ...map[string]string) (*http.Response, error) {
	h := make(map[string]string)
	if len(headers) > 0 {
		h = headers[0]
	}
	return hth.Request("POST", path, body, h)
}

// PUT makes a PUT request
func (hth *HTTPTestHelper) PUT(path string, body interface{}, headers ...map[string]string) (*http.Response, error) {
	h := make(map[string]string)
	if len(headers) > 0 {
		h = headers[0]
	}
	return hth.Request("PUT", path, body, h)
}

// DELETE makes a DELETE request
func (hth *HTTPTestHelper) DELETE(path string, headers ...map[string]string) (*http.Response, error) {
	h := make(map[string]string)
	if len(headers) > 0 {
		h = headers[0]
	}
	return hth.Request("DELETE", path, nil, h)
}

// ResponseHelper provides utilities for testing HTTP responses
type ResponseHelper struct {
	Response *http.Response
	Body     []byte
}

// NewResponseHelper creates a new response helper
func NewResponseHelper(resp *http.Response) (*ResponseHelper, error) {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &ResponseHelper{
		Response: resp,
		Body:     body,
	}, nil
}

// AssertStatus asserts the response status code
func (rh *ResponseHelper) AssertStatus(t *testing.T, expectedStatus int) *ResponseHelper {
	if rh.Response.StatusCode != expectedStatus {
		t.Errorf("Expected status %d, got %d. Response body: %s", 
			expectedStatus, rh.Response.StatusCode, string(rh.Body))
	}
	return rh
}

// AssertJSON unmarshals the response body to the provided struct
func (rh *ResponseHelper) AssertJSON(t *testing.T, target interface{}) *ResponseHelper {
	if err := json.Unmarshal(rh.Body, target); err != nil {
		t.Errorf("Failed to unmarshal JSON response: %v. Body: %s", err, string(rh.Body))
	}
	return rh
}

// AssertContains checks if the response body contains a substring
func (rh *ResponseHelper) AssertContains(t *testing.T, substring string) *ResponseHelper {
	if !strings.Contains(string(rh.Body), substring) {
		t.Errorf("Response body does not contain '%s'. Body: %s", substring, string(rh.Body))
	}
	return rh
}

// AssertHeader checks if a response header has the expected value
func (rh *ResponseHelper) AssertHeader(t *testing.T, headerName, expectedValue string) *ResponseHelper {
	actualValue := rh.Response.Header.Get(headerName)
	if actualValue != expectedValue {
		t.Errorf("Expected header %s to be '%s', got '%s'", headerName, expectedValue, actualValue)
	}
	return rh
}

// FileHelper provides file testing utilities
type FileHelper struct {
	testDir string
}

// NewFileHelper creates a new file helper
func NewFileHelper(testDir string) *FileHelper {
	if testDir == "" {
		testDir = os.TempDir()
	}
	return &FileHelper{testDir: testDir}
}

// CreateTempFile creates a temporary file with content
func (fh *FileHelper) CreateTempFile(t *testing.T, content string, suffix ...string) string {
	s := ".tmp"
	if len(suffix) > 0 {
		s = suffix[0]
	}

	file, err := os.CreateTemp(fh.testDir, "test-*"+s)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := file.WriteString(content); err != nil {
		file.Close()
		os.Remove(file.Name())
		t.Fatalf("Failed to write temp file: %v", err)
	}

	file.Close()
	return file.Name()
}

// CreateTempDir creates a temporary directory
func (fh *FileHelper) CreateTempDir(t *testing.T, prefix string) string {
	dir, err := os.MkdirTemp(fh.testDir, prefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}

// ReadFile reads a file and returns its content
func (fh *FileHelper) ReadFile(t *testing.T, filename string) string {
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", filename, err)
	}
	return string(content)
}

// WriteFile writes content to a file
func (fh *FileHelper) WriteFile(t *testing.T, filename, content string) {
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write file %s: %v", filename, err)
	}
}

// LoadTestData loads test data from a JSON file
func LoadTestData(t *testing.T, filename string, target interface{}) {
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read test data file %s: %v", filename, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}
}

// SaveTestData saves test data to a JSON file
func SaveTestData(t *testing.T, filename string, data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		t.Fatalf("Failed to write test data file %s: %v", filename, err)
	}
}

// AssertEqual asserts that two values are equal
func AssertEqual(t *testing.T, expected, actual interface{}, message ...string) {
	if expected != actual {
		msg := fmt.Sprintf("Expected %v, got %v", expected, actual)
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// AssertNotEqual asserts that two values are not equal
func AssertNotEqual(t *testing.T, expected, actual interface{}, message ...string) {
	if expected == actual {
		msg := fmt.Sprintf("Expected %v to not equal %v", expected, actual)
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// AssertNil asserts that a value is nil
func AssertNil(t *testing.T, actual interface{}, message ...string) {
	if actual != nil {
		msg := fmt.Sprintf("Expected nil, got %v", actual)
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// AssertNotNil asserts that a value is not nil
func AssertNotNil(t *testing.T, actual interface{}, message ...string) {
	if actual == nil {
		msg := "Expected non-nil value"
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// AssertError asserts that an error occurred
func AssertError(t *testing.T, err error, message ...string) {
	if err == nil {
		msg := "Expected an error"
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// AssertNoError asserts that no error occurred
func AssertNoError(t *testing.T, err error, message ...string) {
	if err != nil {
		msg := fmt.Sprintf("Expected no error, got: %v", err)
		if len(message) > 0 {
			msg = message[0] + ": " + msg
		}
		t.Error(msg)
	}
}

// MockTimeProvider provides a mock time implementation for testing
type MockTimeProvider struct {
	CurrentTime time.Time
}

// Now returns the mocked current time
func (mtp *MockTimeProvider) Now() time.Time {
	return mtp.CurrentTime
}

// SetTime sets the mocked current time
func (mtp *MockTimeProvider) SetTime(t time.Time) {
	mtp.CurrentTime = t
}

// AdvanceTime advances the mocked time by the given duration
func (mtp *MockTimeProvider) AdvanceTime(duration time.Duration) {
	mtp.CurrentTime = mtp.CurrentTime.Add(duration)
}

// TestSuite represents a test suite with setup and cleanup
type TestSuite struct {
	Name        string
	DB          *DatabaseTestHelper
	HTTP        *HTTPTestHelper
	Files       *FileHelper
	Config      *TestConfig
	MockTime    *MockTimeProvider
	cleanupFns  []func()
}

// NewTestSuite creates a new test suite
func NewTestSuite(name string, config *TestConfig) *TestSuite {
	if config == nil {
		config = DefaultTestConfig()
	}

	return &TestSuite{
		Name:     name,
		Config:   config,
		Files:    NewFileHelper(config.TestDataDir),
		MockTime: &MockTimeProvider{CurrentTime: time.Now()},
	}
}

// SetupDatabase initializes the database helper
func (ts *TestSuite) SetupDatabase(t *testing.T, models ...interface{}) {
	var err error
	ts.DB, err = NewDatabaseTestHelper(ts.Config)
	if err != nil {
		t.Fatalf("Failed to setup database: %v", err)
	}

	if err := ts.DB.Setup(t, models...); err != nil {
		t.Fatalf("Failed to setup database schema: %v", err)
	}

	ts.cleanupFns = append(ts.cleanupFns, func() {
		ts.DB.Cleanup(t)
	})
}

// SetupHTTP initializes the HTTP helper
func (ts *TestSuite) SetupHTTP(handler http.Handler) {
	ts.HTTP = NewHTTPTestHelper(handler, ts.Config)
	ts.cleanupFns = append(ts.cleanupFns, func() {
		ts.HTTP.Cleanup()
	})
}

// Cleanup runs all cleanup functions
func (ts *TestSuite) Cleanup(t *testing.T) {
	for i := len(ts.cleanupFns) - 1; i >= 0; i-- {
		ts.cleanupFns[i]()
	}
}

// Run runs a test function with the test suite
func (ts *TestSuite) Run(t *testing.T, testFn func(t *testing.T, suite *TestSuite)) {
	t.Run(ts.Name, func(t *testing.T) {
		defer ts.Cleanup(t)
		testFn(t, ts)
	})
}

// Benchmark utilities

// BenchmarkHelper provides benchmarking utilities
type BenchmarkHelper struct {
	config *TestConfig
}

// NewBenchmarkHelper creates a new benchmark helper
func NewBenchmarkHelper(config *TestConfig) *BenchmarkHelper {
	if config == nil {
		config = DefaultTestConfig()
	}
	return &BenchmarkHelper{config: config}
}

// RunHTTPBenchmark runs an HTTP benchmark
func (bh *BenchmarkHelper) RunHTTPBenchmark(b *testing.B, handler http.Handler, method, path string, body interface{}) {
	server := httptest.NewServer(handler)
	defer server.Close()

	client := &http.Client{
		Timeout: time.Duration(bh.config.TimeoutSeconds) * time.Second,
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			b.Fatalf("Failed to marshal body: %v", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var reqBody io.Reader
			if body != nil {
				jsonBody, _ := json.Marshal(body)
				reqBody = bytes.NewBuffer(jsonBody)
			}

			req, err := http.NewRequest(method, server.URL+path, reqBody)
			if err != nil {
				b.Fatalf("Failed to create request: %v", err)
			}

			if reqBody != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()
		}
	})
}

// Integration test utilities

// IntegrationTestHelper provides integration testing utilities
type IntegrationTestHelper struct {
	Config    *TestConfig
	Processes map[string]*os.Process
}

// NewIntegrationTestHelper creates a new integration test helper
func NewIntegrationTestHelper(config *TestConfig) *IntegrationTestHelper {
	if config == nil {
		config = DefaultTestConfig()
	}

	return &IntegrationTestHelper{
		Config:    config,
		Processes: make(map[string]*os.Process),
	}
}

// StartService starts a service for integration testing
func (ith *IntegrationTestHelper) StartService(t *testing.T, name, command string, args ...string) {
	// This would start external services for integration testing
	// Implementation would depend on specific requirements
	t.Logf("Starting service %s: %s %v", name, command, args)
}

// StopService stops a running service
func (ith *IntegrationTestHelper) StopService(t *testing.T, name string) {
	if process, exists := ith.Processes[name]; exists {
		if err := process.Kill(); err != nil {
			t.Errorf("Failed to stop service %s: %v", name, err)
		}
		delete(ith.Processes, name)
	}
}

// WaitForService waits for a service to become available
func (ith *IntegrationTestHelper) WaitForService(t *testing.T, url string, timeout time.Duration) {
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("Service at %s did not become available within %v", url, timeout)
}

// Cleanup stops all running services
func (ith *IntegrationTestHelper) Cleanup(t *testing.T) {
	for name := range ith.Processes {
		ith.StopService(t, name)
	}
}