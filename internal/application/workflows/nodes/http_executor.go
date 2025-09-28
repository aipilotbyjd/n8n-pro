package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// HTTPExecutor implements actual HTTP requests for the HTTP node
type HTTPExecutor struct {
	client *http.Client
	logger logger.Logger
}

// HTTPNodeConfig represents the configuration for HTTP node
type HTTPNodeConfig struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            interface{}       `json:"body"`
	Timeout         int               `json:"timeout"`
	FollowRedirects bool              `json:"follow_redirects"`
	Authentication  *HTTPAuth         `json:"authentication,omitempty"`
	RetryAttempts   int               `json:"retry_attempts"`
	RetryDelay      int               `json:"retry_delay"`
}

// HTTPAuth represents authentication configuration
type HTTPAuth struct {
	Type     string `json:"type"` // "bearer", "basic", "api_key"
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
	Header   string `json:"header,omitempty"`
}

// HTTPResponse represents the response from HTTP request
type HTTPResponse struct {
	StatusCode int                    `json:"status_code"`
	Status     string                 `json:"status"`
	Headers    map[string][]string    `json:"headers"`
	Body       interface{}            `json:"body"`
	Success    bool                   `json:"success"`
	Duration   int64                  `json:"duration_ms"`
	Size       int64                  `json:"response_size"`
	Timestamp  int64                  `json:"timestamp"`
	Error      string                 `json:"error,omitempty"`
}

// NewHTTPExecutor creates a new HTTP node executor
func NewHTTPExecutor() *HTTPExecutor {
	return &HTTPExecutor{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger.New("http-node"),
	}
}

// Execute performs the HTTP request
func (h *HTTPExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	start := time.Now()
	
	// Parse configuration from parameters
	config, err := h.parseConfig(parameters)
	if err != nil {
		return h.createErrorResponse(start, fmt.Sprintf("Invalid configuration: %v", err)), err
	}

	h.logger.Debug("Executing HTTP request", "method", config.Method, "url", config.URL)

	// Create HTTP request
	req, err := h.createRequest(ctx, config, inputData)
	if err != nil {
		return h.createErrorResponse(start, fmt.Sprintf("Failed to create request: %v", err)), err
	}

	// Add authentication if configured
	if err := h.addAuthentication(req, config.Authentication); err != nil {
		return h.createErrorResponse(start, fmt.Sprintf("Authentication failed: %v", err)), err
	}

	// Add headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// Set timeout if specified
	if config.Timeout > 0 {
		timeout := time.Duration(config.Timeout) * time.Second
		h.client.Timeout = timeout
	}

	// Configure redirect handling
	if !config.FollowRedirects {
		h.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Execute request with retries
	resp, err := h.executeWithRetries(req, config.RetryAttempts, config.RetryDelay)
	if err != nil {
		return h.createErrorResponse(start, fmt.Sprintf("Request failed: %v", err)), err
	}
	defer resp.Body.Close()

	// Process response
	return h.processResponse(resp, start)
}

// parseConfig parses the node parameters into HTTP configuration
func (h *HTTPExecutor) parseConfig(parameters map[string]interface{}) (*HTTPNodeConfig, error) {
	config := &HTTPNodeConfig{
		Method:          "GET",
		Headers:         make(map[string]string),
		FollowRedirects: true,
		RetryAttempts:   0,
		RetryDelay:      1000,
		Timeout:         30,
	}

	// Parse URL (required)
	if url, ok := parameters["url"].(string); ok && url != "" {
		config.URL = url
	} else {
		return nil, errors.NewValidationError("URL is required")
	}

	// Parse method
	if method, ok := parameters["method"].(string); ok {
		config.Method = strings.ToUpper(method)
	}

	// Parse headers
	if headers, ok := parameters["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				config.Headers[key] = strValue
			}
		}
	}

	// Parse body
	if body, exists := parameters["body"]; exists {
		config.Body = body
	}

	// Parse timeout
	if timeout, ok := parameters["timeout"].(float64); ok {
		config.Timeout = int(timeout)
	}

	// Parse follow redirects
	if followRedirects, ok := parameters["follow_redirects"].(bool); ok {
		config.FollowRedirects = followRedirects
	}

	// Parse retry settings
	if retryAttempts, ok := parameters["retry_attempts"].(float64); ok {
		config.RetryAttempts = int(retryAttempts)
	}

	if retryDelay, ok := parameters["retry_delay"].(float64); ok {
		config.RetryDelay = int(retryDelay)
	}

	// Parse authentication
	if auth, ok := parameters["authentication"].(map[string]interface{}); ok {
		config.Authentication = h.parseAuthentication(auth)
	}

	return config, nil
}

// parseAuthentication parses authentication configuration
func (h *HTTPExecutor) parseAuthentication(auth map[string]interface{}) *HTTPAuth {
	httpAuth := &HTTPAuth{}

	if authType, ok := auth["type"].(string); ok {
		httpAuth.Type = authType
	}

	if token, ok := auth["token"].(string); ok {
		httpAuth.Token = token
	}

	if username, ok := auth["username"].(string); ok {
		httpAuth.Username = username
	}

	if password, ok := auth["password"].(string); ok {
		httpAuth.Password = password
	}

	if apiKey, ok := auth["api_key"].(string); ok {
		httpAuth.APIKey = apiKey
	}

	if header, ok := auth["header"].(string); ok {
		httpAuth.Header = header
	}

	return httpAuth
}

// createRequest creates an HTTP request
func (h *HTTPExecutor) createRequest(ctx context.Context, config *HTTPNodeConfig, inputData interface{}) (*http.Request, error) {
	var body io.Reader

	// Prepare request body
	if config.Body != nil && config.Method != "GET" && config.Method != "HEAD" {
		// If body is a string, use it directly
		if bodyStr, ok := config.Body.(string); ok {
			body = strings.NewReader(bodyStr)
		} else {
			// Otherwise, marshal to JSON
			bodyBytes, err := json.Marshal(config.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			body = bytes.NewReader(bodyBytes)
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, config.Method, config.URL, body)
	if err != nil {
		return nil, err
	}

	// Set default content type for JSON body
	if config.Body != nil && config.Method != "GET" && config.Method != "HEAD" {
		if _, exists := config.Headers["Content-Type"]; !exists {
			if _, ok := config.Body.(string); !ok {
				req.Header.Set("Content-Type", "application/json")
			}
		}
	}

	return req, nil
}

// addAuthentication adds authentication to the request
func (h *HTTPExecutor) addAuthentication(req *http.Request, auth *HTTPAuth) error {
	if auth == nil {
		return nil
	}

	switch auth.Type {
	case "bearer":
		if auth.Token == "" {
			return fmt.Errorf("bearer token is required")
		}
		req.Header.Set("Authorization", "Bearer "+auth.Token)

	case "basic":
		if auth.Username == "" || auth.Password == "" {
			return fmt.Errorf("username and password are required for basic auth")
		}
		req.SetBasicAuth(auth.Username, auth.Password)

	case "api_key":
		if auth.APIKey == "" || auth.Header == "" {
			return fmt.Errorf("API key and header name are required")
		}
		req.Header.Set(auth.Header, auth.APIKey)

	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}

	return nil
}

// executeWithRetries executes the request with retry logic
func (h *HTTPExecutor) executeWithRetries(req *http.Request, maxRetries, retryDelay int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			h.logger.Debug("Retrying HTTP request", "attempt", attempt, "max_retries", maxRetries)
			time.Sleep(time.Duration(retryDelay) * time.Millisecond)
		}

		resp, err := h.client.Do(req)
		if err == nil {
			// Success or non-retryable HTTP status
			if resp.StatusCode < 500 || resp.StatusCode == 501 || resp.StatusCode == 505 {
				return resp, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: %s", resp.Status)
		} else {
			lastErr = err
		}
	}

	return nil, lastErr
}

// processResponse processes the HTTP response
func (h *HTTPExecutor) processResponse(resp *http.Response, startTime time.Time) (interface{}, error) {
	duration := time.Since(startTime)

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return h.createErrorResponse(startTime, fmt.Sprintf("Failed to read response body: %v", err)), err
	}

	// Parse response body
	var bodyData interface{}
	if len(bodyBytes) > 0 {
		// Try to parse as JSON first
		if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
			// If JSON parsing fails, store as string
			bodyData = string(bodyBytes)
		}
	}

	httpResp := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    resp.Header,
		Body:       bodyData,
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		Duration:   duration.Milliseconds(),
		Size:       int64(len(bodyBytes)),
		Timestamp:  time.Now().Unix(),
	}

	h.logger.Debug("HTTP request completed", 
		"status", resp.StatusCode, 
		"duration", duration.Milliseconds(), 
		"size", len(bodyBytes))

	return httpResp, nil
}

// createErrorResponse creates an error response
func (h *HTTPExecutor) createErrorResponse(startTime time.Time, errorMsg string) *HTTPResponse {
	return &HTTPResponse{
		Success:   false,
		Error:     errorMsg,
		Duration:  time.Since(startTime).Milliseconds(),
		Timestamp: time.Now().Unix(),
	}
}