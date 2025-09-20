package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// HTTPExecutor implements HTTP request functionality
type HTTPExecutor struct {
	logger     logger.Logger
	httpClient *http.Client
}

// HTTPConfig represents configuration for HTTP requests
type HTTPConfig struct {
	URL                string                 `json:"url"`
	Method             string                 `json:"method"`
	Headers            map[string]string      `json:"headers"`
	QueryParameters    map[string]string      `json:"query_parameters"`
	Body               interface{}            `json:"body"`
	BodyContentType    string                 `json:"body_content_type"`
	Authentication     AuthConfig             `json:"authentication"`
	Timeout            int                    `json:"timeout"` // seconds
	FollowRedirects    bool                   `json:"follow_redirects"`
	IgnoreSSLIssues    bool                   `json:"ignore_ssl_issues"`
	ResponseFormat     string                 `json:"response_format"`
	BinaryPropertyName string                 `json:"binary_property_name"`
	FullResponse       bool                   `json:"full_response"`
	ProxyURL           string                 `json:"proxy_url"`
	AdditionalOptions  map[string]interface{} `json:"additional_options"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type             string            `json:"type"`
	Username         string            `json:"username"`
	Password         string            `json:"password"`
	Token            string            `json:"token"`
	APIKey           string            `json:"api_key"`
	APIKeyLocation   string            `json:"api_key_location"` // header, query
	APIKeyName       string            `json:"api_key_name"`
	BearerToken      string            `json:"bearer_token"`
	CustomHeaders    map[string]string `json:"custom_headers"`
	OAuth2Token      string            `json:"oauth2_token"`
	ClientCert       string            `json:"client_cert"`
	ClientKey        string            `json:"client_key"`
	CredentialID     string            `json:"credential_id"`
	AdditionalFields map[string]string `json:"additional_fields"`
}

// HTTPResponse represents the response from an HTTP request
type HTTPResponse struct {
	StatusCode int                    `json:"statusCode"`
	StatusText string                 `json:"statusText"`
	Headers    map[string]interface{} `json:"headers"`
	Body       interface{}            `json:"body"`
	Data       interface{}            `json:"data"`
	Binary     []byte                 `json:"binary,omitempty"`
	URL        string                 `json:"url"`
	Method     string                 `json:"method"`
	Duration   int64                  `json:"duration"` // milliseconds
	Size       int64                  `json:"size"`
}

// New creates a new HTTP executor
func New(log logger.Logger) *HTTPExecutor {
	return &HTTPExecutor{
		logger: log,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

// Execute performs the HTTP request
func (e *HTTPExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	startTime := time.Now()

	// Parse configuration from parameters
	config, err := e.parseConfig(parameters)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Invalid HTTP configuration: %v", err))
	}

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return nil, err
	}

	e.logger.Info("Executing HTTP request",
		"method", config.Method,
		"url", config.URL,
		"timeout", config.Timeout,
	)

	// Create HTTP request
	req, err := e.createRequest(ctx, config, inputData)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Failed to create HTTP request: %v", err))
	}

	// Apply authentication
	if err := e.applyAuthentication(req, &config.Authentication); err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Failed to apply authentication: %v", err))
	}

	// Configure HTTP client
	client := e.configureClient(config)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		e.logger.Error("HTTP request failed", "error", err, "url", config.URL)
		return nil, errors.NewNetworkError(fmt.Sprintf("HTTP request failed: %v", err))
	}
	defer resp.Body.Close()

	// Process response
	response, err := e.processResponse(resp, config, startTime)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Failed to process response: %v", err))
	}

	e.logger.Info("HTTP request completed",
		"status_code", response.StatusCode,
		"duration_ms", response.Duration,
		"response_size", response.Size,
	)

	return response, nil
}

// Validate validates the HTTP node parameters
func (e *HTTPExecutor) Validate(parameters map[string]interface{}) error {
	config, err := e.parseConfig(parameters)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid configuration: %v", err))
	}

	return e.validateConfig(config)
}

// GetDefinition returns the node definition
func (e *HTTPExecutor) GetDefinition() *nodes.NodeDefinition {
	return &nodes.NodeDefinition{
		Name:        "n8n-nodes-base.httpRequest",
		DisplayName: "HTTP Request",
		Description: "Makes HTTP requests and returns the response data",
		Version:     "2.0.0",
		Type:        nodes.NodeTypeHTTP,
		Category:    nodes.CategoryCore,
		Status:      nodes.NodeStatusStable,
		Icon:        "fa:globe",
		Color:       "#2196F3",
		Subtitle:    "={{$parameter[\"method\"]}} {{$parameter[\"url\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"http", "api", "request", "web", "rest", "webhook"},
		Parameters: []nodes.Parameter{
			{
				Name:        "url",
				DisplayName: "URL",
				Type:        nodes.ParameterTypeString,
				Description: "The URL to make the request to",
				Required:    true,
				Placeholder: "https://api.example.com/data",
			},
			{
				Name:        "method",
				DisplayName: "Method",
				Type:        nodes.ParameterTypeOptions,
				Description: "HTTP method to use for the request",
				Required:    true,
				Default:     "GET",
				Options: []nodes.Option{
					{Value: "GET", Label: "GET", Description: "Retrieve data from the server"},
					{Value: "POST", Label: "POST", Description: "Send data to the server"},
					{Value: "PUT", Label: "PUT", Description: "Update data on the server"},
					{Value: "DELETE", Label: "DELETE", Description: "Delete data from the server"},
					{Value: "PATCH", Label: "PATCH", Description: "Partially update data on the server"},
					{Value: "HEAD", Label: "HEAD", Description: "Get headers only"},
					{Value: "OPTIONS", Label: "OPTIONS", Description: "Get allowed methods"},
				},
			},
			{
				Name:        "authentication",
				DisplayName: "Authentication",
				Type:        nodes.ParameterTypeOptions,
				Description: "Authentication method to use",
				Default:     "none",
				Options: []nodes.Option{
					{Value: "none", Label: "None"},
					{Value: "basic", Label: "Basic Auth"},
					{Value: "bearer", Label: "Bearer Token"},
					{Value: "api_key", Label: "API Key"},
					{Value: "oauth2", Label: "OAuth2"},
					{Value: "credential", Label: "Predefined Credential"},
				},
			},
			{
				Name:        "username",
				DisplayName: "Username",
				Type:        nodes.ParameterTypeString,
				Description: "Username for basic authentication",
				ShowIf:      "authentication=basic",
			},
			{
				Name:        "password",
				DisplayName: "Password",
				Type:        nodes.ParameterTypeString,
				Description: "Password for basic authentication",
				ShowIf:      "authentication=basic",
			},
			{
				Name:        "bearer_token",
				DisplayName: "Bearer Token",
				Type:        nodes.ParameterTypeString,
				Description: "Bearer token for authorization",
				ShowIf:      "authentication=bearer",
			},
			{
				Name:        "api_key",
				DisplayName: "API Key",
				Type:        nodes.ParameterTypeString,
				Description: "API key for authentication",
				ShowIf:      "authentication=api_key",
			},
			{
				Name:        "api_key_location",
				DisplayName: "API Key Location",
				Type:        nodes.ParameterTypeOptions,
				Description: "Where to send the API key",
				Default:     "header",
				ShowIf:      "authentication=api_key",
				Options: []nodes.Option{
					{Value: "header", Label: "Header"},
					{Value: "query", Label: "Query Parameter"},
				},
			},
			{
				Name:        "api_key_name",
				DisplayName: "API Key Name",
				Type:        nodes.ParameterTypeString,
				Description: "Name of the header/query parameter for the API key",
				Default:     "X-API-Key",
				ShowIf:      "authentication=api_key",
			},
			{
				Name:        "headers",
				DisplayName: "Headers",
				Type:        nodes.ParameterTypeObject,
				Description: "HTTP headers to send with the request",
				Placeholder: `{"Content-Type": "application/json"}`,
			},
			{
				Name:        "query_parameters",
				DisplayName: "Query Parameters",
				Type:        nodes.ParameterTypeObject,
				Description: "Query parameters to add to the URL",
				Placeholder: `{"param1": "value1", "param2": "value2"}`,
			},
			{
				Name:        "body",
				DisplayName: "Body",
				Type:        nodes.ParameterTypeCode,
				Description: "Request body content",
				ShowIf:      "method!=GET&method!=HEAD&method!=OPTIONS",
			},
			{
				Name:        "body_content_type",
				DisplayName: "Body Content Type",
				Type:        nodes.ParameterTypeOptions,
				Description: "Content type of the request body",
				Default:     "json",
				ShowIf:      "method!=GET&method!=HEAD&method!=OPTIONS",
				Options: []nodes.Option{
					{Value: "json", Label: "JSON"},
					{Value: "form", Label: "Form URL Encoded"},
					{Value: "multipart", Label: "Multipart Form Data"},
					{Value: "text", Label: "Plain Text"},
					{Value: "xml", Label: "XML"},
					{Value: "binary", Label: "Binary"},
				},
			},
			{
				Name:        "timeout",
				DisplayName: "Timeout (seconds)",
				Type:        nodes.ParameterTypeNumber,
				Description: "Request timeout in seconds",
				Default:     30,
				Validation: &nodes.Validation{
					Min: func() *float64 { f := 1.0; return &f }(),
					Max: func() *float64 { f := 300.0; return &f }(),
				},
			},
			{
				Name:        "follow_redirects",
				DisplayName: "Follow Redirects",
				Type:        nodes.ParameterTypeBoolean,
				Description: "Whether to follow HTTP redirects",
				Default:     true,
			},
			{
				Name:        "ignore_ssl_issues",
				DisplayName: "Ignore SSL Issues",
				Type:        nodes.ParameterTypeBoolean,
				Description: "Ignore SSL certificate issues",
				Default:     false,
			},
			{
				Name:        "response_format",
				DisplayName: "Response Format",
				Type:        nodes.ParameterTypeOptions,
				Description: "How to parse the response",
				Default:     "autodetect",
				Options: []nodes.Option{
					{Value: "autodetect", Label: "Auto-detect"},
					{Value: "json", Label: "JSON"},
					{Value: "text", Label: "Text"},
					{Value: "binary", Label: "Binary"},
					{Value: "xml", Label: "XML"},
				},
			},
			{
				Name:        "full_response",
				DisplayName: "Full Response",
				Type:        nodes.ParameterTypeBoolean,
				Description: "Return full response including headers and status",
				Default:     false,
			},
		},
		Inputs: []nodes.NodeInput{
			{Name: "main", DisplayName: "Main", Type: "main", Required: false, MaxConnections: 1},
		},
		Outputs: []nodes.NodeOutput{
			{Name: "main", DisplayName: "Main", Type: "main", Description: "HTTP response data"},
		},
		RetryOnFail:      2,
		ContinueOnFail:   false,
		AlwaysOutputData: false,
		MaxExecutionTime: 5 * time.Minute,
		DocumentationURL: "https://docs.n8n.io/nodes/n8n-nodes-base.httpRequest/",
		Examples: []nodes.NodeExample{
			{
				Name:        "Simple GET request",
				Description: "Make a GET request to retrieve data",
				Parameters: map[string]interface{}{
					"url":    "https://jsonplaceholder.typicode.com/posts/1",
					"method": "GET",
				},
			},
			{
				Name:        "POST with JSON data",
				Description: "Send JSON data via POST request",
				Parameters: map[string]interface{}{
					"url":               "https://jsonplaceholder.typicode.com/posts",
					"method":            "POST",
					"body_content_type": "json",
					"body":              `{"title": "New Post", "body": "Post content", "userId": 1}`,
					"headers":           map[string]string{"Content-Type": "application/json"},
				},
			},
		},
		Dependencies: []string{},
		Author:       "n8n Team",
		License:      "MIT",
	}
}

// parseConfig parses the node parameters into an HTTPConfig
func (e *HTTPExecutor) parseConfig(parameters map[string]interface{}) (*HTTPConfig, error) {
	config := &HTTPConfig{
		Method:          "GET",
		Headers:         make(map[string]string),
		QueryParameters: make(map[string]string),
		Authentication:  AuthConfig{Type: "none"},
		Timeout:         30,
		FollowRedirects: true,
		ResponseFormat:  "autodetect",
		FullResponse:    false,
	}

	// Parse URL
	if url, ok := parameters["url"].(string); ok {
		config.URL = url
	}

	// Parse method
	if method, ok := parameters["method"].(string); ok {
		config.Method = strings.ToUpper(method)
	}

	// Parse headers
	if headers, ok := parameters["headers"]; ok {
		if headersMap, ok := headers.(map[string]interface{}); ok {
			for k, v := range headersMap {
				if str, ok := v.(string); ok {
					config.Headers[k] = str
				}
			}
		}
	}

	// Parse query parameters
	if queryParams, ok := parameters["query_parameters"]; ok {
		if queryMap, ok := queryParams.(map[string]interface{}); ok {
			for k, v := range queryMap {
				if str, ok := v.(string); ok {
					config.QueryParameters[k] = str
				}
			}
		}
	}

	// Parse body
	if body, ok := parameters["body"]; ok {
		config.Body = body
	}

	// Parse body content type
	if bodyContentType, ok := parameters["body_content_type"].(string); ok {
		config.BodyContentType = bodyContentType
	}

	// Parse authentication
	if auth, ok := parameters["authentication"].(string); ok {
		config.Authentication.Type = auth

		switch auth {
		case "basic":
			if username, ok := parameters["username"].(string); ok {
				config.Authentication.Username = username
			}
			if password, ok := parameters["password"].(string); ok {
				config.Authentication.Password = password
			}
		case "bearer":
			if token, ok := parameters["bearer_token"].(string); ok {
				config.Authentication.BearerToken = token
			}
		case "api_key":
			if apiKey, ok := parameters["api_key"].(string); ok {
				config.Authentication.APIKey = apiKey
			}
			if location, ok := parameters["api_key_location"].(string); ok {
				config.Authentication.APIKeyLocation = location
			} else {
				config.Authentication.APIKeyLocation = "header"
			}
			if name, ok := parameters["api_key_name"].(string); ok {
				config.Authentication.APIKeyName = name
			} else {
				config.Authentication.APIKeyName = "X-API-Key"
			}
		}
	}

	// Parse timeout
	if timeout, ok := parameters["timeout"]; ok {
		switch t := timeout.(type) {
		case int:
			config.Timeout = t
		case float64:
			config.Timeout = int(t)
		}
	}

	// Parse follow redirects
	if followRedirects, ok := parameters["follow_redirects"].(bool); ok {
		config.FollowRedirects = followRedirects
	}

	// Parse ignore SSL issues
	if ignoreSSL, ok := parameters["ignore_ssl_issues"].(bool); ok {
		config.IgnoreSSLIssues = ignoreSSL
	}

	// Parse response format
	if responseFormat, ok := parameters["response_format"].(string); ok {
		config.ResponseFormat = responseFormat
	}

	// Parse full response
	if fullResponse, ok := parameters["full_response"].(bool); ok {
		config.FullResponse = fullResponse
	}

	return config, nil
}

// validateConfig validates the HTTP configuration
func (e *HTTPExecutor) validateConfig(config *HTTPConfig) error {
	if config.URL == "" {
		return errors.NewValidationError("URL is required")
	}

	if _, err := url.Parse(config.URL); err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid URL: %v", err))
	}

	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}

	if !validMethods[config.Method] {
		return errors.NewValidationError(fmt.Sprintf("Invalid HTTP method: %s", config.Method))
	}

	if config.Timeout <= 0 || config.Timeout > 300 {
		return errors.NewValidationError("Timeout must be between 1 and 300 seconds")
	}

	return nil
}

// createRequest creates an HTTP request from the configuration
func (e *HTTPExecutor) createRequest(ctx context.Context, config *HTTPConfig, inputData interface{}) (*http.Request, error) {
	// Build URL with query parameters
	reqURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Add query parameters
	query := reqURL.Query()
	for key, value := range config.QueryParameters {
		query.Add(key, value)
	}
	reqURL.RawQuery = query.Encode()

	// Prepare request body
	var bodyReader io.Reader
	if config.Body != nil && (config.Method == "POST" || config.Method == "PUT" || config.Method == "PATCH") {
		bodyData, err := e.prepareRequestBody(config.Body, config.BodyContentType)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, config.Method, reqURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// Set content type based on body type
	if config.Body != nil && req.Header.Get("Content-Type") == "" {
		switch config.BodyContentType {
		case "json":
			req.Header.Set("Content-Type", "application/json")
		case "form":
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		case "xml":
			req.Header.Set("Content-Type", "application/xml")
		case "text":
			req.Header.Set("Content-Type", "text/plain")
		}
	}

	// Set user agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "n8n-pro/1.0")
	}

	return req, nil
}

// prepareRequestBody prepares the request body based on content type
func (e *HTTPExecutor) prepareRequestBody(body interface{}, contentType string) ([]byte, error) {
	switch contentType {
	case "json":
		if str, ok := body.(string); ok {
			return []byte(str), nil
		}
		return json.Marshal(body)
	case "form":
		if data, ok := body.(map[string]interface{}); ok {
			values := url.Values{}
			for key, value := range data {
				values.Add(key, fmt.Sprintf("%v", value))
			}
			return []byte(values.Encode()), nil
		}
		if str, ok := body.(string); ok {
			return []byte(str), nil
		}
	case "text", "xml":
		return []byte(fmt.Sprintf("%v", body)), nil
	case "binary":
		if data, ok := body.([]byte); ok {
			return data, nil
		}
		return []byte(fmt.Sprintf("%v", body)), nil
	}

	// Default: convert to JSON
	if str, ok := body.(string); ok {
		return []byte(str), nil
	}
	return json.Marshal(body)
}

// applyAuthentication applies authentication to the request
func (e *HTTPExecutor) applyAuthentication(req *http.Request, auth *AuthConfig) error {
	switch auth.Type {
	case "none":
		return nil
	case "basic":
		if auth.Username != "" {
			req.SetBasicAuth(auth.Username, auth.Password)
		}
	case "bearer":
		if auth.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+auth.BearerToken)
		}
	case "api_key":
		if auth.APIKey != "" {
			if auth.APIKeyLocation == "header" {
				req.Header.Set(auth.APIKeyName, auth.APIKey)
			} else if auth.APIKeyLocation == "query" {
				q := req.URL.Query()
				q.Add(auth.APIKeyName, auth.APIKey)
				req.URL.RawQuery = q.Encode()
			}
		}
	}

	// Apply custom headers
	for key, value := range auth.CustomHeaders {
		req.Header.Set(key, value)
	}

	return nil
}

// configureClient configures the HTTP client based on the configuration
func (e *HTTPExecutor) configureClient(config *HTTPConfig) *http.Client {
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// Configure redirect policy
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Configure TLS settings
	if config.IgnoreSSLIssues {
		// In a real implementation, you would configure TLS settings here
		e.logger.Warn("SSL issues ignored - not recommended for production")
	}

	return client
}

// processResponse processes the HTTP response
func (e *HTTPExecutor) processResponse(resp *http.Response, config *HTTPConfig, startTime time.Time) (*HTTPResponse, error) {
	duration := time.Since(startTime).Milliseconds()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Process headers
	headers := make(map[string]interface{})
	for key, values := range resp.Header {
		if len(values) == 1 {
			headers[key] = values[0]
		} else {
			headers[key] = values
		}
	}

	response := &HTTPResponse{
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Headers:    headers,
		URL:        resp.Request.URL.String(),
		Method:     resp.Request.Method,
		Duration:   duration,
		Size:       int64(len(bodyBytes)),
	}

	// Process body based on response format
	var bodyData interface{}

	if config.ResponseFormat == "binary" {
		response.Binary = bodyBytes
		bodyData = bodyBytes
	} else {
		// Auto-detect content type if needed
		contentType := resp.Header.Get("Content-Type")
		format := config.ResponseFormat

		if format == "autodetect" {
			if strings.Contains(contentType, "application/json") {
				format = "json"
			} else if strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
				format = "xml"
			} else {
				format = "text"
			}
		}

		switch format {
		case "json":
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
					// If JSON parsing fails, return as text
					bodyData = string(bodyBytes)
				}
			}
		default:
			bodyData = string(bodyBytes)
		}
	}

	response.Body = bodyData
	response.Data = bodyData

	// Return appropriate response format
	if config.FullResponse {
		return response, nil
	}

	// Return simplified response (just the data)
	return &HTTPResponse{
		StatusCode: response.StatusCode,
		Body:       bodyData,
		Data:       bodyData,
	}, nil
}
