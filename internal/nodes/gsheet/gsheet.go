package gsheet

import (
	"context"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"
)

// GSheetsExecutor implements Google Sheets operations for workflow nodes
type GSheetsExecutor struct {
	logger logger.Logger
}

// GSheetsConfig represents Google Sheets operation configuration
type GSheetsConfig struct {
	Operation        string                 `json:"operation"`          // read, write, append, clear
	SpreadsheetID    string                 `json:"spreadsheet_id"`     // Google Sheets ID
	SheetName        string                 `json:"sheet_name"`         // Sheet name/tab
	Range            string                 `json:"range"`              // A1 notation range
	ValueInputOption string                 `json:"value_input_option"` // RAW or USER_ENTERED
	Data             [][]interface{}        `json:"data"`               // Data to write
	Headers          bool                   `json:"headers"`            // First row contains headers
	Authentication   AuthConfig             `json:"authentication"`     // Auth configuration
	Options          map[string]interface{} `json:"options"`            // Additional options
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type         string `json:"type"`          // oauth2, service_account
	ClientID     string `json:"client_id"`     // OAuth2 client ID
	ClientSecret string `json:"client_secret"` // OAuth2 client secret
	RefreshToken string `json:"refresh_token"` // OAuth2 refresh token
	AccessToken  string `json:"access_token"`  // OAuth2 access token
	ServiceKey   string `json:"service_key"`   // Service account key JSON
}

// GSheetsResponse represents the response from Google Sheets operations
type GSheetsResponse struct {
	Operation     string                   `json:"operation"`
	SpreadsheetID string                   `json:"spreadsheet_id"`
	SheetName     string                   `json:"sheet_name"`
	Range         string                   `json:"range"`
	Data          []map[string]interface{} `json:"data,omitempty"`
	RowsAffected  int                      `json:"rows_affected,omitempty"`
	UpdatedCells  int                      `json:"updated_cells,omitempty"`
	ExecutionTime int64                    `json:"execution_time"` // milliseconds
}

// New creates a new Google Sheets executor
func New(log logger.Logger) *GSheetsExecutor {
	return &GSheetsExecutor{
		logger: log,
	}
}

// Execute performs the Google Sheets operation
func (e *GSheetsExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	startTime := time.Now()

	// Parse configuration
	config, err := e.parseConfig(parameters)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Invalid Google Sheets configuration: %v", err))
	}

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return nil, err
	}

	e.logger.Info("Executing Google Sheets operation",
		"operation", config.Operation,
		"spreadsheet_id", config.SpreadsheetID,
		"sheet_name", config.SheetName,
		"range", config.Range,
	)

	// Execute operation
	response, err := e.executeOperation(ctx, config, inputData)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Google Sheets operation failed: %v", err))
	}

	response.ExecutionTime = time.Since(startTime).Milliseconds()

	e.logger.Info("Google Sheets operation completed",
		"operation", config.Operation,
		"rows_affected", response.RowsAffected,
		"execution_time_ms", response.ExecutionTime,
	)

	return response, nil
}

// Validate validates the Google Sheets node parameters
func (e *GSheetsExecutor) Validate(parameters map[string]interface{}) error {
	config, err := e.parseConfig(parameters)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid configuration: %v", err))
	}

	return e.validateConfig(config)
}

// GetDefinition returns the node definition
func (e *GSheetsExecutor) GetDefinition() *nodes.NodeDefinition {
	return &nodes.NodeDefinition{
		Name:        "n8n-nodes-base.googleSheets",
		DisplayName: "Google Sheets",
		Description: "Read and write data to Google Sheets",
		Version:     "2.0.0",
		Type:        nodes.NodeTypeAction,
		Category:    nodes.CategoryIntegration,
		Status:      nodes.NodeStatusStable,
		Icon:        "file:googlesheets.svg",
		Color:       "#34A853",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"sheet_name\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"google", "sheets", "spreadsheet", "data", "productivity"},
		Parameters: []nodes.Parameter{
			{
				Name:        "operation",
				DisplayName: "Operation",
				Type:        nodes.ParameterTypeOptions,
				Description: "Operation to perform on the Google Sheet",
				Required:    true,
				Default:     "read",
				Options: []nodes.Option{
					{Value: "read", Label: "Read", Description: "Read data from sheet"},
					{Value: "write", Label: "Write", Description: "Write data to sheet"},
					{Value: "append", Label: "Append", Description: "Append data to sheet"},
					{Value: "clear", Label: "Clear", Description: "Clear sheet data"},
				},
			},
			{
				Name:        "spreadsheet_id",
				DisplayName: "Spreadsheet ID",
				Type:        nodes.ParameterTypeString,
				Description: "The ID of the Google Spreadsheet",
				Required:    true,
				Placeholder: "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
			},
			{
				Name:        "sheet_name",
				DisplayName: "Sheet Name",
				Type:        nodes.ParameterTypeString,
				Description: "Name of the sheet/tab within the spreadsheet",
				Default:     "Sheet1",
			},
			{
				Name:        "range",
				DisplayName: "Range",
				Type:        nodes.ParameterTypeString,
				Description: "A1 notation range (e.g., A1:E10)",
				Default:     "A:Z",
				ShowIf:      "operation=read",
			},
			{
				Name:        "headers",
				DisplayName: "Headers in First Row",
				Type:        nodes.ParameterTypeBoolean,
				Description: "Whether the first row contains headers",
				Default:     true,
			},
			{
				Name:        "value_input_option",
				DisplayName: "Value Input Option",
				Type:        nodes.ParameterTypeOptions,
				Description: "How input data should be interpreted",
				Default:     "USER_ENTERED",
				ShowIf:      "operation!=read",
				Options: []nodes.Option{
					{Value: "RAW", Label: "Raw", Description: "Values will not be parsed"},
					{Value: "USER_ENTERED", Label: "User Entered", Description: "Values will be parsed as if entered via UI"},
				},
			},
			{
				Name:        "data",
				DisplayName: "Data",
				Type:        nodes.ParameterTypeArray,
				Description: "Data to write to the sheet",
				ShowIf:      "operation=write||operation=append",
			},
			{
				Name:        "authentication",
				DisplayName: "Authentication",
				Type:        nodes.ParameterTypeOptions,
				Description: "Authentication method",
				Required:    true,
				Default:     "oauth2",
				Options: []nodes.Option{
					{Value: "oauth2", Label: "OAuth2", Description: "Use OAuth2 authentication"},
					{Value: "service_account", Label: "Service Account", Description: "Use service account key"},
				},
			},
			{
				Name:        "client_id",
				DisplayName: "Client ID",
				Type:        nodes.ParameterTypeString,
				Description: "OAuth2 Client ID",
				ShowIf:      "authentication=oauth2",
			},
			{
				Name:        "client_secret",
				DisplayName: "Client Secret",
				Type:        nodes.ParameterTypeString,
				Description: "OAuth2 Client Secret",
				ShowIf:      "authentication=oauth2",
			},
			{
				Name:        "refresh_token",
				DisplayName: "Refresh Token",
				Type:        nodes.ParameterTypeString,
				Description: "OAuth2 Refresh Token",
				ShowIf:      "authentication=oauth2",
			},
			{
				Name:        "service_key",
				DisplayName: "Service Account Key",
				Type:        nodes.ParameterTypeCode,
				Description: "Service account key in JSON format",
				ShowIf:      "authentication=service_account",
			},
		},
		Inputs: []nodes.NodeInput{
			{Name: "main", DisplayName: "Main", Type: "main", Required: false, MaxConnections: 1},
		},
		Outputs: []nodes.NodeOutput{
			{Name: "main", DisplayName: "Main", Type: "main", Description: "Google Sheets operation results"},
		},
		Credentials:      []string{"googleSheetsOAuth2", "googleSheetsServiceAccount"},
		RetryOnFail:      2,
		ContinueOnFail:   false,
		AlwaysOutputData: false,
		MaxExecutionTime: 2 * time.Minute,
		DocumentationURL: "https://docs.n8n.io/nodes/n8n-nodes-base.googleSheets/",
		Examples: []nodes.NodeExample{
			{
				Name:        "Read sheet data",
				Description: "Read all data from a Google Sheet",
				Parameters: map[string]interface{}{
					"operation":      "read",
					"spreadsheet_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
					"sheet_name":     "Sheet1",
					"range":          "A:D",
					"headers":        true,
				},
			},
			{
				Name:        "Append data",
				Description: "Append new rows to a Google Sheet",
				Parameters: map[string]interface{}{
					"operation":      "append",
					"spreadsheet_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
					"sheet_name":     "Sheet1",
					"data": [][]interface{}{
						{"John Doe", "john@example.com", "Manager"},
						{"Jane Smith", "jane@example.com", "Developer"},
					},
				},
			},
		},
		Dependencies: []string{},
		Author:       "n8n Team",
		License:      "MIT",
	}
}

// parseConfig parses parameters into GSheetsConfig
func (e *GSheetsExecutor) parseConfig(parameters map[string]interface{}) (*GSheetsConfig, error) {
	config := &GSheetsConfig{
		Operation:        "read",
		SheetName:        "Sheet1",
		Range:            "A:Z",
		ValueInputOption: "USER_ENTERED",
		Headers:          true,
		Authentication:   AuthConfig{Type: "oauth2"},
		Options:          make(map[string]interface{}),
	}

	if operation, ok := parameters["operation"].(string); ok {
		config.Operation = operation
	}

	if spreadsheetID, ok := parameters["spreadsheet_id"].(string); ok {
		config.SpreadsheetID = spreadsheetID
	}

	if sheetName, ok := parameters["sheet_name"].(string); ok {
		config.SheetName = sheetName
	}

	if rangeVal, ok := parameters["range"].(string); ok {
		config.Range = rangeVal
	}

	if valueInputOption, ok := parameters["value_input_option"].(string); ok {
		config.ValueInputOption = valueInputOption
	}

	if headers, ok := parameters["headers"].(bool); ok {
		config.Headers = headers
	}

	if data, ok := parameters["data"].([][]interface{}); ok {
		config.Data = data
	}

	// Parse authentication
	if auth, ok := parameters["authentication"].(string); ok {
		config.Authentication.Type = auth
	}

	if clientID, ok := parameters["client_id"].(string); ok {
		config.Authentication.ClientID = clientID
	}

	if clientSecret, ok := parameters["client_secret"].(string); ok {
		config.Authentication.ClientSecret = clientSecret
	}

	if refreshToken, ok := parameters["refresh_token"].(string); ok {
		config.Authentication.RefreshToken = refreshToken
	}

	if serviceKey, ok := parameters["service_key"].(string); ok {
		config.Authentication.ServiceKey = serviceKey
	}

	return config, nil
}

// validateConfig validates the Google Sheets configuration
func (e *GSheetsExecutor) validateConfig(config *GSheetsConfig) error {
	if config.SpreadsheetID == "" {
		return errors.NewValidationError("Spreadsheet ID is required")
	}

	validOperations := map[string]bool{
		"read": true, "write": true, "append": true, "clear": true,
	}

	if !validOperations[config.Operation] {
		return errors.NewValidationError(fmt.Sprintf("Invalid operation: %s", config.Operation))
	}

	if config.Operation == "write" || config.Operation == "append" {
		if len(config.Data) == 0 {
			return errors.NewValidationError("Data is required for write/append operations")
		}
	}

	// Validate authentication
	switch config.Authentication.Type {
	case "oauth2":
		if config.Authentication.RefreshToken == "" {
			return errors.NewValidationError("Refresh token is required for OAuth2 authentication")
		}
	case "service_account":
		if config.Authentication.ServiceKey == "" {
			return errors.NewValidationError("Service account key is required for service account authentication")
		}
	default:
		return errors.NewValidationError("Invalid authentication type")
	}

	return nil
}

// executeOperation executes the Google Sheets operation
func (e *GSheetsExecutor) executeOperation(ctx context.Context, config *GSheetsConfig, inputData interface{}) (*GSheetsResponse, error) {
	switch config.Operation {
	case "read":
		return e.executeRead(ctx, config)
	case "write":
		return e.executeWrite(ctx, config)
	case "append":
		return e.executeAppend(ctx, config)
	case "clear":
		return e.executeClear(ctx, config)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", config.Operation)
	}
}

// executeRead executes a read operation
func (e *GSheetsExecutor) executeRead(ctx context.Context, config *GSheetsConfig) (*GSheetsResponse, error) {
	// In a real implementation, this would call Google Sheets API
	// For now, return mock data
	mockData := []map[string]interface{}{
		{"Name": "John Doe", "Email": "john@example.com", "Role": "Manager"},
		{"Name": "Jane Smith", "Email": "jane@example.com", "Role": "Developer"},
		{"Name": "Bob Wilson", "Email": "bob@example.com", "Role": "Designer"},
	}

	e.logger.Info("Mock Google Sheets read operation", "rows", len(mockData))

	return &GSheetsResponse{
		Operation:     "read",
		SpreadsheetID: config.SpreadsheetID,
		SheetName:     config.SheetName,
		Range:         config.Range,
		Data:          mockData,
	}, nil
}

// executeWrite executes a write operation
func (e *GSheetsExecutor) executeWrite(ctx context.Context, config *GSheetsConfig) (*GSheetsResponse, error) {
	// In a real implementation, this would call Google Sheets API
	rowsAffected := len(config.Data)
	updatedCells := 0
	for _, row := range config.Data {
		updatedCells += len(row)
	}

	e.logger.Info("Mock Google Sheets write operation",
		"rows_affected", rowsAffected,
		"updated_cells", updatedCells)

	return &GSheetsResponse{
		Operation:     "write",
		SpreadsheetID: config.SpreadsheetID,
		SheetName:     config.SheetName,
		Range:         config.Range,
		RowsAffected:  rowsAffected,
		UpdatedCells:  updatedCells,
	}, nil
}

// executeAppend executes an append operation
func (e *GSheetsExecutor) executeAppend(ctx context.Context, config *GSheetsConfig) (*GSheetsResponse, error) {
	// In a real implementation, this would call Google Sheets API
	rowsAffected := len(config.Data)
	updatedCells := 0
	for _, row := range config.Data {
		updatedCells += len(row)
	}

	e.logger.Info("Mock Google Sheets append operation",
		"rows_affected", rowsAffected,
		"updated_cells", updatedCells)

	return &GSheetsResponse{
		Operation:     "append",
		SpreadsheetID: config.SpreadsheetID,
		SheetName:     config.SheetName,
		RowsAffected:  rowsAffected,
		UpdatedCells:  updatedCells,
	}, nil
}

// executeClear executes a clear operation
func (e *GSheetsExecutor) executeClear(ctx context.Context, config *GSheetsConfig) (*GSheetsResponse, error) {
	// In a real implementation, this would call Google Sheets API
	e.logger.Info("Mock Google Sheets clear operation")

	return &GSheetsResponse{
		Operation:     "clear",
		SpreadsheetID: config.SpreadsheetID,
		SheetName:     config.SheetName,
		Range:         config.Range,
		RowsAffected:  1, // Mock: assume some rows were cleared
	}, nil
}

// buildFullRange builds the full range including sheet name
func (e *GSheetsExecutor) buildFullRange(sheetName, rangeNotation string) string {
	if strings.Contains(rangeNotation, "!") {
		return rangeNotation
	}
	return fmt.Sprintf("'%s'!%s", sheetName, rangeNotation)
}

// convertToA1Notation converts row/col numbers to A1 notation
func (e *GSheetsExecutor) convertToA1Notation(row, col int) string {
	columnName := ""
	for col > 0 {
		col-- // Convert to 0-based
		columnName = string(rune('A'+col%26)) + columnName
		col /= 26
	}
	return fmt.Sprintf("%s%d", columnName, row)
}

// parseA1Notation parses A1 notation to row/col numbers
func (e *GSheetsExecutor) parseA1Notation(a1 string) (int, int, error) {
	// Simple implementation - in production would be more robust
	var col, row int
	var colStr, rowStr string

	for i, char := range a1 {
		if char >= '0' && char <= '9' {
			colStr = a1[:i]
			rowStr = a1[i:]
			break
		}
	}

	// Convert column letters to number
	for _, char := range colStr {
		col = col*26 + int(char-'A') + 1
	}

	// Convert row string to number
	fmt.Sscanf(rowStr, "%d", &row)

	return row, col, nil
}
