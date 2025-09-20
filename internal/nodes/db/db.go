package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"n8n-pro/internal/nodes"
	"n8n-pro/pkg/errors"
	"n8n-pro/pkg/logger"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DBExecutor implements database operations for workflow nodes
type DBExecutor struct {
	logger logger.Logger
}

// DBConfig represents database connection configuration
type DBConfig struct {
	Type       string                 `json:"type"` // postgres, mysql, sqlite
	Host       string                 `json:"host"`
	Port       int                    `json:"port"`
	Database   string                 `json:"database"`
	Username   string                 `json:"username"`
	Password   string                 `json:"password"`
	SSLMode    string                 `json:"ssl_mode"`
	Operation  string                 `json:"operation"`  // select, insert, update, delete
	Query      string                 `json:"query"`      // SQL query
	Table      string                 `json:"table"`      // table name for operations
	Values     map[string]interface{} `json:"values"`     // values for insert/update
	Conditions map[string]interface{} `json:"conditions"` // where conditions
	Limit      int                    `json:"limit"`
	Timeout    int                    `json:"timeout"` // connection timeout in seconds
}

// DBResponse represents the response from database operations
type DBResponse struct {
	Rows          []map[string]interface{} `json:"rows,omitempty"`
	RowsAffected  int64                    `json:"rows_affected,omitempty"`
	LastInsertID  int64                    `json:"last_insert_id,omitempty"`
	Operation     string                   `json:"operation"`
	ExecutionTime int64                    `json:"execution_time"` // milliseconds
}

// New creates a new database executor
func New(log logger.Logger) *DBExecutor {
	return &DBExecutor{
		logger: log,
	}
}

// Execute performs the database operation
func (e *DBExecutor) Execute(ctx context.Context, parameters map[string]interface{}, inputData interface{}) (interface{}, error) {
	startTime := time.Now()

	// Parse configuration
	config, err := e.parseConfig(parameters)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Invalid database configuration: %v", err))
	}

	// Validate configuration
	if err := e.validateConfig(config); err != nil {
		return nil, err
	}

	e.logger.Info("Executing database operation",
		"operation", config.Operation,
		"type", config.Type,
		"database", config.Database,
	)

	// Create database connection
	db, err := e.createConnection(config)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Failed to connect to database: %v", err))
	}
	defer db.Close()

	// Execute operation
	response, err := e.executeOperation(ctx, db, config)
	if err != nil {
		return nil, errors.NewExecutionError(fmt.Sprintf("Database operation failed: %v", err))
	}

	response.ExecutionTime = time.Since(startTime).Milliseconds()

	e.logger.Info("Database operation completed",
		"operation", config.Operation,
		"rows_affected", response.RowsAffected,
		"execution_time_ms", response.ExecutionTime,
	)

	return response, nil
}

// Validate validates the database node parameters
func (e *DBExecutor) Validate(parameters map[string]interface{}) error {
	config, err := e.parseConfig(parameters)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid configuration: %v", err))
	}

	return e.validateConfig(config)
}

// GetDefinition returns the node definition
func (e *DBExecutor) GetDefinition() *nodes.NodeDefinition {
	return &nodes.NodeDefinition{
		Name:        "n8n-nodes-base.database",
		DisplayName: "Database",
		Description: "Execute SQL queries against databases",
		Version:     "1.0.0",
		Type:        nodes.NodeTypeDatabase,
		Category:    nodes.CategoryDatabase,
		Status:      nodes.NodeStatusStable,
		Icon:        "fa:database",
		Color:       "#336791",
		Subtitle:    "={{$parameter[\"operation\"]}} {{$parameter[\"database\"]}}",
		Group:       []string{"input", "output"},
		Tags:        []string{"database", "sql", "postgres", "mysql", "data"},
		Parameters: []nodes.Parameter{
			{
				Name:        "type",
				DisplayName: "Database Type",
				Type:        nodes.ParameterTypeOptions,
				Description: "Type of database to connect to",
				Required:    true,
				Default:     "postgres",
				Options: []nodes.Option{
					{Value: "postgres", Label: "PostgreSQL"},
					{Value: "mysql", Label: "MySQL"},
					{Value: "sqlite", Label: "SQLite"},
				},
			},
			{
				Name:        "host",
				DisplayName: "Host",
				Type:        nodes.ParameterTypeString,
				Description: "Database host address",
				Required:    true,
				Default:     "localhost",
				ShowIf:      "type!=sqlite",
			},
			{
				Name:        "port",
				DisplayName: "Port",
				Type:        nodes.ParameterTypeNumber,
				Description: "Database port number",
				Default:     5432,
				ShowIf:      "type!=sqlite",
			},
			{
				Name:        "database",
				DisplayName: "Database",
				Type:        nodes.ParameterTypeString,
				Description: "Database name",
				Required:    true,
			},
			{
				Name:        "username",
				DisplayName: "Username",
				Type:        nodes.ParameterTypeString,
				Description: "Database username",
				ShowIf:      "type!=sqlite",
			},
			{
				Name:        "password",
				DisplayName: "Password",
				Type:        nodes.ParameterTypeString,
				Description: "Database password",
				ShowIf:      "type!=sqlite",
			},
			{
				Name:        "operation",
				DisplayName: "Operation",
				Type:        nodes.ParameterTypeOptions,
				Description: "Database operation to perform",
				Required:    true,
				Default:     "select",
				Options: []nodes.Option{
					{Value: "select", Label: "SELECT", Description: "Query data from database"},
					{Value: "insert", Label: "INSERT", Description: "Insert new records"},
					{Value: "update", Label: "UPDATE", Description: "Update existing records"},
					{Value: "delete", Label: "DELETE", Description: "Delete records"},
					{Value: "query", Label: "Custom Query", Description: "Execute custom SQL"},
				},
			},
			{
				Name:        "table",
				DisplayName: "Table",
				Type:        nodes.ParameterTypeString,
				Description: "Database table name",
				ShowIf:      "operation!=query",
			},
			{
				Name:        "query",
				DisplayName: "SQL Query",
				Type:        nodes.ParameterTypeCode,
				Description: "Custom SQL query to execute",
				ShowIf:      "operation=query",
			},
			{
				Name:        "values",
				DisplayName: "Values",
				Type:        nodes.ParameterTypeObject,
				Description: "Column values for INSERT/UPDATE operations",
				ShowIf:      "operation=insert||operation=update",
				Placeholder: `{"column1": "value1", "column2": "value2"}`,
			},
			{
				Name:        "conditions",
				DisplayName: "Conditions",
				Type:        nodes.ParameterTypeObject,
				Description: "WHERE conditions for SELECT/UPDATE/DELETE",
				ShowIf:      "operation!=insert",
				Placeholder: `{"id": 1, "status": "active"}`,
			},
			{
				Name:        "limit",
				DisplayName: "Limit",
				Type:        nodes.ParameterTypeNumber,
				Description: "Maximum number of rows to return",
				Default:     100,
				ShowIf:      "operation=select",
			},
			{
				Name:        "timeout",
				DisplayName: "Timeout (seconds)",
				Type:        nodes.ParameterTypeNumber,
				Description: "Query timeout in seconds",
				Default:     30,
				Validation: &nodes.Validation{
					Min: func() *float64 { f := 1.0; return &f }(),
					Max: func() *float64 { f := 300.0; return &f }(),
				},
			},
		},
		Inputs: []nodes.NodeInput{
			{Name: "main", DisplayName: "Main", Type: "main", Required: false, MaxConnections: 1},
		},
		Outputs: []nodes.NodeOutput{
			{Name: "main", DisplayName: "Main", Type: "main", Description: "Database query results"},
		},
		RetryOnFail:      2,
		ContinueOnFail:   false,
		AlwaysOutputData: false,
		MaxExecutionTime: 5 * time.Minute,
		DocumentationURL: "https://docs.n8n.io/nodes/n8n-nodes-base.database/",
		Examples: []nodes.NodeExample{
			{
				Name:        "Select users",
				Description: "Select all active users from database",
				Parameters: map[string]interface{}{
					"type":      "postgres",
					"host":      "localhost",
					"database":  "myapp",
					"operation": "select",
					"table":     "users",
					"conditions": map[string]interface{}{
						"status": "active",
					},
					"limit": 50,
				},
			},
			{
				Name:        "Insert user",
				Description: "Insert a new user record",
				Parameters: map[string]interface{}{
					"type":      "postgres",
					"operation": "insert",
					"table":     "users",
					"values": map[string]interface{}{
						"name":   "John Doe",
						"email":  "john@example.com",
						"status": "active",
					},
				},
			},
		},
		Dependencies: []string{},
		Author:       "n8n Team",
		License:      "MIT",
	}
}

// parseConfig parses parameters into DBConfig
func (e *DBExecutor) parseConfig(parameters map[string]interface{}) (*DBConfig, error) {
	config := &DBConfig{
		Type:      "postgres",
		Host:      "localhost",
		Port:      5432,
		Operation: "select",
		Limit:     100,
		Timeout:   30,
	}

	if dbType, ok := parameters["type"].(string); ok {
		config.Type = dbType
	}

	if host, ok := parameters["host"].(string); ok {
		config.Host = host
	}

	if port, ok := parameters["port"]; ok {
		switch p := port.(type) {
		case int:
			config.Port = p
		case float64:
			config.Port = int(p)
		}
	}

	if database, ok := parameters["database"].(string); ok {
		config.Database = database
	}

	if username, ok := parameters["username"].(string); ok {
		config.Username = username
	}

	if password, ok := parameters["password"].(string); ok {
		config.Password = password
	}

	if operation, ok := parameters["operation"].(string); ok {
		config.Operation = operation
	}

	if table, ok := parameters["table"].(string); ok {
		config.Table = table
	}

	if query, ok := parameters["query"].(string); ok {
		config.Query = query
	}

	if values, ok := parameters["values"].(map[string]interface{}); ok {
		config.Values = values
	}

	if conditions, ok := parameters["conditions"].(map[string]interface{}); ok {
		config.Conditions = conditions
	}

	if limit, ok := parameters["limit"]; ok {
		switch l := limit.(type) {
		case int:
			config.Limit = l
		case float64:
			config.Limit = int(l)
		}
	}

	if timeout, ok := parameters["timeout"]; ok {
		switch t := timeout.(type) {
		case int:
			config.Timeout = t
		case float64:
			config.Timeout = int(t)
		}
	}

	return config, nil
}

// validateConfig validates the database configuration
func (e *DBExecutor) validateConfig(config *DBConfig) error {
	if config.Database == "" {
		return errors.NewValidationError("Database name is required")
	}

	if config.Type != "sqlite" && config.Host == "" {
		return errors.NewValidationError("Host is required")
	}

	validOperations := map[string]bool{
		"select": true, "insert": true, "update": true, "delete": true, "query": true,
	}

	if !validOperations[config.Operation] {
		return errors.NewValidationError(fmt.Sprintf("Invalid operation: %s", config.Operation))
	}

	if config.Operation != "query" && config.Table == "" {
		return errors.NewValidationError("Table name is required for this operation")
	}

	if config.Operation == "query" && config.Query == "" {
		return errors.NewValidationError("SQL query is required for query operation")
	}

	if config.Operation == "insert" && len(config.Values) == 0 {
		return errors.NewValidationError("Values are required for insert operation")
	}

	return nil
}

// createConnection creates a database connection
func (e *DBExecutor) createConnection(config *DBConfig) (*sql.DB, error) {
	var dsn string

	switch config.Type {
	case "postgres":
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			config.Username, config.Password, config.Host, config.Port, config.Database,
			getOrDefault(config.SSLMode, "disable"))
	case "mysql":
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			config.Username, config.Password, config.Host, config.Port, config.Database)
	case "sqlite":
		dsn = config.Database
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}

	db, err := sql.Open(config.Type, dsn)
	if err != nil {
		return nil, err
	}

	// Set connection limits
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// executeOperation executes the database operation
func (e *DBExecutor) executeOperation(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	switch config.Operation {
	case "select":
		return e.executeSelect(ctx, db, config)
	case "insert":
		return e.executeInsert(ctx, db, config)
	case "update":
		return e.executeUpdate(ctx, db, config)
	case "delete":
		return e.executeDelete(ctx, db, config)
	case "query":
		return e.executeQuery(ctx, db, config)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", config.Operation)
	}
}

// executeSelect executes a SELECT query
func (e *DBExecutor) executeSelect(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	query := fmt.Sprintf("SELECT * FROM %s", config.Table)
	var args []interface{}

	// Add WHERE conditions
	if len(config.Conditions) > 0 {
		conditions, condArgs := e.buildWhereClause(config.Conditions)
		query += " WHERE " + conditions
		args = append(args, condArgs...)
	}

	// Add LIMIT
	if config.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", config.Limit)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return e.scanRows(rows, "select")
}

// executeInsert executes an INSERT query
func (e *DBExecutor) executeInsert(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	columns := make([]string, 0, len(config.Values))
	placeholders := make([]string, 0, len(config.Values))
	args := make([]interface{}, 0, len(config.Values))

	i := 1
	for column, value := range config.Values {
		columns = append(columns, column)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		args = append(args, value)
		i++
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		config.Table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "))

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	rowsAffected, _ := result.RowsAffected()
	lastInsertID, _ := result.LastInsertId()

	return &DBResponse{
		Operation:    "insert",
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

// executeUpdate executes an UPDATE query
func (e *DBExecutor) executeUpdate(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	setParts := make([]string, 0, len(config.Values))
	args := make([]interface{}, 0, len(config.Values)+len(config.Conditions))

	i := 1
	for column, value := range config.Values {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", column, i))
		args = append(args, value)
		i++
	}

	query := fmt.Sprintf("UPDATE %s SET %s", config.Table, strings.Join(setParts, ", "))

	if len(config.Conditions) > 0 {
		conditions, condArgs := e.buildWhereClause(config.Conditions)
		query += " WHERE " + conditions
		args = append(args, condArgs...)
	}

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	rowsAffected, _ := result.RowsAffected()

	return &DBResponse{
		Operation:    "update",
		RowsAffected: rowsAffected,
	}, nil
}

// executeDelete executes a DELETE query
func (e *DBExecutor) executeDelete(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	query := fmt.Sprintf("DELETE FROM %s", config.Table)
	var args []interface{}

	if len(config.Conditions) > 0 {
		conditions, condArgs := e.buildWhereClause(config.Conditions)
		query += " WHERE " + conditions
		args = append(args, condArgs...)
	}

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	rowsAffected, _ := result.RowsAffected()

	return &DBResponse{
		Operation:    "delete",
		RowsAffected: rowsAffected,
	}, nil
}

// executeQuery executes a custom SQL query
func (e *DBExecutor) executeQuery(ctx context.Context, db *sql.DB, config *DBConfig) (*DBResponse, error) {
	query := config.Query

	// Check if it's a SELECT query
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT") {
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		return e.scanRows(rows, "query")
	}

	// For non-SELECT queries
	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return nil, err
	}

	rowsAffected, _ := result.RowsAffected()
	lastInsertID, _ := result.LastInsertId()

	return &DBResponse{
		Operation:    "query",
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

// buildWhereClause builds WHERE clause from conditions
func (e *DBExecutor) buildWhereClause(conditions map[string]interface{}) (string, []interface{}) {
	parts := make([]string, 0, len(conditions))
	args := make([]interface{}, 0, len(conditions))

	i := 1
	for column, value := range conditions {
		parts = append(parts, fmt.Sprintf("%s = $%d", column, i))
		args = append(args, value)
		i++
	}

	return strings.Join(parts, " AND "), args
}

// scanRows scans database rows into response format
func (e *DBExecutor) scanRows(rows *sql.Rows, operation string) (*DBResponse, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))

		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}

		results = append(results, row)
	}

	return &DBResponse{
		Operation: operation,
		Rows:      results,
	}, rows.Err()
}

// getOrDefault returns value or default if empty
func getOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}
