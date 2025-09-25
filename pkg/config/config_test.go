package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"
)

// mockLogger implements logger.Logger for testing
type mockLogger struct {
	logs []logEntry
}

type logEntry struct {
	level   string
	message string
	fields  map[string]interface{}
}

func (ml *mockLogger) Debug(msg string, keysAndValues ...interface{}) {
	ml.addLog("DEBUG", msg, keysAndValues...)
}

func (ml *mockLogger) Info(msg string, keysAndValues ...interface{}) {
	ml.addLog("INFO", msg, keysAndValues...)
}

func (ml *mockLogger) Warn(msg string, keysAndValues ...interface{}) {
	ml.addLog("WARN", msg, keysAndValues...)
}

func (ml *mockLogger) Error(msg string, keysAndValues ...interface{}) {
	ml.addLog("ERROR", msg, keysAndValues...)
}

func (ml *mockLogger) With(keysAndValues ...interface{}) logger.Logger {
	return ml
}

func (ml *mockLogger) addLog(level, msg string, keysAndValues ...interface{}) {
	fields := make(map[string]interface{})
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			fields[fmt.Sprintf("%v", keysAndValues[i])] = keysAndValues[i+1]
		}
	}
	ml.logs = append(ml.logs, logEntry{
		level:   level,
		message: msg,
		fields:  fields,
	})
}

func (ml *mockLogger) reset() {
	ml.logs = nil
}

func TestNewConfigManager(t *testing.T) {
	logger := &mockLogger{}
	validator := validator.New()
	
	cm := NewConfigManager(logger, validator)
	
	if cm == nil {
		t.Fatal("NewConfigManager returned nil")
	}
	
	if cm.logger != logger {
		t.Error("ConfigManager logger not set correctly")
	}
	
	if cm.validator != validator {
		t.Error("ConfigManager validator not set correctly")
	}
	
	if len(cm.watchers) != 0 {
		t.Error("ConfigManager should have no watchers initially")
	}
}

func TestConfigManager_LoadConfigFromEnv(t *testing.T) {
	// Set test environment variables
	testEnvVars := map[string]string{
		"N8N_PRO_APP_NAME":        "test-app",
		"N8N_PRO_APP_PORT":        "9000",
		"N8N_PRO_APP_DEBUG":       "false",
		"N8N_PRO_DATABASE_HOST":   "testdb",
		"N8N_PRO_DATABASE_PORT":   "5433",
		"N8N_PRO_AUTH_JWT_SECRET": "test_jwt_secret_32_characters_long",
	}
	
	// Set environment variables
	for key, value := range testEnvVars {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range testEnvVars {
			os.Unsetenv(key)
		}
	}()
	
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	config, err := cm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	if config.App.Name != "test-app" {
		t.Errorf("Expected app name 'test-app', got '%s'", config.App.Name)
	}
	
	if config.App.Port != 9000 {
		t.Errorf("Expected app port 9000, got %d", config.App.Port)
	}
	
	if config.App.Debug != false {
		t.Errorf("Expected app debug false, got %v", config.App.Debug)
	}
	
	if config.Database.Host != "testdb" {
		t.Errorf("Expected database host 'testdb', got '%s'", config.Database.Host)
	}
	
	if config.Database.Port != 5433 {
		t.Errorf("Expected database port 5433, got %d", config.Database.Port)
	}
}

func TestConfigManager_LoadConfigFromFile(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.json")
	
	testConfig := map[string]interface{}{
		"app": map[string]interface{}{
			"name": "file-test-app",
			"port": 8888,
		},
		"database": map[string]interface{}{
			"host": "filedb",
			"port": 5434,
		},
	}
	
	configData, err := json.Marshal(testConfig)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	config, err := cm.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	if config.App.Name != "file-test-app" {
		t.Errorf("Expected app name 'file-test-app', got '%s'", config.App.Name)
	}
	
	if config.App.Port != 8888 {
		t.Errorf("Expected app port 8888, got %d", config.App.Port)
	}
}

func TestConfigManager_GetConfig(t *testing.T) {
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	// Should return nil when no config is loaded
	config := cm.GetConfig()
	if config != nil {
		t.Error("Expected nil config when none is loaded")
	}
	
	// Load a config
	os.Setenv("N8N_PRO_AUTH_JWT_SECRET", "test_jwt_secret_32_characters_long")
	defer os.Unsetenv("N8N_PRO_AUTH_JWT_SECRET")
	
	_, err := cm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	// Should return config copy
	config = cm.GetConfig()
	if config == nil {
		t.Error("Expected config to be returned")
	}
	
	// Modify returned config should not affect internal config
	originalName := config.App.Name
	config.App.Name = "modified"
	
	config2 := cm.GetConfig()
	if config2.App.Name != originalName {
		t.Error("Internal config was modified when external copy was changed")
	}
}

func TestConfigManager_ConfigWatcher(t *testing.T) {
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	// Mock watcher
	watcherCalled := false
	var oldConfig, newConfig *Config
	
	watcher := &mockConfigWatcher{
		onChanged: func(old, new *Config) {
			watcherCalled = true
			oldConfig = old
			newConfig = new
		},
	}
	
	cm.AddWatcher(watcher)
	
	// Load initial config
	os.Setenv("N8N_PRO_AUTH_JWT_SECRET", "test_jwt_secret_32_characters_long")
	defer os.Unsetenv("N8N_PRO_AUTH_JWT_SECRET")
	
	_, err := cm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	// Change environment and reload
	os.Setenv("N8N_PRO_APP_PORT", "9999")
	defer os.Unsetenv("N8N_PRO_APP_PORT")
	
	_, err = cm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	// Give time for watcher to be called (it runs in goroutine)
	time.Sleep(100 * time.Millisecond)
	
	if !watcherCalled {
		t.Error("Configuration watcher was not called")
	}
	
	if oldConfig == nil || newConfig == nil {
		t.Error("Watcher did not receive old and new configs")
	}
	
	if newConfig.App.Port != 9999 {
		t.Errorf("New config port should be 9999, got %d", newConfig.App.Port)
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		environment string
		expected    bool
	}{
		{"production", true},
		{"staging", false},
		{"development", false},
		{"test", false},
	}
	
	for _, test := range tests {
		config := &Config{
			App: AppConfig{
				Environment: test.environment,
			},
		}
		
		result := config.IsProduction()
		if result != test.expected {
			t.Errorf("IsProduction() for environment '%s' expected %v, got %v", 
				test.environment, test.expected, result)
		}
	}
}

func TestConfig_IsDevelopment(t *testing.T) {
	tests := []struct {
		environment string
		expected    bool
	}{
		{"development", true},
		{"production", false},
		{"staging", false},
		{"test", false},
	}
	
	for _, test := range tests {
		config := &Config{
			App: AppConfig{
				Environment: test.environment,
			},
		}
		
		result := config.IsDevelopment()
		if result != test.expected {
			t.Errorf("IsDevelopment() for environment '%s' expected %v, got %v", 
				test.environment, test.expected, result)
		}
	}
}

func TestConfig_GetDatabaseDSN(t *testing.T) {
	config := &Config{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
			SSLMode:  "disable",
		},
	}
	
	dsn := config.GetDatabaseDSN()
	expected := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
	
	if dsn != expected {
		t.Errorf("GetDatabaseDSN() expected '%s', got '%s'", expected, dsn)
	}
}

func TestConfig_GetRedisAddr(t *testing.T) {
	config := &Config{
		Redis: RedisConfig{
			Host: "redis-host",
			Port: 6380,
		},
	}
	
	addr := config.GetRedisAddr()
	expected := "redis-host:6380"
	
	if addr != expected {
		t.Errorf("GetRedisAddr() expected '%s', got '%s'", expected, addr)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid development config",
			config: &Config{
				App: AppConfig{
					Environment: "development",
				},
				Auth: AuthConfig{
					JWTSecret: "test_secret_32_characters_long",
				},
			},
			expectError: false,
		},
		{
			name: "production config with debug enabled",
			config: &Config{
				App: AppConfig{
					Environment: "production",
					Debug:       true,
				},
				Auth: AuthConfig{
					JWTSecret: "test_secret_32_characters_long",
				},
				Database: DatabaseConfig{
					SSLMode: "require",
				},
				Security: SecurityConfig{
					TLSEnabled: true,
				},
			},
			expectError: true,
			errorMsg:    "debug mode should be disabled in production",
		},
		{
			name: "production config with disabled SSL",
			config: &Config{
				App: AppConfig{
					Environment: "production",
					Debug:       false,
				},
				Auth: AuthConfig{
					JWTSecret: "test_secret_32_characters_long",
				},
				Database: DatabaseConfig{
					SSLMode: "disable",
				},
				Security: SecurityConfig{
					TLSEnabled: true,
				},
			},
			expectError: true,
			errorMsg:    "SSL should be enabled for database in production",
		},
		{
			name: "enterprise config without encryption key",
			config: &Config{
				App: AppConfig{
					Environment: "development",
				},
				Auth: AuthConfig{
					JWTSecret: "test_secret_32_characters_long",
				},
				Enterprise: EnterpriseConfig{
					Enabled: true,
				},
			},
			expectError: true,
			errorMsg:    "enterprise encryption key must be exactly 32 characters",
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			
			if test.expectError {
				if err == nil {
					t.Error("Expected validation error but got none")
				} else if !strings.Contains(err.Error(), test.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", test.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error but got: %v", err)
				}
			}
		})
	}
}

func TestConfigManager_SaveConfigToFile(t *testing.T) {
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	// Load a config
	os.Setenv("N8N_PRO_AUTH_JWT_SECRET", "test_jwt_secret_32_characters_long")
	defer os.Unsetenv("N8N_PRO_AUTH_JWT_SECRET")
	
	_, err := cm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	
	// Save to file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "saved_config.json")
	
	err = cm.SaveConfigToFile(configFile)
	if err != nil {
		t.Fatalf("SaveConfigToFile failed: %v", err)
	}
	
	// Verify file exists and contains expected content
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read saved config file: %v", err)
	}
	
	var savedConfig map[string]interface{}
	if err := json.Unmarshal(data, &savedConfig); err != nil {
		t.Fatalf("Failed to unmarshal saved config: %v", err)
	}
	
	// Verify sensitive fields are not saved
	if auth, ok := savedConfig["auth"].(map[string]interface{}); ok {
		if jwtSecret, exists := auth["jwt_secret"]; exists && jwtSecret != "" {
			t.Error("JWT secret should be empty in saved config")
		}
	}
}

func TestEnvironmentLoader_LoadEnvFile(t *testing.T) {
	logger := &mockLogger{}
	envLoader := NewEnvironmentLoader(logger)
	
	// Create temporary .env file
	tempDir := t.TempDir()
	envFile := filepath.Join(tempDir, ".env")
	
	envContent := `# Test environment file
TEST_VAR1=value1
TEST_VAR2="value with spaces"
TEST_VAR3='single quoted value'
# This is a comment
TEST_VAR4=value4

# Empty lines should be ignored
TEST_VAR5=value5`
	
	if err := os.WriteFile(envFile, []byte(envContent), 0644); err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}
	
	// Load the env file
	err := envLoader.LoadEnvFile(envFile)
	if err != nil {
		t.Fatalf("LoadEnvFile failed: %v", err)
	}
	
	// Verify environment variables were set
	tests := []struct {
		key      string
		expected string
	}{
		{"TEST_VAR1", "value1"},
		{"TEST_VAR2", "value with spaces"},
		{"TEST_VAR3", "single quoted value"},
		{"TEST_VAR4", "value4"},
		{"TEST_VAR5", "value5"},
	}
	
	for _, test := range tests {
		if value := os.Getenv(test.key); value != test.expected {
			t.Errorf("Expected %s=%s, got %s=%s", test.key, test.expected, test.key, value)
		}
		// Clean up
		os.Unsetenv(test.key)
	}
}

func TestConfigValidator_ValidateEnvironment(t *testing.T) {
	logger := &mockLogger{}
	validator := NewConfigValidator(logger)
	
	requiredVars := []string{"REQUIRED_VAR1", "REQUIRED_VAR2"}
	
	// Test with missing variables
	err := validator.ValidateEnvironment(requiredVars)
	if err == nil {
		t.Error("Expected validation error for missing variables")
	}
	
	// Set required variables
	os.Setenv("REQUIRED_VAR1", "value1")
	os.Setenv("REQUIRED_VAR2", "value2")
	defer func() {
		os.Unsetenv("REQUIRED_VAR1")
		os.Unsetenv("REQUIRED_VAR2")
	}()
	
	// Test with all variables present
	err = validator.ValidateEnvironment(requiredVars)
	if err != nil {
		t.Errorf("Expected no validation error, got: %v", err)
	}
}

func TestGetEnvPrefix(t *testing.T) {
	prefix := GetEnvPrefix()
	expected := "N8N_PRO"
	
	if prefix != expected {
		t.Errorf("GetEnvPrefix() expected '%s', got '%s'", expected, prefix)
	}
}

func TestGetConfigFromEnv(t *testing.T) {
	key := "TEST_CONFIG_KEY"
	envKey := GetEnvPrefix() + "_" + key
	defaultValue := "default"
	testValue := "test_value"
	
	// Test with default value
	result := GetConfigFromEnv(key, defaultValue)
	if result != defaultValue {
		t.Errorf("Expected default value '%s', got '%s'", defaultValue, result)
	}
	
	// Set environment variable
	os.Setenv(envKey, testValue)
	defer os.Unsetenv(envKey)
	
	// Test with environment value
	result = GetConfigFromEnv(key, defaultValue)
	if result != testValue {
		t.Errorf("Expected environment value '%s', got '%s'", testValue, result)
	}
}

// mockConfigWatcher implements ConfigWatcher for testing
type mockConfigWatcher struct {
	onChanged func(oldConfig, newConfig *Config)
}

func (mcw *mockConfigWatcher) OnConfigChanged(oldConfig, newConfig *Config) {
	if mcw.onChanged != nil {
		mcw.onChanged(oldConfig, newConfig)
	}
}

func TestGetConfigSummary(t *testing.T) {
	config := &Config{
		App: AppConfig{
			Name:        "test-app",
			Version:     "1.0.0",
			Environment: "development",
			Port:        8080,
			Debug:       true,
		},
		Database: DatabaseConfig{
			Host:           "localhost",
			Port:           5432,
			Name:           "testdb",
			SSLMode:        "disable",
			MaxConnections: 25,
		},
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Database: 0,
		},
		Enterprise: EnterpriseConfig{
			Enabled: false,
			SAML: SAMLConfig{
				Enabled: false,
			},
			LDAP: LDAPConfig{
				Enabled: false,
			},
		},
		Security: SecurityConfig{
			TLSEnabled:        false,
			EncryptionEnabled: true,
			RateLimiting: RateLimitingConfig{
				Enabled: true,
			},
			CORS: CORSConfig{
				Enabled: true,
			},
		},
		Monitoring: MonitoringConfig{
			Enabled:     true,
			MetricsPort: 9090,
			HealthPort:  8081,
		},
		Storage: StorageConfig{
			Provider: "local",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
	
	summary := GetConfigSummary(config)
	
	// Verify summary structure and values
	if app, ok := summary["app"].(map[string]interface{}); ok {
		if app["name"] != "test-app" {
			t.Error("Summary app name is incorrect")
		}
		if app["environment"] != "development" {
			t.Error("Summary app environment is incorrect")
		}
	} else {
		t.Error("Summary missing app section")
	}
	
	if database, ok := summary["database"].(map[string]interface{}); ok {
		if database["host"] != "localhost" {
			t.Error("Summary database host is incorrect")
		}
	} else {
		t.Error("Summary missing database section")
	}
	
	// Verify sensitive information is not included
	summaryJSON, _ := json.Marshal(summary)
	summaryStr := string(summaryJSON)
	
	sensitiveTerms := []string{"password", "secret", "key"}
	for _, term := range sensitiveTerms {
		if strings.Contains(strings.ToLower(summaryStr), term) {
			t.Errorf("Summary contains sensitive term: %s", term)
		}
	}
}

// Benchmark tests
func BenchmarkConfigManager_LoadConfig(b *testing.B) {
	logger := &mockLogger{}
	validator := validator.New()
	cm := NewConfigManager(logger, validator)
	
	os.Setenv("N8N_PRO_AUTH_JWT_SECRET", "test_jwt_secret_32_characters_long")
	defer os.Unsetenv("N8N_PRO_AUTH_JWT_SECRET")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cm.LoadConfig()
		if err != nil {
			b.Fatalf("LoadConfig failed: %v", err)
		}
	}
}

func BenchmarkConfig_GetDatabaseDSN(b *testing.B) {
	config := &Config{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
			SSLMode:  "disable",
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.GetDatabaseDSN()
	}
}