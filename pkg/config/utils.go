package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"n8n-pro/pkg/logger"
)

// EnvironmentLoader provides utilities for loading environment files
type EnvironmentLoader struct {
	logger logger.Logger
}

// NewEnvironmentLoader creates a new environment loader
func NewEnvironmentLoader(logger logger.Logger) *EnvironmentLoader {
	return &EnvironmentLoader{
		logger: logger,
	}
}

// LoadEnvFile loads environment variables from a .env file
func (el *EnvironmentLoader) LoadEnvFile(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		el.logger.Warn("Environment file does not exist", "file", filename)
		return nil // Don't error if file doesn't exist
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read environment file %s: %w", filename, err)
	}

	lines := strings.Split(string(content), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			el.logger.Warn("Invalid line in environment file", 
				"file", filename, 
				"line", lineNum+1, 
				"content", line)
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// Remove surrounding quotes if present
		if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
		   (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
			value = value[1 : len(value)-1]
		}
		
		// Only set if not already set in environment
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, value); err != nil {
				el.logger.Warn("Failed to set environment variable", 
					"key", key, 
					"error", err)
			}
		}
	}
	
	el.logger.Info("Loaded environment file", "file", filename)
	return nil
}

// LoadEnvFiles loads multiple environment files in order
func (el *EnvironmentLoader) LoadEnvFiles(filenames ...string) error {
	for _, filename := range filenames {
		if err := el.LoadEnvFile(filename); err != nil {
			return err
		}
	}
	return nil
}

// LoadEnvironmentWithDefaults loads environment files with default locations
func (el *EnvironmentLoader) LoadEnvironmentWithDefaults() error {
	// Try to load environment files in priority order
	envFiles := []string{
		".env.local",     // Local overrides (highest priority)
		".env",           // Main environment file
		"configs/.env",   // Config directory
		".env.example",   // Example file as fallback
	}
	
	return el.LoadEnvFiles(envFiles...)
}

// ConfigWatchService provides configuration hot-reload functionality
type ConfigWatchService struct {
	configManager *ConfigManager
	logger        logger.Logger
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewConfigWatchService creates a new configuration watch service
func NewConfigWatchService(configManager *ConfigManager, logger logger.Logger) *ConfigWatchService {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigWatchService{
		configManager: configManager,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the configuration watcher
func (cws *ConfigWatchService) Start() {
	go cws.watchLoop()
}

// Stop stops the configuration watcher
func (cws *ConfigWatchService) Stop() {
	cws.cancel()
}

// watchLoop monitors configuration files for changes
func (cws *ConfigWatchService) watchLoop() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()
	
	var lastModTime time.Time
	configFile := cws.configManager.configFile
	
	if configFile != "" {
		if stat, err := os.Stat(configFile); err == nil {
			lastModTime = stat.ModTime()
		}
	}
	
	for {
		select {
		case <-cws.ctx.Done():
			return
		case <-ticker.C:
			if configFile == "" {
				continue
			}
			
			stat, err := os.Stat(configFile)
			if err != nil {
				continue
			}
			
			if stat.ModTime().After(lastModTime) {
				cws.logger.Info("Configuration file changed, reloading", "file", configFile)
				if err := cws.configManager.ReloadConfig(); err != nil {
					cws.logger.Error("Failed to reload configuration", "error", err)
				} else {
					cws.logger.Info("Configuration reloaded successfully")
				}
				lastModTime = stat.ModTime()
			}
		}
	}
}

// ConfigValidator provides additional configuration validation utilities
type ConfigValidator struct {
	logger logger.Logger
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger logger.Logger) *ConfigValidator {
	return &ConfigValidator{
		logger: logger,
	}
}

// ValidateEnvironment validates that required environment variables are set
func (cv *ConfigValidator) ValidateEnvironment(requiredVars []string) error {
	var missing []string
	
	for _, varName := range requiredVars {
		if os.Getenv(varName) == "" {
			missing = append(missing, varName)
		}
	}
	
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	
	return nil
}

// ValidateProductionConfig validates production-specific configuration requirements
func (cv *ConfigValidator) ValidateProductionConfig(config *Config) error {
	if !config.IsProduction() {
		return nil // Only validate production configs
	}
	
	var issues []string
	
	// Security validations
	if config.App.Debug {
		issues = append(issues, "debug mode must be disabled in production")
	}
	
	if config.Database.SSLMode == "disable" {
		issues = append(issues, "database SSL must be enabled in production")
	}
	
	if len(config.Auth.JWTSecret) < 32 {
		issues = append(issues, "JWT secret must be at least 32 characters in production")
	}
	
	if !config.Security.TLSEnabled {
		issues = append(issues, "TLS must be enabled in production")
	}
	
	if !config.Security.RateLimiting.Enabled {
		issues = append(issues, "rate limiting should be enabled in production")
	}
	
	// Logging validations
	if config.Logging.Level == "debug" {
		issues = append(issues, "debug logging should not be used in production")
	}
	
	// Enterprise validations
	if config.Enterprise.Enabled {
		if len(config.Enterprise.EncryptionKey) != 32 {
			issues = append(issues, "enterprise encryption key must be exactly 32 characters")
		}
		
		if config.Enterprise.LicenseKey == "" {
			issues = append(issues, "enterprise license key is required when enterprise features are enabled")
		}
	}
	
	if len(issues) > 0 {
		return fmt.Errorf("production configuration validation failed: %s", strings.Join(issues, "; "))
	}
	
	return nil
}

// ConfigTemplate provides configuration template generation utilities
type ConfigTemplate struct {
	logger logger.Logger
}

// NewConfigTemplate creates a new configuration template generator
func NewConfigTemplate(logger logger.Logger) *ConfigTemplate {
	return &ConfigTemplate{
		logger: logger,
	}
}

// GenerateEnvTemplate generates an environment template file
func (ct *ConfigTemplate) GenerateEnvTemplate(filename string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Read the existing .env.example content
	exampleFile := filepath.Join(filepath.Dir(filename), ".env.example")
	content, err := os.ReadFile(exampleFile)
	if err != nil {
		return fmt.Errorf("failed to read example file: %w", err)
	}
	
	// Write to the target file
	if err := os.WriteFile(filename, content, 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}
	
	ct.logger.Info("Generated environment template", "file", filename)
	return nil
}

// GenerateConfigJSON generates a JSON configuration template
func (ct *ConfigTemplate) GenerateConfigJSON(filename string) error {
	// Create a default configuration
	config := &Config{}
	
	// Set all default values
	config.App.Name = "n8n-pro"
	config.App.Version = "1.0.0"
	config.App.Environment = "development"
	config.App.Port = 8080
	config.App.Host = "0.0.0.0"
	config.App.BaseURL = "http://localhost:8080"
	config.App.Debug = true
	config.App.Maintenance = false
	
	config.Database.Host = "localhost"
	config.Database.Port = 5432
	config.Database.Name = "n8n_pro"
	config.Database.User = "n8n_user"
	config.Database.Password = "your_secure_password_here"
	config.Database.SSLMode = "disable"
	config.Database.MaxConnections = 25
	config.Database.MaxIdleConns = 5
	config.Database.ConnMaxLifetime = 300 * time.Second
	config.Database.ConnMaxIdleTime = 300 * time.Second
	
	config.Redis.Host = "localhost"
	config.Redis.Port = 6379
	config.Redis.Database = 0
	config.Redis.MaxRetries = 3
	config.Redis.DialTimeout = 5 * time.Second
	config.Redis.ReadTimeout = 3 * time.Second
	config.Redis.WriteTimeout = 3 * time.Second
	config.Redis.PoolSize = 10
	
	config.Auth.JWTSecret = "your_super_secret_jwt_key_here_32_chars_minimum"
	config.Auth.JWTExpiration = 24 * time.Hour
	config.Auth.RefreshTokenExpiration = 720 * time.Hour
	config.Auth.PasswordMinLength = 8
	config.Auth.PasswordRequireSpecial = true
	config.Auth.EnableMFA = false
	config.Auth.SessionTimeout = 24 * time.Hour
	config.Auth.MaxLoginAttempts = 5
	config.Auth.LockoutDuration = 15 * time.Minute
	
	config.Enterprise.Enabled = false
	config.Enterprise.AuditRetentionDays = 365
	
	config.Security.EncryptionEnabled = true
	config.Security.TLSEnabled = false
	config.Security.RateLimiting.Enabled = true
	config.Security.RateLimiting.RPS = 100
	config.Security.RateLimiting.Burst = 200
	config.Security.RateLimiting.WindowSize = 1 * time.Minute
	config.Security.CORS.Enabled = true
	config.Security.CORS.AllowedOrigins = []string{"*"}
	config.Security.CORS.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.Security.CORS.AllowedHeaders = []string{"*"}
	config.Security.CORS.AllowCredentials = true
	config.Security.CORS.MaxAge = 86400
	config.Security.Validation.MaxRequestSize = 10485760
	config.Security.Validation.RequestTimeout = 30 * time.Second
	config.Security.Validation.EnableSQLInjection = true
	config.Security.Validation.EnableXSSProtection = true
	config.Security.Validation.MaxFieldLength = 10000
	
	config.Monitoring.Enabled = true
	config.Monitoring.MetricsPort = 9090
	config.Monitoring.HealthPort = 8081
	config.Monitoring.PrometheusPath = "/metrics"
	config.Monitoring.HealthPath = "/health"
	
	config.Email.Provider = "smtp"
	config.Email.Host = "smtp.gmail.com"
	config.Email.Port = 587
	config.Email.Username = "your-email@gmail.com"
	config.Email.Password = "your-app-password"
	config.Email.FromAddress = "noreply@yourcompany.com"
	config.Email.FromName = "N8N Pro"
	config.Email.UseTLS = true
	
	config.Storage.Provider = "local"
	config.Storage.LocalPath = "./storage"
	
	config.Logging.Level = "info"
	config.Logging.Format = "json"
	config.Logging.Output = "stdout"
	config.Logging.File = "./logs/app.log"
	config.Logging.MaxSize = 100
	config.Logging.MaxBackups = 3
	config.Logging.MaxAge = 28
	config.Logging.Compress = true
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Use ConfigManager to save the config
	cm := NewConfigManager(ct.logger, nil)
	cm.config = config
	
	if err := cm.SaveConfigToFile(filename); err != nil {
		return fmt.Errorf("failed to save config template: %w", err)
	}
	
	ct.logger.Info("Generated JSON configuration template", "file", filename)
	return nil
}

// RequiredEnvironmentVariables returns a list of required environment variables for production
func RequiredEnvironmentVariables() []string {
	return []string{
		"N8N_PRO_APP_ENVIRONMENT",
		"N8N_PRO_DATABASE_HOST",
		"N8N_PRO_DATABASE_PORT",
		"N8N_PRO_DATABASE_NAME",
		"N8N_PRO_DATABASE_USER",
		"N8N_PRO_DATABASE_PASSWORD",
		"N8N_PRO_AUTH_JWT_SECRET",
	}
}

// DevelopmentEnvironmentVariables returns a list of environment variables needed for development
func DevelopmentEnvironmentVariables() []string {
	return []string{
		"N8N_PRO_APP_ENVIRONMENT",
		"N8N_PRO_DATABASE_HOST",
		"N8N_PRO_DATABASE_NAME",
		"N8N_PRO_DATABASE_USER",
		"N8N_PRO_AUTH_JWT_SECRET",
	}
}

// EnterpriseEnvironmentVariables returns a list of additional environment variables for enterprise features
func EnterpriseEnvironmentVariables() []string {
	return []string{
		"N8N_PRO_ENTERPRISE_ENABLED",
		"N8N_PRO_ENTERPRISE_ENCRYPTION_KEY",
		"N8N_PRO_ENTERPRISE_LICENSE_KEY",
	}
}

// GetConfigSummary returns a summary of the current configuration (excluding sensitive values)
func GetConfigSummary(config *Config) map[string]interface{} {
	return map[string]interface{}{
		"app": map[string]interface{}{
			"name":        config.App.Name,
			"version":     config.App.Version,
			"environment": config.App.Environment,
			"port":        config.App.Port,
			"debug":       config.App.Debug,
		},
		"database": map[string]interface{}{
			"host":            config.Database.Host,
			"port":            config.Database.Port,
			"name":            config.Database.Name,
			"ssl_mode":        config.Database.SSLMode,
			"max_connections": config.Database.MaxConnections,
		},
		"redis": map[string]interface{}{
			"host":     config.Redis.Host,
			"port":     config.Redis.Port,
			"database": config.Redis.Database,
		},
		"enterprise": map[string]interface{}{
			"enabled": config.Enterprise.Enabled,
			"saml":    config.Enterprise.SAML.Enabled,
			"ldap":    config.Enterprise.LDAP.Enabled,
		},
		"security": map[string]interface{}{
			"tls_enabled":        config.Security.TLSEnabled,
			"rate_limiting":      config.Security.RateLimiting.Enabled,
			"cors":               config.Security.CORS.Enabled,
			"encryption_enabled": config.Security.EncryptionEnabled,
		},
		"monitoring": map[string]interface{}{
			"enabled":      config.Monitoring.Enabled,
			"metrics_port": config.Monitoring.MetricsPort,
			"health_port":  config.Monitoring.HealthPort,
		},
		"storage": map[string]interface{}{
			"provider": config.Storage.Provider,
		},
		"logging": map[string]interface{}{
			"level":  config.Logging.Level,
			"format": config.Logging.Format,
			"output": config.Logging.Output,
		},
	}
}