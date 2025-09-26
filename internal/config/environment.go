package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// EnvironmentProfile represents different deployment environments
type EnvironmentProfile struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Variables   map[string]string `json:"variables" yaml:"variables"`
	Overrides   *Config           `json:"overrides" yaml:"overrides"`
}

// EnvironmentManager manages environment-specific configurations
type EnvironmentManager struct {
	profiles map[string]*EnvironmentProfile
}

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager() *EnvironmentManager {
	return &EnvironmentManager{
		profiles: make(map[string]*EnvironmentProfile),
	}
}

// LoadProfiles loads environment profiles from configuration files
func (em *EnvironmentManager) LoadProfiles(profilesDir string) error {
	if profilesDir == "" {
		profilesDir = "configs/environments"
	}

	// Check if directory exists
	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		// Create default profiles if directory doesn't exist
		return em.createDefaultProfiles(profilesDir)
	}

	// Read all profile files
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return fmt.Errorf("failed to read profiles directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".env") {
			continue
		}

		profileName := strings.TrimSuffix(entry.Name(), ".env")
		profilePath := filepath.Join(profilesDir, entry.Name())

		profile, err := em.loadProfileFromFile(profileName, profilePath)
		if err != nil {
			return fmt.Errorf("failed to load profile '%s': %w", profileName, err)
		}

		em.profiles[profileName] = profile
	}

	return nil
}

// loadProfileFromFile loads a single profile from an environment file
func (em *EnvironmentManager) loadProfileFromFile(name, filePath string) (*EnvironmentProfile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open profile file: %w", err)
	}
	defer file.Close()

	profile := &EnvironmentProfile{
		Name:      name,
		Variables: make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# Description: ") {
				profile.Description = strings.TrimPrefix(line, "# Description: ")
			}
			continue
		}

		// Parse key=value pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove quotes if present
			if len(value) >= 2 {
				if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
					(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
					value = value[1 : len(value)-1]
				}
			}

			profile.Variables[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading profile file: %w", err)
	}

	return profile, nil
}

// ApplyProfile applies an environment profile by setting environment variables
func (em *EnvironmentManager) ApplyProfile(profileName string) error {
	profile, exists := em.profiles[profileName]
	if !exists {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	// Set environment variables
	for key, value := range profile.Variables {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	// Set the current environment
	if err := os.Setenv("ENVIRONMENT", profileName); err != nil {
		return fmt.Errorf("failed to set ENVIRONMENT variable: %w", err)
	}

	return nil
}

// GetProfile returns a specific environment profile
func (em *EnvironmentManager) GetProfile(name string) (*EnvironmentProfile, bool) {
	profile, exists := em.profiles[name]
	return profile, exists
}

// ListProfiles returns all available environment profiles
func (em *EnvironmentManager) ListProfiles() map[string]*EnvironmentProfile {
	return em.profiles
}

// createDefaultProfiles creates default environment profiles
func (em *EnvironmentManager) createDefaultProfiles(profilesDir string) error {
	// Create directory
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	profiles := map[string]*EnvironmentProfile{
		"development": {
			Name:        "development",
			Description: "Development environment with debug logging and local services",
			Variables: map[string]string{
				"ENVIRONMENT":         "development",
				"DEBUG":               "true",
				"LOG_LEVEL":           "debug",
				"API_HOST":            "localhost",
				"API_PORT":            "8080",
				"DB_HOST":             "localhost",
				"DB_PORT":             "5432",
				"DB_NAME":             "n8n_pro_dev",
				"DB_USER":             "postgres",
				"DB_SSL_MODE":         "disable",
				"REDIS_HOST":          "localhost",
				"REDIS_PORT":          "6379",
				"API_ENABLE_CORS":     "true",
				"METRICS_ENABLED":     "false",
				"API_TLS_ENABLED":     "false",
				"DB_ENABLE_MIGRATIONS": "true",
			},
		},
		"staging": {
			Name:        "staging",
			Description: "Staging environment for testing with production-like settings",
			Variables: map[string]string{
				"ENVIRONMENT":         "staging",
				"DEBUG":               "false",
				"LOG_LEVEL":           "info",
				"API_HOST":            "0.0.0.0",
				"API_PORT":            "8080",
				"DB_SSL_MODE":         "require",
				"API_ENABLE_CORS":     "false",
				"METRICS_ENABLED":     "true",
				"METRICS_HOST":        "0.0.0.0",
				"METRICS_PORT":        "9090",
				"API_TLS_ENABLED":     "true",
				"DB_ENABLE_MIGRATIONS": "true",
				"API_ENABLE_RATE_LIMIT": "true",
			},
		},
		"production": {
			Name:        "production",
			Description: "Production environment with security and performance optimizations",
			Variables: map[string]string{
				"ENVIRONMENT":           "production",
				"DEBUG":                 "false",
				"LOG_LEVEL":             "warn",
				"API_HOST":              "0.0.0.0",
				"API_PORT":              "8080",
				"DB_SSL_MODE":           "require",
				"API_ENABLE_CORS":       "false",
				"METRICS_ENABLED":       "true",
				"METRICS_HOST":          "127.0.0.1",
				"METRICS_PORT":          "9090",
				"API_TLS_ENABLED":       "true",
				"DB_ENABLE_MIGRATIONS":  "false",
				"API_ENABLE_RATE_LIMIT": "true",
				"SECURITY_ENABLE_HSTS":  "true",
				"SECURITY_ENABLE_CSRF":  "true",
			},
		},
		"testing": {
			Name:        "testing",
			Description: "Testing environment for automated tests",
			Variables: map[string]string{
				"ENVIRONMENT":         "testing",
				"DEBUG":               "false",
				"LOG_LEVEL":           "error",
				"API_PORT":            "0", // Random port for tests
				"DB_NAME":             "n8n_pro_test",
				"API_ENABLE_CORS":     "true",
				"METRICS_ENABLED":     "false",
				"API_TLS_ENABLED":     "false",
				"DB_ENABLE_MIGRATIONS": "true",
				"REDIS_DATABASE":      "1", // Use different Redis DB
			},
		},
	}

	// Write profile files
	for name, profile := range profiles {
		filePath := filepath.Join(profilesDir, name+".env")
		if err := em.writeProfileFile(filePath, profile); err != nil {
			return fmt.Errorf("failed to write profile '%s': %w", name, err)
		}
		em.profiles[name] = profile
	}

	return nil
}

// writeProfileFile writes a profile to an environment file
func (em *EnvironmentManager) writeProfileFile(filePath string, profile *EnvironmentProfile) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create profile file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# %s Environment Profile\n", strings.Title(profile.Name))
	if profile.Description != "" {
		fmt.Fprintf(file, "# Description: %s\n", profile.Description)
	}
	fmt.Fprintf(file, "# Generated automatically by n8n-pro\n\n")

	// Write variables
	for key, value := range profile.Variables {
		// Quote values that contain spaces
		if strings.Contains(value, " ") {
			fmt.Fprintf(file, "%s=\"%s\"\n", key, value)
		} else {
			fmt.Fprintf(file, "%s=%s\n", key, value)
		}
	}

	return nil
}

// ValidateProfile validates an environment profile
func (em *EnvironmentManager) ValidateProfile(profileName string) error {
	profile, exists := em.profiles[profileName]
	if !exists {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	// Basic validation
	requiredVars := []string{"ENVIRONMENT", "API_PORT", "DB_HOST", "DB_PORT", "DB_NAME"}
	
	for _, required := range requiredVars {
		if _, exists := profile.Variables[required]; !exists {
			return fmt.Errorf("required variable '%s' missing in profile '%s'", required, profileName)
		}
	}

	// Validate specific values
	if port := profile.Variables["API_PORT"]; port != "" && port != "0" {
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid API_PORT '%s' in profile '%s'", port, profileName)
		}
	}

	if dbPort := profile.Variables["DB_PORT"]; dbPort != "" {
		if portNum, err := strconv.Atoi(dbPort); err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid DB_PORT '%s' in profile '%s'", dbPort, profileName)
		}
	}

	return nil
}

// DetectEnvironment detects the current environment from various sources
func DetectEnvironment() string {
	// Check environment variable first
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}

	// Check common deployment environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "production"
	}

	if os.Getenv("DOCKER") == "true" || os.Getenv("DOCKERIZED") == "true" {
		return "production"
	}

	if os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true" {
		return "testing"
	}

	// Check for development indicators
	if os.Getenv("DEBUG") == "true" || os.Getenv("DEV") == "true" {
		return "development"
	}

	// Default to development
	return "development"
}

// LoadEnvironmentConfig loads configuration with environment-specific overrides
func LoadEnvironmentConfig() (*Config, error) {
	// Detect current environment
	currentEnv := DetectEnvironment()

	// Load base configuration
	config, err := Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load base configuration: %w", err)
	}

	// Apply environment-specific overrides
	envManager := NewEnvironmentManager()
	if err := envManager.LoadProfiles(""); err != nil {
		// Log warning but continue - profiles are optional
		fmt.Printf("Warning: failed to load environment profiles: %v\n", err)
		return config, nil
	}

	if profile, exists := envManager.GetProfile(currentEnv); exists {
		if err := applyEnvironmentOverrides(config, profile); err != nil {
			return nil, fmt.Errorf("failed to apply environment overrides: %w", err)
		}
	}

	return config, nil
}

// applyEnvironmentOverrides applies profile overrides to configuration
func applyEnvironmentOverrides(config *Config, profile *EnvironmentProfile) error {
	// Apply variable overrides by re-parsing with profile variables set
	originalEnv := make(map[string]string)
	
	// Backup original environment variables
	for key := range profile.Variables {
		if value := os.Getenv(key); value != "" {
			originalEnv[key] = value
		}
	}

	// Set profile variables
	for key, value := range profile.Variables {
		os.Setenv(key, value)
	}

	// Re-load configuration to pick up new environment variables
	newConfig, err := Load()
	if err != nil {
		// Restore original environment
		for key, value := range originalEnv {
			os.Setenv(key, value)
		}
		return fmt.Errorf("failed to load configuration with overrides: %w", err)
	}

	// Copy values from new config
	*config = *newConfig

	// Restore original environment
	for key, value := range originalEnv {
		os.Setenv(key, value)
	}

	return nil
}

// GenerateEnvironmentTemplate generates a template environment file
func GenerateEnvironmentTemplate(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create environment template: %w", err)
	}
	defer file.Close()

	template := `# n8n-pro Environment Configuration Template
# Copy this file to .env and customize for your environment

# ================================================
# Application Settings
# ================================================
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=info

# ================================================
# API Server Settings
# ================================================
API_HOST=localhost
API_PORT=8080
API_READ_TIMEOUT=30s
API_WRITE_TIMEOUT=30s
API_ENABLE_CORS=true
API_ENABLE_RATE_LIMIT=false
API_TLS_ENABLED=false
# API_TLS_CERT_FILE=/path/to/cert.pem
# API_TLS_KEY_FILE=/path/to/key.pem

# ================================================
# Database Settings
# ================================================
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=secret://db_password
DB_SSL_MODE=disable
DB_MAX_OPEN_CONNECTIONS=25
DB_MAX_IDLE_CONNECTIONS=5
DB_ENABLE_MIGRATIONS=true
DB_ENABLE_QUERY_LOGGING=false

# ================================================
# Redis Settings
# ================================================
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=secret://redis_password
REDIS_DATABASE=0
REDIS_POOL_SIZE=10

# ================================================
# Authentication Settings
# ================================================
JWT_SECRET=secret://jwt_secret
JWT_EXPIRATION=24h
REFRESH_TOKEN_EXPIRATION=720h
ENABLE_MFA=false
MFA_ISSUER=n8n-pro

# ================================================
# Security Settings
# ================================================
ENCRYPTION_KEY=secret://encryption_key
HASH_COST=12
ENABLE_CSRF=false
ENABLE_HSTS=false

# ================================================
# Metrics Settings
# ================================================
METRICS_ENABLED=false
METRICS_HOST=localhost
METRICS_PORT=9090

# ================================================
# Email Settings (Optional)
# ================================================
# EMAIL_PROVIDER=smtp
# SMTP_HOST=smtp.example.com
# SMTP_PORT=587
# SMTP_USERNAME=noreply@example.com
# SMTP_PASSWORD=secret://smtp_password
# EMAIL_FROM=noreply@example.com

# ================================================
# Storage Settings (Optional)
# ================================================
# STORAGE_PROVIDER=local
# STORAGE_LOCAL_PATH=./storage
# STORAGE_MAX_FILE_SIZE=10485760

# ================================================
# Webhook Settings (Optional)
# ================================================
# WEBHOOK_HOST=localhost
# WEBHOOK_PORT=8081

# ================================================
# Worker Settings (Optional)
# ================================================
# WORKER_ENABLED=false
# WORKER_CONCURRENCY=5

# ================================================
# Limits
# ================================================
# MAX_WORKFLOWS_PER_TEAM=100
# MAX_NODES_PER_WORKFLOW=50
# MAX_EXECUTION_TIME=300s
`

	_, err = file.WriteString(template)
	return err
}

// GetConfigSummary returns a summary of the current configuration
func GetConfigSummary(config *Config) map[string]interface{} {
	summary := make(map[string]interface{})

	summary["environment"] = config.Environment
	summary["debug"] = config.Debug
	summary["log_level"] = config.LogLevel

	if config.API != nil {
		summary["api"] = map[string]interface{}{
			"host":        config.API.Host,
			"port":        config.API.Port,
			"tls_enabled": config.API.TLSEnabled,
			"cors_enabled": config.API.EnableCORS,
		}
	}

	if config.Database != nil {
		summary["database"] = map[string]interface{}{
			"host":              config.Database.Host,
			"port":              config.Database.Port,
			"database":          config.Database.Database,
			"ssl_mode":          config.Database.SSLMode,
			"migrations_enabled": config.Database.EnableMigrations,
		}
	}

	if config.Metrics != nil {
		summary["metrics"] = map[string]interface{}{
			"enabled": config.Metrics.Enabled,
			"port":    config.Metrics.Port,
		}
	}

	return summary
}