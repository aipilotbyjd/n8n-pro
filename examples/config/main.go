package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n8n-pro/pkg/config"
	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"
)

// ExampleConfigWatcher demonstrates how to watch for configuration changes
type ExampleConfigWatcher struct {
	logger logger.Logger
}

func (ecw *ExampleConfigWatcher) OnConfigChanged(oldConfig, newConfig *config.Config) {
	ecw.logger.Info("Configuration changed",
		"old_environment", oldConfig.App.Environment,
		"new_environment", newConfig.App.Environment,
		"old_port", oldConfig.App.Port,
		"new_port", newConfig.App.Port,
	)
	
	// Handle specific configuration changes
	if oldConfig.App.Port != newConfig.App.Port {
		ecw.logger.Info("Server port changed, restart may be required")
	}
	
	if oldConfig.Database.Host != newConfig.Database.Host {
		ecw.logger.Info("Database host changed, reconnection required")
	}
	
	if oldConfig.Enterprise.Enabled != newConfig.Enterprise.Enabled {
		if newConfig.Enterprise.Enabled {
			ecw.logger.Info("Enterprise features enabled")
		} else {
			ecw.logger.Info("Enterprise features disabled")
		}
	}
}

func main() {
	// Initialize logger (would use your actual logger implementation)
	logger := &simpleLogger{}
	
	// Initialize validator
	validator := validator.New()
	
	// Create environment loader and load environment files
	envLoader := config.NewEnvironmentLoader(logger)
	if err := envLoader.LoadEnvironmentWithDefaults(); err != nil {
		logger.Error("Failed to load environment files", "error", err)
		os.Exit(1)
	}
	
	// Create configuration manager
	configManager := config.NewConfigManager(logger, validator)
	
	// Add configuration watcher
	watcher := &ExampleConfigWatcher{logger: logger}
	configManager.AddWatcher(watcher)
	
	// Load initial configuration
	cfg, err := configManager.LoadConfig("configs/app.json")
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	
	// Validate environment variables based on environment
	configValidator := config.NewConfigValidator(logger)
	var requiredVars []string
	
	if cfg.IsProduction() {
		requiredVars = config.RequiredEnvironmentVariables()
		if err := configValidator.ValidateProductionConfig(cfg); err != nil {
			logger.Error("Production configuration validation failed", "error", err)
			os.Exit(1)
		}
	} else {
		requiredVars = config.DevelopmentEnvironmentVariables()
	}
	
	if err := configValidator.ValidateEnvironment(requiredVars); err != nil {
		logger.Error("Environment validation failed", "error", err)
		os.Exit(1)
	}
	
	// Perform additional configuration validation
	if err := cfg.Validate(); err != nil {
		logger.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}
	
	// Display configuration summary
	summary := config.GetConfigSummary(cfg)
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	logger.Info("Configuration loaded successfully")
	fmt.Printf("Configuration Summary:\n%s\n", summaryJSON)
	
	// Start configuration hot-reload if enabled
	watchService := config.NewConfigWatchService(configManager, logger)
	if !cfg.IsProduction() { // Only enable hot-reload in non-production environments
		watchService.Start()
		defer watchService.Stop()
		logger.Info("Configuration hot-reload enabled")
	}
	
	// Example: Use configuration in your application
	demonstrateConfigUsage(cfg, logger)
	
	// Generate configuration templates (for demonstration)
	generateConfigurationTemplates(logger)
	
	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	logger.Info("Application started, press Ctrl+C to stop")
	
	// Main application loop (simulate work)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-sigChan:
			logger.Info("Shutting down application")
			return
		case <-ticker.C:
			// Periodically get fresh configuration
			currentConfig := configManager.GetConfig()
			if currentConfig != nil {
				logger.Info("Application running",
					"environment", currentConfig.App.Environment,
					"enterprise_enabled", currentConfig.Enterprise.Enabled,
				)
			}
		}
	}
}

// demonstrateConfigUsage shows how to use configuration in your application
func demonstrateConfigUsage(cfg *config.Config, logger logger.Logger) {
	logger.Info("=== Configuration Usage Examples ===")
	
	// Database connection
	dsn := cfg.GetDatabaseDSN()
	logger.Info("Database connection string generated", "masked_dsn", maskPassword(dsn))
	
	// Redis connection
	redisAddr := cfg.GetRedisAddr()
	logger.Info("Redis address", "addr", redisAddr)
	
	// Environment-specific behavior
	if cfg.IsProduction() {
		logger.Info("Running in production mode")
		// Production-specific initialization
	} else if cfg.IsDevelopment() {
		logger.Info("Running in development mode")
		// Development-specific initialization
	}
	
	// Enterprise features
	if cfg.Enterprise.Enabled {
		logger.Info("Enterprise features are enabled")
		
		if cfg.Enterprise.SAML.Enabled {
			logger.Info("SAML authentication is enabled")
		}
		
		if cfg.Enterprise.LDAP.Enabled {
			logger.Info("LDAP authentication is enabled")
		}
		
		// OAuth providers
		oauthProviders := []string{}
		if cfg.Enterprise.OAuth.Google.Enabled {
			oauthProviders = append(oauthProviders, "Google")
		}
		if cfg.Enterprise.OAuth.GitHub.Enabled {
			oauthProviders = append(oauthProviders, "GitHub")
		}
		if cfg.Enterprise.OAuth.Microsoft.Enabled {
			oauthProviders = append(oauthProviders, "Microsoft")
		}
		
		if len(oauthProviders) > 0 {
			logger.Info("OAuth providers enabled", "providers", oauthProviders)
		}
	} else {
		logger.Info("Enterprise features are disabled")
	}
	
	// Security configuration
	logger.Info("Security settings",
		"tls_enabled", cfg.Security.TLSEnabled,
		"rate_limiting_enabled", cfg.Security.RateLimiting.Enabled,
		"cors_enabled", cfg.Security.CORS.Enabled,
	)
	
	// Storage configuration
	logger.Info("Storage configuration",
		"provider", cfg.Storage.Provider,
		"local_path", cfg.Storage.LocalPath,
	)
	
	// Monitoring configuration
	if cfg.Monitoring.Enabled {
		logger.Info("Monitoring enabled",
			"metrics_port", cfg.Monitoring.MetricsPort,
			"health_port", cfg.Monitoring.HealthPort,
		)
	}
}

// generateConfigurationTemplates demonstrates template generation
func generateConfigurationTemplates(logger logger.Logger) {
	logger.Info("=== Generating Configuration Templates ===")
	
	templateGenerator := config.NewConfigTemplate(logger)
	
	// Generate environment template
	if err := templateGenerator.GenerateEnvTemplate("configs/.env.generated"); err != nil {
		logger.Error("Failed to generate environment template", "error", err)
	}
	
	// Generate JSON configuration template
	if err := templateGenerator.GenerateConfigJSON("configs/app.template.json"); err != nil {
		logger.Error("Failed to generate JSON configuration template", "error", err)
	}
}

// maskPassword masks passwords in connection strings for logging
func maskPassword(dsn string) string {
	// Simple password masking for demonstration
	if len(dsn) == 0 {
		return dsn
	}
	
	// This is a simple implementation - in production you'd want more robust password masking
	masked := dsn
	if len(masked) > 10 {
		start := len(masked) / 3
		end := start + (len(masked) / 3)
		masked = masked[:start] + "***MASKED***" + masked[end:]
	}
	
	return masked
}

// simpleLogger is a basic logger implementation for the example
type simpleLogger struct{}

func (sl *simpleLogger) Debug(msg string, keysAndValues ...interface{}) {
	sl.logWithLevel("DEBUG", msg, keysAndValues...)
}

func (sl *simpleLogger) Info(msg string, keysAndValues ...interface{}) {
	sl.logWithLevel("INFO", msg, keysAndValues...)
}

func (sl *simpleLogger) Warn(msg string, keysAndValues ...interface{}) {
	sl.logWithLevel("WARN", msg, keysAndValues...)
}

func (sl *simpleLogger) Error(msg string, keysAndValues ...interface{}) {
	sl.logWithLevel("ERROR", msg, keysAndValues...)
}

func (sl *simpleLogger) With(keysAndValues ...interface{}) logger.Logger {
	return sl
}

func (sl *simpleLogger) logWithLevel(level, msg string, keysAndValues ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	// Build key-value pairs
	var pairs []string
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			pairs = append(pairs, fmt.Sprintf("%v=%v", keysAndValues[i], keysAndValues[i+1]))
		}
	}
	
	var kvStr string
	if len(pairs) > 0 {
		kvStr = " " + fmt.Sprintf("[%s]", fmt.Sprintf("%s", pairs))
	}
	
	log.Printf("[%s] %s %s%s", level, timestamp, msg, kvStr)
}