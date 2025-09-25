# Configuration Management System

A comprehensive, enterprise-ready configuration management system for N8N Pro with environment variable support, hot-reload capabilities, and advanced security features.

## Features

- **Environment Variable Loading**: Automatic loading from `.env` files with support for multiple file locations
- **JSON Configuration**: Support for JSON configuration files with environment variable overrides
- **Hot Reload**: Configuration file watching with automatic reloading (development mode)
- **Validation**: Built-in validation with struct tags and custom production rules
- **Security**: Automatic masking of sensitive fields when saving/logging configurations
- **Enterprise Features**: Advanced configuration for SAML, LDAP, OAuth, and audit logging
- **Template Generation**: Automatic generation of configuration templates and examples
- **Type Safety**: Strongly typed configuration with comprehensive validation
- **Thread Safety**: Concurrent access protection with mutex locks
- **Watcher System**: Extensible configuration change notification system

## Quick Start

### Basic Usage

```go
package main

import (
    "n8n-pro/pkg/config"
    "n8n-pro/pkg/logger"
    "n8n-pro/pkg/validator"
)

func main() {
    // Initialize dependencies
    logger := logger.New()
    validator := validator.New()
    
    // Create configuration manager
    configManager := config.NewConfigManager(logger, validator)
    
    // Load environment files
    envLoader := config.NewEnvironmentLoader(logger)
    envLoader.LoadEnvironmentWithDefaults()
    
    // Load configuration
    cfg, err := configManager.LoadConfig("configs/app.json")
    if err != nil {
        logger.Error("Failed to load configuration", "error", err)
        return
    }
    
    // Use configuration
    logger.Info("Application started",
        "environment", cfg.App.Environment,
        "port", cfg.App.Port,
        "database_host", cfg.Database.Host,
    )
}
```

### Environment Variables

The system uses a hierarchical environment variable naming convention:

```bash
N8N_PRO_APP_NAME=n8n-pro
N8N_PRO_APP_PORT=8080
N8N_PRO_DATABASE_HOST=localhost
N8N_PRO_DATABASE_PORT=5432
N8N_PRO_AUTH_JWT_SECRET=your_super_secret_jwt_key_here_32_chars_minimum
```

### Environment Files

Create a `.env` file in your project root:

```env
# Application Configuration
N8N_PRO_APP_NAME=n8n-pro
N8N_PRO_APP_ENVIRONMENT=development
N8N_PRO_APP_PORT=8080
N8N_PRO_APP_DEBUG=true

# Database Configuration
N8N_PRO_DATABASE_HOST=localhost
N8N_PRO_DATABASE_PORT=5432
N8N_PRO_DATABASE_NAME=n8n_pro
N8N_PRO_DATABASE_USER=n8n_user
N8N_PRO_DATABASE_PASSWORD=your_secure_password

# Authentication
N8N_PRO_AUTH_JWT_SECRET=your_super_secret_jwt_key_here_32_chars_minimum
```

## Configuration Structure

### Application Configuration

```go
type AppConfig struct {
    Name        string `json:"name" env:"NAME" validate:"required"`
    Version     string `json:"version" env:"VERSION" validate:"required"`
    Environment string `json:"environment" env:"ENVIRONMENT" validate:"required,oneof=development staging production"`
    Port        int    `json:"port" env:"PORT" validate:"required,min=1,max=65535"`
    Host        string `json:"host" env:"HOST" validate:"required"`
    BaseURL     string `json:"base_url" env:"BASE_URL" validate:"required,url"`
    Debug       bool   `json:"debug" env:"DEBUG"`
    Maintenance bool   `json:"maintenance" env:"MAINTENANCE"`
}
```

### Database Configuration

```go
type DatabaseConfig struct {
    Host            string        `json:"host" env:"HOST" validate:"required"`
    Port            int           `json:"port" env:"PORT" validate:"required,min=1,max=65535"`
    Name            string        `json:"name" env:"NAME" validate:"required"`
    User            string        `json:"user" env:"USER" validate:"required"`
    Password        string        `json:"password" env:"PASSWORD" validate:"required" sensitive:"true"`
    SSLMode         string        `json:"ssl_mode" env:"SSL_MODE" validate:"oneof=disable require verify-ca verify-full"`
    MaxConnections  int           `json:"max_connections" env:"MAX_CONNECTIONS" validate:"min=1"`
    MaxIdleConns    int           `json:"max_idle_conns" env:"MAX_IDLE_CONNS" validate:"min=1"`
    ConnMaxLifetime time.Duration `json:"conn_max_lifetime" env:"CONN_MAX_LIFETIME"`
    ConnMaxIdleTime time.Duration `json:"conn_max_idle_time" env:"CONN_MAX_IDLE_TIME"`
}
```

### Enterprise Configuration

```go
type EnterpriseConfig struct {
    Enabled          bool   `json:"enabled" env:"ENABLED"`
    EncryptionKey    string `json:"encryption_key" env:"ENCRYPTION_KEY" validate:"len=32" sensitive:"true"`
    LicenseKey       string `json:"license_key" env:"LICENSE_KEY" sensitive:"true"`
    SAML             SAMLConfig `json:"saml" env:"SAML"`
    LDAP             LDAPConfig `json:"ldap" env:"LDAP"`
    OAuth            OAuthConfig `json:"oauth" env:"OAUTH"`
    AuditRetentionDays int   `json:"audit_retention_days" env:"AUDIT_RETENTION_DAYS" validate:"min=30"`
}
```

## Advanced Features

### Configuration Watchers

Register watchers to be notified of configuration changes:

```go
type MyConfigWatcher struct {
    logger logger.Logger
}

func (w *MyConfigWatcher) OnConfigChanged(oldConfig, newConfig *config.Config) {
    if oldConfig.App.Port != newConfig.App.Port {
        w.logger.Info("Server port changed, restart required")
    }
}

// Register watcher
watcher := &MyConfigWatcher{logger: logger}
configManager.AddWatcher(watcher)
```

### Hot Reload (Development)

Enable configuration hot-reload for development environments:

```go
watchService := config.NewConfigWatchService(configManager, logger)
if !cfg.IsProduction() {
    watchService.Start()
    defer watchService.Stop()
}
```

### Validation

#### Environment Variable Validation

```go
configValidator := config.NewConfigValidator(logger)

// Validate required variables
requiredVars := config.RequiredEnvironmentVariables()
if err := configValidator.ValidateEnvironment(requiredVars); err != nil {
    logger.Error("Environment validation failed", "error", err)
}

// Validate production configuration
if cfg.IsProduction() {
    if err := configValidator.ValidateProductionConfig(cfg); err != nil {
        logger.Error("Production validation failed", "error", err)
    }
}
```

#### Custom Validation

```go
if err := cfg.Validate(); err != nil {
    logger.Error("Configuration validation failed", "error", err)
}
```

### Template Generation

Generate configuration templates:

```go
templateGenerator := config.NewConfigTemplate(logger)

// Generate environment template
err := templateGenerator.GenerateEnvTemplate("configs/.env.template")

// Generate JSON configuration template
err := templateGenerator.GenerateConfigJSON("configs/app.template.json")
```

### Configuration Summary

Get a sanitized configuration summary (no sensitive data):

```go
summary := config.GetConfigSummary(cfg)
summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
logger.Info("Configuration loaded", "summary", string(summaryJSON))
```

## Configuration Loading Priority

The system loads configuration in the following priority order (highest to lowest):

1. **Environment Variables** - Direct environment variables (highest priority)
2. **JSON Configuration File** - Specified configuration file
3. **Environment Files** - `.env` files in priority order:
   - `.env.local` (local overrides)
   - `.env` (main environment file)
   - `configs/.env` (config directory)
   - `.env.example` (example file as fallback)
4. **Default Values** - Built-in default values (lowest priority)

## Environment-Specific Configurations

### Development

```bash
N8N_PRO_APP_ENVIRONMENT=development
N8N_PRO_APP_DEBUG=true
N8N_PRO_DATABASE_SSL_MODE=disable
N8N_PRO_SECURITY_TLS_ENABLED=false
```

### Staging

```bash
N8N_PRO_APP_ENVIRONMENT=staging
N8N_PRO_APP_DEBUG=false
N8N_PRO_DATABASE_SSL_MODE=require
N8N_PRO_SECURITY_TLS_ENABLED=true
```

### Production

```bash
N8N_PRO_APP_ENVIRONMENT=production
N8N_PRO_APP_DEBUG=false
N8N_PRO_DATABASE_SSL_MODE=verify-full
N8N_PRO_SECURITY_TLS_ENABLED=true
N8N_PRO_AUTH_JWT_SECRET=your_production_secret_key_32_chars_minimum
```

## Security Features

### Sensitive Field Protection

Fields marked with `sensitive:"true"` are automatically:
- Excluded from saved configuration files
- Masked in logs and summaries
- Protected during serialization

### Production Validation

The system enforces security requirements in production:
- Debug mode must be disabled
- TLS must be enabled
- Database SSL must be enabled
- JWT secrets must be at least 32 characters
- Rate limiting must be enabled

### Enterprise Security

When enterprise features are enabled:
- Encryption keys must be exactly 32 characters
- License keys are required
- SAML certificates and keys are validated
- LDAP configurations are verified

## Integration Examples

### Database Connection

```go
// Get database connection string
dsn := cfg.GetDatabaseDSN()
db, err := sql.Open("postgres", dsn)
```

### Redis Connection

```go
// Get Redis address
redisAddr := cfg.GetRedisAddr()
rdb := redis.NewClient(&redis.Options{
    Addr:         redisAddr,
    Password:     cfg.Redis.Password,
    DB:           cfg.Redis.Database,
    DialTimeout:  cfg.Redis.DialTimeout,
    ReadTimeout:  cfg.Redis.ReadTimeout,
    WriteTimeout: cfg.Redis.WriteTimeout,
    PoolSize:     cfg.Redis.PoolSize,
})
```

### HTTP Server

```go
server := &http.Server{
    Addr:         fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port),
    Handler:      router,
    ReadTimeout:  cfg.Security.Validation.RequestTimeout,
    WriteTimeout: cfg.Security.Validation.RequestTimeout,
}

if cfg.Security.TLSEnabled {
    server.ListenAndServeTLS(cfg.Security.TLSCertFile, cfg.Security.TLSKeyFile)
} else {
    server.ListenAndServe()
}
```

## Best Practices

### 1. Environment-Specific Configuration

- Use separate configuration files for each environment
- Never commit sensitive values to version control
- Use environment variables for secrets in production

### 2. Validation

- Always validate configuration on startup
- Use production-specific validation in production environments
- Implement custom validation for business rules

### 3. Security

- Use strong secrets (minimum 32 characters for JWT)
- Enable TLS in production
- Use SSL for database connections in production
- Regularly rotate encryption keys

### 4. Monitoring

- Log configuration changes
- Monitor for configuration validation failures
- Set up alerts for production configuration issues

### 5. Development Workflow

- Use hot-reload in development
- Generate configuration templates for new deployments
- Document all configuration options

## Testing

Run the configuration tests:

```bash
go test -v ./pkg/config/...
```

Run benchmarks:

```bash
go test -bench=. ./pkg/config/
```

## Error Handling

The configuration system provides detailed error messages:

```go
config, err := configManager.LoadConfig()
if err != nil {
    switch {
    case strings.Contains(err.Error(), "validation failed"):
        logger.Error("Configuration validation error", "error", err)
        // Handle validation errors
    case strings.Contains(err.Error(), "file does not exist"):
        logger.Warn("Configuration file not found, using defaults", "error", err)
        // Handle missing file
    default:
        logger.Error("Configuration loading failed", "error", err)
        // Handle other errors
    }
}
```

## Migration Guide

### From Environment Variables Only

If you're currently using only environment variables:

1. Continue using your existing environment variables
2. Optionally create a JSON configuration file for complex configurations
3. Add configuration validation

### From Configuration Files

If you're using configuration files:

1. Rename your configuration keys to match the new structure
2. Add environment variable support for sensitive values
3. Implement configuration watchers for hot-reload

## Troubleshooting

### Common Issues

1. **Configuration Not Loading**
   - Check file permissions
   - Verify file path
   - Check JSON syntax

2. **Environment Variables Not Working**
   - Verify variable names match the expected format
   - Check environment variable precedence
   - Ensure proper data type conversion

3. **Validation Errors**
   - Check required fields are set
   - Verify data formats (URLs, durations, etc.)
   - Check production-specific requirements

4. **Hot Reload Not Working**
   - Ensure file watcher is started
   - Check file modification detection
   - Verify not running in production mode

### Debug Mode

Enable debug logging to troubleshoot configuration issues:

```bash
N8N_PRO_LOGGING_LEVEL=debug
```

This will provide detailed information about configuration loading, validation, and changes.