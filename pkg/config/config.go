package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"n8n-pro/pkg/logger"
	"n8n-pro/pkg/validator"
)

// ConfigManager manages application configuration with environment variable support
type ConfigManager struct {
	config     *Config
	mu         sync.RWMutex
	logger     logger.Logger
	validator  *validator.Validator
	watchers   []ConfigWatcher
	configFile string
}

// ConfigWatcher defines the interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigChanged(oldConfig, newConfig *Config)
}

// Config represents the complete application configuration
type Config struct {
	App        AppConfig        `json:"app" env:"APP"`
	Database   DatabaseConfig   `json:"database" env:"DATABASE"`
	Redis      RedisConfig      `json:"redis" env:"REDIS"`
	Auth       AuthConfig       `json:"auth" env:"AUTH"`
	Enterprise EnterpriseConfig `json:"enterprise" env:"ENTERPRISE"`
	Security   SecurityConfig   `json:"security" env:"SECURITY"`
	Monitoring MonitoringConfig `json:"monitoring" env:"MONITORING"`
	Email      EmailConfig      `json:"email" env:"EMAIL"`
	Storage    StorageConfig    `json:"storage" env:"STORAGE"`
	Logging    LoggingConfig    `json:"logging" env:"LOGGING"`
}

// AppConfig contains general application configuration
type AppConfig struct {
	Name        string `json:"name" env:"NAME" validate:"required" default:"n8n-pro"`
	Version     string `json:"version" env:"VERSION" validate:"required" default:"1.0.0"`
	Environment string `json:"environment" env:"ENVIRONMENT" validate:"required,oneof=development staging production" default:"development"`
	Port        int    `json:"port" env:"PORT" validate:"required,min=1,max=65535" default:"8080"`
	Host        string `json:"host" env:"HOST" validate:"required" default:"0.0.0.0"`
	BaseURL     string `json:"base_url" env:"BASE_URL" validate:"required,url" default:"http://localhost:8080"`
	Debug       bool   `json:"debug" env:"DEBUG" default:"true"`
	Maintenance bool   `json:"maintenance" env:"MAINTENANCE" default:"false"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Host            string        `json:"host" env:"HOST" validate:"required" default:"localhost"`
	Port            int           `json:"port" env:"PORT" validate:"required,min=1,max=65535" default:"5432"`
	Name            string        `json:"name" env:"NAME" validate:"required" default:"n8n_pro"`
	User            string        `json:"user" env:"USER" validate:"required" default:"n8n_user"`
	Password        string        `json:"password" env:"PASSWORD" validate:"required" sensitive:"true"`
	SSLMode         string        `json:"ssl_mode" env:"SSL_MODE" validate:"oneof=disable require verify-ca verify-full" default:"disable"`
	MaxConnections  int           `json:"max_connections" env:"MAX_CONNECTIONS" validate:"min=1" default:"25"`
	MaxIdleConns    int           `json:"max_idle_conns" env:"MAX_IDLE_CONNS" validate:"min=1" default:"5"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" env:"CONN_MAX_LIFETIME" default:"300s"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time" env:"CONN_MAX_IDLE_TIME" default:"300s"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Host         string        `json:"host" env:"HOST" validate:"required" default:"localhost"`
	Port         int           `json:"port" env:"PORT" validate:"required,min=1,max=65535" default:"6379"`
	Password     string        `json:"password" env:"PASSWORD" sensitive:"true"`
	Database     int           `json:"database" env:"DATABASE" validate:"min=0,max=15" default:"0"`
	MaxRetries   int           `json:"max_retries" env:"MAX_RETRIES" validate:"min=0" default:"3"`
	DialTimeout  time.Duration `json:"dial_timeout" env:"DIAL_TIMEOUT" default:"5s"`
	ReadTimeout  time.Duration `json:"read_timeout" env:"READ_TIMEOUT" default:"3s"`
	WriteTimeout time.Duration `json:"write_timeout" env:"WRITE_TIMEOUT" default:"3s"`
	PoolSize     int           `json:"pool_size" env:"POOL_SIZE" validate:"min=1" default:"10"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	JWTSecret              string        `json:"jwt_secret" env:"JWT_SECRET" validate:"required,min=32" sensitive:"true"`
	JWTExpiration          time.Duration `json:"jwt_expiration" env:"JWT_EXPIRATION" default:"24h"`
	RefreshTokenExpiration time.Duration `json:"refresh_token_expiration" env:"REFRESH_TOKEN_EXPIRATION" default:"720h"`
	PasswordMinLength      int           `json:"password_min_length" env:"PASSWORD_MIN_LENGTH" validate:"min=8" default:"8"`
	PasswordRequireSpecial bool          `json:"password_require_special" env:"PASSWORD_REQUIRE_SPECIAL" default:"true"`
	EnableMFA              bool          `json:"enable_mfa" env:"ENABLE_MFA" default:"false"`
	SessionTimeout         time.Duration `json:"session_timeout" env:"SESSION_TIMEOUT" default:"24h"`
	MaxLoginAttempts       int           `json:"max_login_attempts" env:"MAX_LOGIN_ATTEMPTS" validate:"min=1" default:"5"`
	LockoutDuration        time.Duration `json:"lockout_duration" env:"LOCKOUT_DURATION" default:"15m"`
}

// EnterpriseConfig contains enterprise feature configuration
type EnterpriseConfig struct {
	Enabled          bool   `json:"enabled" env:"ENABLED" default:"false"`
	EncryptionKey    string `json:"encryption_key" env:"ENCRYPTION_KEY" validate:"len=32" sensitive:"true"`
	LicenseKey       string `json:"license_key" env:"LICENSE_KEY" sensitive:"true"`
	SAML             SAMLConfig `json:"saml" env:"SAML"`
	LDAP             LDAPConfig `json:"ldap" env:"LDAP"`
	OAuth            OAuthConfig `json:"oauth" env:"OAUTH"`
	AuditRetentionDays int   `json:"audit_retention_days" env:"AUDIT_RETENTION_DAYS" validate:"min=30" default:"365"`
}

// SAMLConfig contains SAML configuration
type SAMLConfig struct {
	Enabled     bool   `json:"enabled" env:"ENABLED" default:"false"`
	MetadataURL string `json:"metadata_url" env:"METADATA_URL" validate:"url"`
	EntityID    string `json:"entity_id" env:"ENTITY_ID"`
	Certificate string `json:"certificate" env:"CERTIFICATE" sensitive:"true"`
	PrivateKey  string `json:"private_key" env:"PRIVATE_KEY" sensitive:"true"`
}

// LDAPConfig contains LDAP configuration
type LDAPConfig struct {
	Enabled      bool   `json:"enabled" env:"ENABLED" default:"false"`
	Host         string `json:"host" env:"HOST"`
	Port         int    `json:"port" env:"PORT" validate:"min=1,max=65535" default:"389"`
	UseSSL       bool   `json:"use_ssl" env:"USE_SSL" default:"false"`
	BindDN       string `json:"bind_dn" env:"BIND_DN"`
	BindPassword string `json:"bind_password" env:"BIND_PASSWORD" sensitive:"true"`
	BaseDN       string `json:"base_dn" env:"BASE_DN"`
	UserFilter   string `json:"user_filter" env:"USER_FILTER"`
}

// OAuthConfig contains OAuth provider configuration
type OAuthConfig struct {
	Google   OAuthProviderConfig `json:"google" env:"GOOGLE"`
	GitHub   OAuthProviderConfig `json:"github" env:"GITHUB"`
	Microsoft OAuthProviderConfig `json:"microsoft" env:"MICROSOFT"`
}

// OAuthProviderConfig contains OAuth provider specific configuration
type OAuthProviderConfig struct {
	Enabled      bool   `json:"enabled" env:"ENABLED" default:"false"`
	ClientID     string `json:"client_id" env:"CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"CLIENT_SECRET" sensitive:"true"`
	RedirectURL  string `json:"redirect_url" env:"REDIRECT_URL" validate:"url"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	RateLimiting      RateLimitingConfig `json:"rate_limiting" env:"RATE_LIMITING"`
	CORS              CORSConfig         `json:"cors" env:"CORS"`
	Validation        ValidationConfig   `json:"validation" env:"VALIDATION"`
	EncryptionEnabled bool               `json:"encryption_enabled" env:"ENCRYPTION_ENABLED" default:"true"`
	TLSEnabled        bool               `json:"tls_enabled" env:"TLS_ENABLED" default:"false"`
	TLSCertFile       string             `json:"tls_cert_file" env:"TLS_CERT_FILE"`
	TLSKeyFile        string             `json:"tls_key_file" env:"TLS_KEY_FILE"`
}

// RateLimitingConfig contains rate limiting configuration
type RateLimitingConfig struct {
	Enabled    bool          `json:"enabled" env:"ENABLED" default:"true"`
	RPS        float64       `json:"rps" env:"RPS" validate:"min=0" default:"100"`
	Burst      int           `json:"burst" env:"BURST" validate:"min=1" default:"200"`
	WindowSize time.Duration `json:"window_size" env:"WINDOW_SIZE" default:"1m"`
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	Enabled          bool     `json:"enabled" env:"ENABLED" default:"true"`
	AllowedOrigins   []string `json:"allowed_origins" env:"ALLOWED_ORIGINS" default:"*"`
	AllowedMethods   []string `json:"allowed_methods" env:"ALLOWED_METHODS" default:"GET,POST,PUT,DELETE,OPTIONS"`
	AllowedHeaders   []string `json:"allowed_headers" env:"ALLOWED_HEADERS" default:"*"`
	AllowCredentials bool     `json:"allow_credentials" env:"ALLOW_CREDENTIALS" default:"true"`
	MaxAge           int      `json:"max_age" env:"MAX_AGE" default:"86400"`
}

// ValidationConfig contains validation configuration
type ValidationConfig struct {
	MaxRequestSize      int64         `json:"max_request_size" env:"MAX_REQUEST_SIZE" default:"10485760"` // 10MB
	RequestTimeout      time.Duration `json:"request_timeout" env:"REQUEST_TIMEOUT" default:"30s"`
	EnableSQLInjection  bool          `json:"enable_sql_injection" env:"ENABLE_SQL_INJECTION" default:"true"`
	EnableXSSProtection bool          `json:"enable_xss_protection" env:"ENABLE_XSS_PROTECTION" default:"true"`
	MaxFieldLength      int           `json:"max_field_length" env:"MAX_FIELD_LENGTH" default:"10000"`
}

// MonitoringConfig contains monitoring and metrics configuration
type MonitoringConfig struct {
	Enabled        bool   `json:"enabled" env:"ENABLED" default:"true"`
	MetricsPort    int    `json:"metrics_port" env:"METRICS_PORT" validate:"min=1,max=65535" default:"9090"`
	HealthPort     int    `json:"health_port" env:"HEALTH_PORT" validate:"min=1,max=65535" default:"8081"`
	PrometheusPath string `json:"prometheus_path" env:"PROMETHEUS_PATH" default:"/metrics"`
	HealthPath     string `json:"health_path" env:"HEALTH_PATH" default:"/health"`
}

// EmailConfig contains email configuration
type EmailConfig struct {
	Provider    string `json:"provider" env:"PROVIDER" validate:"oneof=smtp sendgrid mailgun" default:"smtp"`
	Host        string `json:"host" env:"HOST"`
	Port        int    `json:"port" env:"PORT" validate:"min=1,max=65535" default:"587"`
	Username    string `json:"username" env:"USERNAME"`
	Password    string `json:"password" env:"PASSWORD" sensitive:"true"`
	FromAddress string `json:"from_address" env:"FROM_ADDRESS" validate:"email"`
	FromName    string `json:"from_name" env:"FROM_NAME" default:"N8N Pro"`
	UseTLS      bool   `json:"use_tls" env:"USE_TLS" default:"true"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Provider   string      `json:"provider" env:"PROVIDER" validate:"oneof=local s3 azure gcs" default:"local"`
	LocalPath  string      `json:"local_path" env:"LOCAL_PATH" default:"./storage"`
	S3Config   S3Config    `json:"s3" env:"S3"`
	AzureConfig AzureConfig `json:"azure" env:"AZURE"`
	GCSConfig  GCSConfig   `json:"gcs" env:"GCS"`
}

// S3Config contains AWS S3 configuration
type S3Config struct {
	Region          string `json:"region" env:"REGION"`
	Bucket          string `json:"bucket" env:"BUCKET"`
	AccessKeyID     string `json:"access_key_id" env:"ACCESS_KEY_ID"`
	SecretAccessKey string `json:"secret_access_key" env:"SECRET_ACCESS_KEY" sensitive:"true"`
	Endpoint        string `json:"endpoint" env:"ENDPOINT"` // For S3-compatible services
}

// AzureConfig contains Azure Blob Storage configuration
type AzureConfig struct {
	AccountName   string `json:"account_name" env:"ACCOUNT_NAME"`
	AccountKey    string `json:"account_key" env:"ACCOUNT_KEY" sensitive:"true"`
	ContainerName string `json:"container_name" env:"CONTAINER_NAME"`
}

// GCSConfig contains Google Cloud Storage configuration
type GCSConfig struct {
	ProjectID      string `json:"project_id" env:"PROJECT_ID"`
	Bucket         string `json:"bucket" env:"BUCKET"`
	CredentialsFile string `json:"credentials_file" env:"CREDENTIALS_FILE"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `json:"level" env:"LEVEL" validate:"oneof=debug info warn error" default:"info"`
	Format     string `json:"format" env:"FORMAT" validate:"oneof=json text" default:"json"`
	Output     string `json:"output" env:"OUTPUT" validate:"oneof=stdout stderr file" default:"stdout"`
	File       string `json:"file" env:"FILE"`
	MaxSize    int    `json:"max_size" env:"MAX_SIZE" default:"100"` // MB
	MaxBackups int    `json:"max_backups" env:"MAX_BACKUPS" default:"3"`
	MaxAge     int    `json:"max_age" env:"MAX_AGE" default:"28"` // days
	Compress   bool   `json:"compress" env:"COMPRESS" default:"true"`
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(logger logger.Logger, validator *validator.Validator) *ConfigManager {
	return &ConfigManager{
		logger:    logger,
		validator: validator,
		watchers:  make([]ConfigWatcher, 0),
	}
}

// LoadConfig loads configuration from environment variables and optional config file
func (cm *ConfigManager) LoadConfig(configFile ...string) (*Config, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	config := &Config{}

	// Set config file path if provided
	if len(configFile) > 0 && configFile[0] != "" {
		cm.configFile = configFile[0]
	}

	// Load from config file if specified
	if cm.configFile != "" {
		if err := cm.loadFromFile(config, cm.configFile); err != nil {
			cm.logger.Warn("Failed to load config from file, using environment variables only", "file", cm.configFile, "error", err)
		}
	}

	// Load from environment variables (overrides file config)
	if err := cm.loadFromEnvironment(config); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	// Set default values
	cm.setDefaults(config)

	// Validate configuration
	if err := cm.validateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Store config
	oldConfig := cm.config
	cm.config = config

	// Notify watchers of config change
	if oldConfig != nil {
		cm.notifyWatchers(oldConfig, config)
	}

	cm.logger.Info("Configuration loaded successfully",
		"environment", config.App.Environment,
		"port", config.App.Port,
		"database_host", config.Database.Host,
		"enterprise_enabled", config.Enterprise.Enabled,
	)

	return config, nil
}

// GetConfig returns the current configuration (thread-safe)
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.config == nil {
		return nil
	}
	
	// Return a copy to prevent external modifications
	configCopy := *cm.config
	return &configCopy
}

// AddWatcher adds a configuration change watcher
func (cm *ConfigManager) AddWatcher(watcher ConfigWatcher) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.watchers = append(cm.watchers, watcher)
}

// ReloadConfig reloads configuration from file and environment
func (cm *ConfigManager) ReloadConfig() error {
	_, err := cm.LoadConfig(cm.configFile)
	return err
}

// loadFromFile loads configuration from JSON file
func (cm *ConfigManager) loadFromFile(config *Config, filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	return nil
}

// loadFromEnvironment loads configuration from environment variables
func (cm *ConfigManager) loadFromEnvironment(config interface{}) error {
	return cm.loadFromEnvRecursive("", reflect.ValueOf(config).Elem(), reflect.TypeOf(config).Elem())
}

// loadFromEnvRecursive recursively loads configuration from environment variables
func (cm *ConfigManager) loadFromEnvRecursive(prefix string, value reflect.Value, structType reflect.Type) error {
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := structType.Field(i)
		
		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		
		envTag := fieldType.Tag.Get("env")
		if envTag == "" {
			envTag = strings.ToUpper(fieldType.Name)
		}
		
		envKey := envTag
		if prefix != "" {
			envKey = prefix + "_" + envTag
		}
		
		switch field.Kind() {
		case reflect.Struct:
			// Recursively handle nested structs
			if err := cm.loadFromEnvRecursive(envKey, field, fieldType.Type); err != nil {
				return err
			}
		case reflect.String:
			if envValue := os.Getenv(envKey); envValue != "" {
				field.SetString(envValue)
			}
		case reflect.Int, reflect.Int64:
			if envValue := os.Getenv(envKey); envValue != "" {
				if field.Type() == reflect.TypeOf(time.Duration(0)) {
					// Handle duration
					if duration, err := time.ParseDuration(envValue); err == nil {
						field.Set(reflect.ValueOf(duration))
					}
				} else {
					// Handle regular int
					if intValue, err := strconv.ParseInt(envValue, 10, 64); err == nil {
						field.SetInt(intValue)
					}
				}
			}
		case reflect.Float64:
			if envValue := os.Getenv(envKey); envValue != "" {
				if floatValue, err := strconv.ParseFloat(envValue, 64); err == nil {
					field.SetFloat(floatValue)
				}
			}
		case reflect.Bool:
			if envValue := os.Getenv(envKey); envValue != "" {
				if boolValue, err := strconv.ParseBool(envValue); err == nil {
					field.SetBool(boolValue)
				}
			}
		case reflect.Slice:
			if envValue := os.Getenv(envKey); envValue != "" {
				// Handle string slices (comma-separated)
				if field.Type().Elem().Kind() == reflect.String {
					values := strings.Split(envValue, ",")
					slice := reflect.MakeSlice(field.Type(), len(values), len(values))
					for j, v := range values {
						slice.Index(j).SetString(strings.TrimSpace(v))
					}
					field.Set(slice)
				}
			}
		}
	}
	
	return nil
}

// setDefaults sets default values for configuration fields
func (cm *ConfigManager) setDefaults(config interface{}) {
	cm.setDefaultsRecursive(reflect.ValueOf(config).Elem(), reflect.TypeOf(config).Elem())
}

// setDefaultsRecursive recursively sets default values
func (cm *ConfigManager) setDefaultsRecursive(value reflect.Value, structType reflect.Type) {
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := structType.Field(i)
		
		if !field.CanSet() {
			continue
		}
		
		defaultTag := fieldType.Tag.Get("default")
		
		switch field.Kind() {
		case reflect.Struct:
			cm.setDefaultsRecursive(field, fieldType.Type)
		case reflect.String:
			if field.String() == "" && defaultTag != "" {
				field.SetString(defaultTag)
			}
		case reflect.Int, reflect.Int64:
			if field.Int() == 0 && defaultTag != "" {
				if field.Type() == reflect.TypeOf(time.Duration(0)) {
					if duration, err := time.ParseDuration(defaultTag); err == nil {
						field.Set(reflect.ValueOf(duration))
					}
				} else {
					if intValue, err := strconv.ParseInt(defaultTag, 10, 64); err == nil {
						field.SetInt(intValue)
					}
				}
			}
		case reflect.Float64:
			if field.Float() == 0 && defaultTag != "" {
				if floatValue, err := strconv.ParseFloat(defaultTag, 64); err == nil {
					field.SetFloat(floatValue)
				}
			}
		case reflect.Bool:
			if defaultTag != "" {
				if boolValue, err := strconv.ParseBool(defaultTag); err == nil {
					field.SetBool(boolValue)
				}
			}
		case reflect.Slice:
			if field.Len() == 0 && defaultTag != "" && field.Type().Elem().Kind() == reflect.String {
				values := strings.Split(defaultTag, ",")
				slice := reflect.MakeSlice(field.Type(), len(values), len(values))
				for j, v := range values {
					slice.Index(j).SetString(strings.TrimSpace(v))
				}
				field.Set(slice)
			}
		}
	}
}

// validateConfig validates the configuration using struct tags
func (cm *ConfigManager) validateConfig(config *Config) error {
	if cm.validator == nil {
		return nil
	}
	
	return cm.validator.Struct(config)
}

// notifyWatchers notifies all registered watchers of configuration changes
func (cm *ConfigManager) notifyWatchers(oldConfig, newConfig *Config) {
	for _, watcher := range cm.watchers {
		go func(w ConfigWatcher) {
			defer func() {
				if r := recover(); r != nil {
					cm.logger.Error("Config watcher panicked", "error", r)
				}
			}()
			w.OnConfigChanged(oldConfig, newConfig)
		}(watcher)
	}
}

// SaveConfigToFile saves the current configuration to a file
func (cm *ConfigManager) SaveConfigToFile(filename string) error {
	cm.mu.RLock()
	config := cm.config
	cm.mu.RUnlock()
	
	if config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	// Create a copy for saving (exclude sensitive fields)
	configCopy := cm.sanitizeForSave(*config)
	
	if err := encoder.Encode(configCopy); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	
	return nil
}

// sanitizeForSave removes sensitive fields from configuration before saving
func (cm *ConfigManager) sanitizeForSave(config Config) Config {
	// Create a copy and remove sensitive values
	sanitized := config
	
	// Remove sensitive fields
	sanitized.Database.Password = ""
	sanitized.Redis.Password = ""
	sanitized.Auth.JWTSecret = ""
	sanitized.Enterprise.EncryptionKey = ""
	sanitized.Enterprise.LicenseKey = ""
	sanitized.Enterprise.SAML.Certificate = ""
	sanitized.Enterprise.SAML.PrivateKey = ""
	sanitized.Enterprise.LDAP.BindPassword = ""
	sanitized.Enterprise.OAuth.Google.ClientSecret = ""
	sanitized.Enterprise.OAuth.GitHub.ClientSecret = ""
	sanitized.Enterprise.OAuth.Microsoft.ClientSecret = ""
	sanitized.Email.Password = ""
	sanitized.Storage.S3Config.SecretAccessKey = ""
	sanitized.Storage.AzureConfig.AccountKey = ""
	
	return sanitized
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.App.Environment == "development"
}

// GetDatabaseDSN returns the database connection string
func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// GetRedisAddr returns the Redis address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

// Validate performs additional configuration validation
func (c *Config) Validate() error {
	var errors []string
	
	// Production-specific validations
	if c.IsProduction() {
		if c.App.Debug {
			errors = append(errors, "debug mode should be disabled in production")
		}
		
		if c.Database.SSLMode == "disable" {
			errors = append(errors, "SSL should be enabled for database in production")
		}
		
		if c.Auth.JWTSecret == "" || len(c.Auth.JWTSecret) < 32 {
			errors = append(errors, "JWT secret must be at least 32 characters in production")
		}
		
		if !c.Security.TLSEnabled {
			errors = append(errors, "TLS should be enabled in production")
		}
	}
	
	// Enterprise feature validations
	if c.Enterprise.Enabled {
		if c.Enterprise.EncryptionKey == "" || len(c.Enterprise.EncryptionKey) != 32 {
			errors = append(errors, "enterprise encryption key must be exactly 32 characters")
		}
		
		if c.Enterprise.SAML.Enabled && (c.Enterprise.SAML.Certificate == "" || c.Enterprise.SAML.PrivateKey == "") {
			errors = append(errors, "SAML certificate and private key are required when SAML is enabled")
		}
		
		if c.Enterprise.LDAP.Enabled && (c.Enterprise.LDAP.Host == "" || c.Enterprise.LDAP.BaseDN == "") {
			errors = append(errors, "LDAP host and base DN are required when LDAP is enabled")
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

// GetEnvPrefix returns the environment variable prefix for the application
func GetEnvPrefix() string {
	return "N8N_PRO"
}

// GetConfigFromEnv gets a configuration value from environment variable with prefix
func GetConfigFromEnv(key string, defaultValue string) string {
	envKey := GetEnvPrefix() + "_" + strings.ToUpper(key)
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return defaultValue
}